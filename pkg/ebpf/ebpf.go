package ebpf

// Generate the eBPF code in dns_redirector.c 👇 this causes go to do that when `go build` is run
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf bpf.c

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
)

type DomainList struct {
	Domains *utils.GenericSyncMap[string, bool]
}

func (d *DomainList) AddDomain(domain string) {
	if d.Domains == nil {
		d.Domains = new(utils.GenericSyncMap[string, bool])
	}
	d.Domains.Store(domain, true)
}

func (d *DomainList) String() string {
	if d == nil || d.Domains == nil {
		return "No Domains"
	}

	var result strings.Builder
	d.Domains.Range(func(key string, value bool) bool {
		result.WriteString(key + ", ")
		return true
	})

	return result.String()
}

// Ensure the interface is implemented
var _ DnsFirewall = &EgressFirewall{}

type AddIPType int

const (
	ViaHttpProxyOnly AddIPType = 1
	ViaAnyPort       AddIPType = 2
)

// DnsFirewall is an interface for the DNS proxy
type DnsFirewall interface {
	AllowIPThroughFirewall(ip string, ipType AddIPType, reason *models.RuleSource) error
	GetPidFromDNSTransactionId(dnsTransactionId uint16) (int32, error)
	GetFirewallMethod() models.FirewallMethod
	TrackIPToDomain(ip string, domain string)
}

type EgressFirewall struct {
	Spec                      *ebpf.CollectionSpec
	Link                      *link.Link
	SockOpsLink               *link.Link
	EgressLink                *link.Link
	Programs                  bpfPrograms
	Objects                   *bpfObjects
	FirewallIPsWithRuleSource *utils.GenericSyncMap[string, *models.RuleSource]
	RingBufferReader          *ringbuf.Reader
	FirewallMethod            models.FirewallMethod
	dnsTransactionIdToPid     *utils.GenericSyncMap[uint16, int32]
	ipDomainTracking          *utils.GenericSyncMap[string, *DomainList]
}

func (e *EgressFirewall) GetFirewallMethod() models.FirewallMethod {
	return e.FirewallMethod
}

func (e *EgressFirewall) PidFromSrcPort(sourcePort int) (uint32, error) {
	clientSocketCookie := uint64(16)
	err := e.Objects.bpfMaps.SrcPortToSockClient.Lookup(uint16(sourcePort), &clientSocketCookie)
	if err != nil {
		slog.Error("failed to lookup srcPortToSockClient map value", logger.SlogError(err), "sourcePort", sourcePort)
		return 0, err
	}

	pid := uint32(16)
	err = e.Objects.bpfMaps.SocketPidMap.Lookup(clientSocketCookie, &pid)
	if err != nil {
		slog.Error("failed to lookup socketPidMap value", logger.SlogError(err), "socketCookie", clientSocketCookie)
		return 0, err
	}

	return pid, nil
}

func (e *EgressFirewall) GetPidFromDNSTransactionId(dnsTransactionId uint16) (int32, error) {
	// LoadAndDelete is used here so we don't have unbounded growth of the map
	pid, ok := e.dnsTransactionIdToPid.LoadAndDelete(dnsTransactionId)
	if !ok {
		slog.Error("Failed to get PID from DNS transaction ID")
		pid = 0
		return pid, fmt.Errorf("failed to get PID from DNS transaction ID")
	}

	return pid, nil
}

func (e *EgressFirewall) HostAndPortFromSourcePort(sourcePort int) (net.IP, int, error) {
	maps := e.Objects.bpfMaps

	// Use the source port map to get the client socket cookie
	clientSocketCookie := uint64(16)
	err := maps.SrcPortToSockClient.Lookup(uint16(sourcePort), &clientSocketCookie)
	if err != nil {
		slog.Error("failed to lookup srcPortToSockClient map value", logger.SlogError(err), "sourcePort", sourcePort)
		return nil, 0, err
	}

	originalIPBitwise := uint32(16)
	err = maps.SockClientToOriginalIp.Lookup(clientSocketCookie, &originalIPBitwise)
	if err != nil {
		slog.Error("failed to lookup sockClientToOriginalIp map value", logger.SlogError(err), "clientSocketCookie", clientSocketCookie)
		return nil, 0, err
	}

	originalIp := models.IntToIP(originalIPBitwise)
	originalPort := uint16(16)
	err = maps.SockClientToOriginalPort.Lookup(clientSocketCookie, &originalPort)
	if err != nil {
		slog.Error("failed to lookup sockClientToOriginalPort map value", logger.SlogError(err), "clientSocketCookie", clientSocketCookie)
		return nil, 0, err
	}

	slog.Debug("eBPF matched source port to retreive original ip and port", "sourcePort", sourcePort, "originalIP", originalIp, "originalPort", originalPort)

	return originalIp, int(originalPort), nil
}

// AllowIPThroughFirewall adds an IP to the FirewallAllowedIpsMap in ebpf
// which causes the cgroup_egress program to allow requests outbound to that ip
func (e *EgressFirewall) AllowIPThroughFirewall(ip string, ipType AddIPType, reason *models.RuleSource) error {
	slog.Debug("Adding IP to firewall_ips_map", "ip", ip, slog.String("reason", reason.Comment), slog.String("kind", reason.KindHumanReadable()))
	firewallIps := e.Objects.bpfMaps.FirewallAllowedIpsMap
	if ipType == ViaHttpProxyOnly {
		// Only allow HTTP traffic
		firewallIps = e.Objects.bpfMaps.FirewallAllowedHttpIpsMap
	}

	err := firewallIps.Put(models.IPToIntNetworkOrder(ip), models.IPToIntNetworkOrder(ip))
	if err != nil {
		slog.Error("adding IP to allowed_ips_map", "error", err)
		return fmt.Errorf("adding IP to allowed_ips_map: %w", err)
	}

	if e.FirewallIPsWithRuleSource == nil {
		e.FirewallIPsWithRuleSource = new(utils.GenericSyncMap[string, *models.RuleSource])
	}

	e.FirewallIPsWithRuleSource.Store(ip, reason)

	return nil
}

func (e *EgressFirewall) TrackIPToDomain(ip string, domain string) {
	if e.ipDomainTracking == nil {
		return
	}

	slog.Debug("Tracking IP to domain", "ip", ip, "domain", domain)

	domainList, _ := e.ipDomainTracking.LoadOrStore(ip, &DomainList{})
	domainList.AddDomain(domain)
}

func intToIPHostByteOrder(val uint32) net.IP {
	// TODO: Detect if the host system is big or little endian and do the right one
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], val)

	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

// AttachRedirectorToCGroup attaches the eBPF program to the cgroup at the specified path.
// Parameters:
//   - cGroupPath: The filesystem path to the cgroup where the eBPF program will be attached.
//   - dnsProxyPort: The port number on localhost to which DNS requests should be forwarded.
//   - exemptPID: The PID of the DNS proxy process that should be exempt from redirection to allow calling upstream dns server.
func AttachRedirectorToCGroup(
	cGroupPath string,
	httpProxyPort int,
	httpsProxyPort int,
	dnsProxyPort int,
	exemptPID int,
	firewallMethod models.FirewallMethod,
	isDockerContainer bool,
) (*EgressFirewall, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	slog.Debug("Attaching eBPF programs to cgroup", "cgroup", cGroupPath)

	// Load network block spec
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading networkblock spec: %w", err)
	}

	// Pass through port configuration for the proxies
	err = spec.Variables["const_http_proxy_port"].Set(uint32(httpProxyPort))
	if err != nil {
		return nil, fmt.Errorf("setting const_http_proxy_port variable failed: %w", err)
	}

	err = spec.Variables["const_https_proxy_port"].Set(uint32(httpsProxyPort))
	if err != nil {
		return nil, fmt.Errorf("setting const_https_proxy_port variable failed: %w", err)
	}

	// TODO: Make this detection better. Use the docker sdk to find containers and compare to the cgroup path
	if isDockerContainer {
		slog.Warn("Docker cgroup detected, updating localhost redirect to instead use the docker0 interface")
		output, err := exec.Command("sh", "-c", "docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'").Output()
		if err != nil {
			return nil, fmt.Errorf("failed to get docker bridge gateway IP: %w", err)
		}
		dockerBridgeGatewayIP := strings.TrimSpace(string(output))
		slog.Debug("Docker bridge gateway IP detected", "dockerBridgeGatewayIP", dockerBridgeGatewayIP)

		// Set the const_mitm_proxy_address proxy IP
		ip := net.ParseIP(dockerBridgeGatewayIP).To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", dockerBridgeGatewayIP)
		}

		// TODO: What if we're on ARM? It's this then wrong?
		ipNetworkOrder := binary.LittleEndian.Uint32(ip)
		err = spec.Variables["const_mitm_proxy_address"].Set(ipNetworkOrder)
		if err != nil {
			return nil, fmt.Errorf("setting const_mitm_proxy_address port variable failed: %w", err)
		}
	}

	// Set the firewall method
	err = spec.Variables["const_firewall_mode"].Set(firewallMethod)
	if err != nil {
		return nil, fmt.Errorf("setting const_firewall_mode port variable failed: %w", err)
	}

	// Set the port which the DNS requests should be forwarded to on localhost
	// this allows us to have multiple hooks each with their own server running at the same time
	if dnsProxyPort < 0 || dnsProxyPort > 4294967295 {
		return nil, fmt.Errorf("dnsProxyPort value %d out of range for uint32", dnsProxyPort)
	}

	// Tell the eBPF program where we're hosting the DNS proxy
	err = spec.Variables["const_dns_proxy_port"].Set(uint32(dnsProxyPort)) //nolint:gosec // DNSProxyPort is checked above to be in range
	if err != nil {
		return nil, fmt.Errorf("setting const_dns_proxy_port port variable failed: %w", err)
	}

	// Tell the eBPF program about the DNS proxy PID so it is allowed to send requests to upstream dns servers
	// without having them redirected back to the proxy
	if exemptPID != 0 {
		err = spec.Variables["const_proxy_pid"].Set(uint32(exemptPID))
		if err != nil {
			return nil, fmt.Errorf("setting const_dns_proxy_pid port variable failed: %w", err)
		}
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var obj bpfObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		return nil, fmt.Errorf("loading and assigning eBPF programs: %w", err)
	}

	cgroup, err := os.Open(cGroupPath)
	if err != nil {
		return nil, fmt.Errorf("opening cgroup path %s: %w", cGroupPath, err)
	}
	defer cgroup.Close()

	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: obj.Connect4,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching eBPF program Connect4 to cgroup: %w", err)
	}

	// TODO store link and use it to pin
	egressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: obj.CgroupSkbEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching eBPF program CgroupSkbEgress to cgroup: %w", err)
	}

	// TODO store link and use it to pin
	sockOpsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupSockOps,
		Program: obj.CgSockOps,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching eBPF program CgSockOps to cgroup: %w", err)
	}

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	ringBufferEventsReader, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	ebpfFirewall := &EgressFirewall{
		Spec: spec,
		// WARNING: If we don't keep an active reference to the link the the program will be unloaded
		//          and stop doing network filtering. I know we don't use these actively but you must
		//          leave them here!
		Link:                      &cgroupLink,
		SockOpsLink:               &sockOpsLink,
		EgressLink:                &egressLink,
		Objects:                   &obj,
		RingBufferReader:          ringBufferEventsReader,
		FirewallMethod:            firewallMethod,
		dnsTransactionIdToPid:     new(utils.GenericSyncMap[uint16, int32]),
		ipDomainTracking:          new(utils.GenericSyncMap[string, *DomainList]),
		FirewallIPsWithRuleSource: new(utils.GenericSyncMap[string, *models.RuleSource]),
	}

	go ebpfFirewall.monitorRingBufferEventfunc()

	slog.Debug("Successfully attached eBPF programs to cgroup blocking network traffic")
	return ebpfFirewall, nil
}
