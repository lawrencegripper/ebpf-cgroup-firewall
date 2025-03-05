package ebpf

// Generate the eBPF code in dns_redirector.c 👇 this causes go to do that when `go build` is run
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event bpf bpf.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
)

type AllowKind int

const (
	UserSpecified AllowKind = iota
	FromDnsRequest
)

type Reason struct {
	Kind    AllowKind
	Comment string
}

func (r *Reason) KindHumanReadable() string {
	switch r.Kind {
	case UserSpecified:
		return "UserSpecified"
	case FromDnsRequest:
		return "FromDNSRequest"
	default:
		return "Unknown"
	}
}

type DomainList struct {
	Domains []string
}

func (d *DomainList) AddDomain(domain string) {
	d.Domains = append(d.Domains, domain)
}

func (d *DomainList) String() string {
	if d == nil || d.Domains == nil {
		return "No Domains"
	}
	return strings.Join(d.Domains, ",")
}

type DnsFirewall struct {
	Spec                  *ebpf.CollectionSpec
	Link                  *link.Link
	Programs              bpfPrograms
	Objects               *bpfObjects
	FirewallIPsWithReason map[string]*Reason
	RingBufferReader      *ringbuf.Reader
	FirewallMethod        models.FirewallMethod
	DnsTransactionIdToPid map[uint16]uint32
	DnsTransactionIdToCmd map[uint16]string
	blockedEvents         []bpfEvent
	blockedEventsMutex    sync.Mutex
	ipDomainTracking      map[string]*DomainList
}

func (e *DnsFirewall) BlockedEvents() []bpfEvent {
	e.blockedEventsMutex.Lock()
	defer e.blockedEventsMutex.Unlock()

	blockedEventsCopy := make([]bpfEvent, len(e.blockedEvents))
	copy(blockedEventsCopy, e.blockedEvents)
	return blockedEventsCopy
}

func (e *DnsFirewall) HostAndPortFromSourcePort(sourcePort int) (string, int, error) {
	maps := e.Objects.bpfMaps
	// serverSocketCookie :=
	// output := &map[string]string{}
	// slog.Warn("server cookie", "serverSocketCookie", serverSocketCookie)

	// slog.Warn("firewallIps")
	// ip := uint32(16)
	// iterateOvereBPFMap(maps.FirewallIpMap.Iterate(), ip)

	slog.Warn("srcPortToSockClient")

	iterateOvereBPFMap(maps.SrcPortToSockClient.Iterate())

	clientSocketCookie := uint64(16)
	err := maps.SrcPortToSockClient.Lookup(uint16(sourcePort), &clientSocketCookie)
	if err != nil {
		slog.Warn("srcPortToSockClient", "error", err)
	}

	slog.Warn("clientSocketCookie", "clientSocketCookie", clientSocketCookie)

	// slog.Warn("sockClientToOriginalDest")
	// dest := "" //TODO: Fix this up
	// iterateOvereBPFMap(maps.SockClientToOriginalDest.Iterate(), dest)
	// slog.Warn("sockServerToSockClient")
	// clientCookie := uint64(16)
	// iterateOvereBPFMap(maps.SockServerToSockClient.Iterate(), clientCookie)

	// err := clientSocketCookie.Lookup(serverSocketCookie, output)
	// if err != nil {
	// 	return x.String(), 0, fmt.Errorf("looking up service mapping: %w", err)
	// }

	return "", 0, errors.New("no output found")
}

func iterateOvereBPFMap(iter *ebpf.MapIterator) {
	key := uint16(16)
	value := uint64(16)

	for iter.Next(&key, &value) {
		slog.Warn(fmt.Sprintf("key: %v, value: %d \n", key, value))
	}
	if err := iter.Err(); err != nil {
		slog.Error("iterating over eBPF map", logger.SlogError(err))
	}
}

// TODO
// Make it so you can optionally allow a port, if no port set then default to any
// this gets interesting for the dns based ones, what ports? 443 and 80? we can't really guess
// hmmm maybe it's ok as just ip allowed.

// AddIPToFirewall adds the specified IP to the firewall's list
// the FirewallMethod (logonly, allowlist, blocklist) defines how this list is handled
// In the case where firewall is blocklist, ips added here are blocked, rest art allowed
// In the case where firewall is allowlist, ips added here are allowed, rest are blocked
func (e *DnsFirewall) AddIPToFirewall(ip string, reason *Reason) error {
	slog.Debug("Adding IP to firewall_ips_map", "ip", ip)
	firewallIps := e.Objects.bpfMaps.FirewallIpMap

	err := firewallIps.Put(models.IPToInt(ip), models.IPToInt(ip))
	if err != nil {
		slog.Error("adding IP to allowed_ips_map", "error", err)
		return fmt.Errorf("adding IP to allowed_ips_map: %w", err)
	}

	if e.FirewallIPsWithReason == nil {
		e.FirewallIPsWithReason = make(map[string]*Reason)
	}

	e.FirewallIPsWithReason[ip] = reason

	return nil
}

func (e *DnsFirewall) TrackIPToDomain(ip string, domain string) {
	if e.ipDomainTracking == nil {
		return
	}
	slog.Debug("Tracking IP to domain", "ip", ip, "domain", domain)
	_, exists := e.ipDomainTracking[ip]
	if !exists {
		e.ipDomainTracking[ip] = &DomainList{}
	}

	domainList := e.ipDomainTracking[ip]
	domainList.AddDomain(domain)
}

func intToIP(val uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], val)

	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

// AttachRedirectorToCGroup attaches the eBPF program to the cgroup at the specified path.
// Parameters:
//   - cGroupPath: The filesystem path to the cgroup where the eBPF program will be attached.
//   - dnsProxyPort: The port number on localhost to which DNS requests should be forwarded.
//   - exemptPID: The PID of the DNS proxy process that should be exempt from redirection to allow calling upstream dns server.
func AttachRedirectorToCGroup(
	cGroupPath string,
	dnsProxyPort int,
	exemptPID int,
	firewallMethod models.FirewallMethod,
) (*DnsFirewall, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load network block spec
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading networkblock spec: %w", err)
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
		err = spec.Variables["const_dns_proxy_pid"].Set(uint32(exemptPID))
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
		return nil, fmt.Errorf("attaching eBPF program to cgroup: %w", err)
	}

	// TODO store link and use it to pin
	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: obj.CgroupSkbEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching eBPF program to cgroup: %w", err)
	}

	// TODO store link and use it to pin
	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupSockOps,
		Program: obj.CgSockOps,
	})
	if err != nil {
		log.Print("Attaching CgSockOpt program to Cgroup:", err)
	}

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	ringBufferEventsReader, err := ringbuf.NewReader(obj.Events)
	if err != nil {
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	ebpfFirewall := &DnsFirewall{
		Spec:                  spec,
		Link:                  &cgroupLink,
		Objects:               &obj,
		RingBufferReader:      ringBufferEventsReader,
		FirewallMethod:        firewallMethod,
		DnsTransactionIdToPid: map[uint16]uint32{},
		DnsTransactionIdToCmd: map[uint16]string{},
		blockedEvents:         []bpfEvent{},
		blockedEventsMutex:    sync.Mutex{},
		ipDomainTracking:      map[string]*DomainList{},
	}

	go ebpfFirewall.monitorRingBufferEventfunc()

	slog.Debug("Successfully attached eBPF programs to cgroup blocking network traffic")
	return ebpfFirewall, nil
}

func (e *DnsFirewall) monitorRingBufferEventfunc() {
	var event bpfEvent
	pid2CmdLineCache := map[int]string{}

	for {
		record, err := e.RingBufferReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				slog.Debug("Received signal, exiting..")

				return
			}
			slog.Error("reading from ringbuf reader", logger.SlogError(err))

			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("parsing ringbuf event", logger.SlogError(err))

			continue
		}

		cmdRun := "unknown"
		// Lookup the processPath for the event
		if event.PidResolved {
			cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", event.Pid)
			cmdlineBytes, err := os.ReadFile(cmdlinePath)
			if err == nil {
				// cmdline args are null-terminated, replace nulls with spaces
				cmdline := string(bytes.ReplaceAll(cmdlineBytes, []byte{0}, []byte{' '}))
				pid2CmdLineCache[int(event.Pid)] = cmdline
				cmdRun = cmdline
			} else {
				slog.Error("reading cmdline", logger.SlogError(err))
			}
		}

		var reasonText string
		var explaination string
		reason := e.FirewallIPsWithReason[intToIP(event.Ip).String()]
		if reason == nil {
			if e.FirewallMethod == models.AllowList {
				reasonText = "NotInAllowList"
				explaination = "Domain doesn't match any allowlist prefixes"
			} else {
				reasonText = "Unknown"
			}
		} else {
			reasonText = reason.KindHumanReadable()
			explaination = reason.Comment
		}

		ip := intToIP(event.Ip)
		if !event.Allowed {
			slog.Warn(
				"Packet BLOCKED",
				"blockedAt", "packet",
				"blocked", !event.Allowed,
				"ip", ip,
				"ipResolvedForDomains", e.ipDomainTracking[ip.String()].String(),
				"pid", event.Pid,
				"cmd", cmdRun,
				"reason", reasonText,
				"explaination", explaination,
				"firewallMethod", e.FirewallMethod.String(),
			)

			// Writing blocked events is nice to have, if we're locked then skip em
			// rather than stack them up
			e.blockedEventsMutex.Lock()
			e.blockedEvents = append(e.blockedEvents, event)
			e.blockedEventsMutex.Unlock()
		}

		if event.IsDns {
			if event.DnsTransactionId != 0 {
				e.DnsTransactionIdToPid[event.DnsTransactionId] = event.Pid
				e.DnsTransactionIdToCmd[event.DnsTransactionId] = cmdRun
			}
		}
	}
}
