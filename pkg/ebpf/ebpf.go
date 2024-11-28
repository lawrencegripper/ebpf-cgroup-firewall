package ebpf

// Generate the eBPF code in dns_redirector.c 👇 this causes go to do that when `go build` is run
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go dnsredirector dns_redirector.c

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type DnsFirewall struct {
	Spec     *ebpf.CollectionSpec
	Link     *link.Link
	Programs dnsredirectorPrograms
	Objects  *dnsredirectorObjects
}

func (e *DnsFirewall) AllowIP(ip string) error {
	fmt.Println("Adding IP to allowed_ips_map: ", ip)
	allowed_ips := e.Objects.dnsredirectorMaps.AllowedIpsMap
	err := allowed_ips.Put(ipToInt(ip), ipToInt(ip))
	if err != nil {
		return fmt.Errorf("adding IP to allowed_ips_map: %w", err)
	}

	fmt.Println("allowed_ips_map: ", allowed_ips.String())
	return nil
}

func intToIP(val uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], val)
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

func ipToInt(val string) uint32 {
	ip := net.ParseIP(val).To4()
	return binary.LittleEndian.Uint32(ip)
}

// Generate the eBPF code in dns_redirector.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go dnsredirector dns_redirector.c

// AttachRedirectorToCGroup attaches the eBPF program to the cgroup at the specified path.
// Parameters:
//   - cGroupPath: The filesystem path to the cgroup where the eBPF program will be attached.
//   - dnsProxyPort: The port number on localhost to which DNS requests should be forwarded.
//   - exemptPID: The PID of the DNS proxy process that should be exempt from redirection to allow calling upstream dns server.
func AttachRedirectorToCGroup(cGroupPath string, dnsProxyPort int, exemptPID int) (*DnsFirewall, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load network block spec
	spec, err := loadDnsredirector()
	if err != nil {
		return nil, fmt.Errorf("loading networkblock spec: %w", err)
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
	err = spec.Variables["const_dns_proxy_pid"].Set(uint32(exemptPID))
	if err != nil {
		return nil, fmt.Errorf("setting const_dns_proxy_pid port variable failed: %w", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var obj dnsredirectorObjects
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

	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: obj.CgroupSkbEgress,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching eBPF program to cgroup: %w", err)
	}

	fmt.Printf("Successfully attached eBPF programs to cgroup blocking network traffic\n")
	return &DnsFirewall{
		Spec:    spec,
		Link:    &cgroupLink,
		Objects: &obj,
	}, nil
}
