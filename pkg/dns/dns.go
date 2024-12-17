package dns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/miekg/dns"
)

// DNSProxy is a DNS proxy that blocks requests to specified domains
type DNSProxy struct {
	Port               int
	Server             *dns.Server
	BlockingDNSHandler *blockingDNSHandler
}

// StartDNSMonitoringProxy configures eBPF to redirect DNS requests for the specified cgroup to a local DNS server
// which blocks requests to the specified domains.
func StartDNSMonitoringProxy(listenPort int, domains []string, firewall *ebpf.DnsFirewall, refuseAtDNSRequest bool) (*DNSProxy, error) {
	// Start the DNS proxy
	fmt.Printf("Starting DNS server on port %d\n", listenPort)
	// Defer to upstream DNS resolver using system's configured resolver
	downstreamClient := new(dns.Client)
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		fmt.Printf("Failed to load resolver configuration: %v\n", err)
		return nil, fmt.Errorf("failed to load resolver configuration: %w", err)
	}
	downstreamServerAddr := config.Servers[0] + ":" + config.Port
	fmt.Printf("Using downstream DNS resolver: %s\n", downstreamServerAddr)

	serverHandler := &blockingDNSHandler{
		firewallDomains:      domains,
		downstreamClient:     downstreamClient,
		dnsFirewall:          firewall,
		DownstreamServerAddr: downstreamServerAddr,
		DNSLog:               make(map[string]int),
		refuseAtDNSRequest:   refuseAtDNSRequest,
	}
	server := &dns.Server{Addr: fmt.Sprintf(":%d", listenPort), Net: "udp", Handler: serverHandler}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("Failed to start DNS server: %v\n", err)
		}
	}()

	// Wait for the DNS server to start
	timeout := time.After(5 * time.Second)
	ticker := time.Tick(5 * time.Millisecond)

waitStartLoop:
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for DNS server to start")
		case <-ticker:
			conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", listenPort))
			if err != nil {
				fmt.Printf("DNS server not yet started: %v\n", err)
				continue
			}

			conn.Close() //nolint:gosec,errcheck,revive // we don't care about the error here

			fmt.Printf("DNS server started on port %d\n", listenPort)
			break waitStartLoop
		}
	}

	// Return a function to stop the DNS server
	return &DNSProxy{
		Port:               listenPort,
		Server:             server,
		BlockingDNSHandler: serverHandler,
	}, nil
}

// HasBlockedDomains checks if there are any domains to be blocked by the DNSProxy.
func (d *DNSProxy) HasBlockedDomains() bool {
	if d.BlockingDNSHandler == nil {
		return false
	}
	return len(d.BlockingDNSHandler.BlockLog) > 0
}

// Shutdown gracefully shuts down the DNS server
func (d *DNSProxy) Shutdown() error {
	if err := d.Server.Shutdown(); err != nil {
		fmt.Printf("Failed to shutdown DNS server: %v\n", err)
		return fmt.Errorf("failed to shutdown DNS server: %w", err)
	}
	fmt.Println("DNS server shut down successfully")
	return nil
}

// BlockedDomains returns a string containing the domains that have been blocked
func (d *DNSProxy) BlockedDomains() string {
	builder := strings.Builder{}

	d.BlockingDNSHandler.blockLogMu.Lock()
	defer d.BlockingDNSHandler.blockLogMu.Unlock()

	for _, block := range d.BlockingDNSHandler.BlockLog {
		msg := fmt.Sprintf("Domain: %s caused request to be blocked. Request: %s\n", block.MatchedDomainSuffix, block.DNSRequest)
		_, err := builder.WriteString(msg)
		if err != nil {
			fmt.Printf("Failed to write blocked domain to string builder: %v\n", err)
			// If we can't write to a string builder, we should panic as something is very wrong with go/host
			panic(err)
		}
	}
	return builder.String()
}

// FindUnusedPort Finds an unused port to listen on
func FindUnusedPort() (int, error) {
	listener, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return 0, fmt.Errorf("failed to find an unused port: %w", err)
	}
	defer listener.Close()
	addr, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("failed to assert type to *net.UDPAddr")
	}
	return addr.Port, nil
}

type dnsBlockResult struct {
	MatchedDomainSuffix string
	DNSRequest          string
}

type blockingDNSHandler struct {
	firewallDomains      []string
	BlockLog             []dnsBlockResult
	blockLogMu           sync.Mutex
	DNSLog               map[string]int
	dnsLogMu             sync.Mutex
	dnsFirewall          *ebpf.DnsFirewall
	downstreamClient     *dns.Client
	DownstreamServerAddr string
	refuseAtDNSRequest   bool
}

func (b *blockingDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true

	for _, q := range r.Question {
		domainMatchedFirewallDomains := false
		matchedBecause := ""

		// Track the DNS request
		b.dnsLogMu.Lock()
		if count, exists := b.DNSLog[q.Name]; exists {
			fmt.Printf("Exiting: DNS request for %s, count: %d\n", q.Name, count)
			b.DNSLog[q.Name] = count + 1
		} else {
			fmt.Printf("New: DNS request for %s, count: 1\n", q.Name)
			b.DNSLog[q.Name] = 1
		}
		b.dnsLogMu.Unlock()

		// Handle blocking
		for _, domain := range b.firewallDomains {
			if strings.HasSuffix(q.Name, domain+".") {
				domainMatchedFirewallDomains = true
			} else {
				matchedBecause = domain
				// Track that we would block this domain
				b.blockLogMu.Lock()
				b.BlockLog = append(b.BlockLog, dnsBlockResult{
					MatchedDomainSuffix: domain,
					DNSRequest:          q.Name,
				})
				b.blockLogMu.Unlock()
			}
		}

		if b.refuseAtDNSRequest && !domainMatchedFirewallDomains && b.dnsFirewall.FirewallMethod == ebpf.AllowList {
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m)
		}

		if b.refuseAtDNSRequest && domainMatchedFirewallDomains && b.dnsFirewall.FirewallMethod == ebpf.BlockList {
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m)
		}

		resp, _, err := b.downstreamClient.Exchange(r, b.DownstreamServerAddr)
		if err != nil {
			fmt.Printf("Failed to resolve from downstream: %v, domain: %s, downstream server: %s\n", err, q.Name, b.DownstreamServerAddr)
			m.Rcode = dns.RcodeServerFailure
			continue
		}
		m.Answer = append(m.Answer, resp.Answer...)

		if b.dnsFirewall.FirewallMethod == ebpf.LogOnly {
			// Do nothing
		} else if domainMatchedFirewallDomains {
			if b.dnsFirewall != nil {
				// If it did match add the IPs to the firewall ip list
				// the matching already decided on the firewall method (allow, block)
				for _, answer := range resp.Answer {
					if a, ok := answer.(*dns.A); ok {
						err = b.dnsFirewall.AddIPToFirewall(
							a.A.String(),
							&ebpf.Reason{Kind: ebpf.FromDnsRequest, Comment: fmt.Sprintf("From DNS request: %s Matched: %s", a.A.String(), matchedBecause)},
						)
						if err != nil {
							fmt.Printf("Failed to allow IP: %v\n", err)
						}
					}
				}
			}
		}
	}

	err := w.WriteMsg(m)
	if err != nil {
		fmt.Printf("Failed to write DNS response: %v\n", err)
	}
}
