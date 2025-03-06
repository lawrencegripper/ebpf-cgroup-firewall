package dns

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
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
func StartDNSMonitoringProxy(listenPort int, domains []string, firewall *ebpf.DnsFirewall, allowDNSRequestForBlocked bool) (*DNSProxy, error) {
	// Start the DNS proxy
	slog.Debug("Starting DNS server", "port", listenPort)
	// Defer to upstream DNS resolver using system's configured resolver
	downstreamClient := new(dns.Client)
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		slog.Error("Failed to load resolver configuration", logger.SlogError(err))
		return nil, fmt.Errorf("failed to load resolver configuration: %w", err)
	}
	downstreamServerAddr := config.Servers[0] + ":" + config.Port
	slog.Debug("Using downstream DNS resolver", "address", downstreamServerAddr)
	if firewall.FirewallMethod == models.AllowList {
		err := firewall.AddIPToFirewall(config.Servers[0], &ebpf.Reason{
			Kind:    ebpf.FromDnsRequest,
			Comment: "when configured as allow list ensure we can call downstream dns server",
		})
		if err != nil {
			slog.Error("Failed to add downstream dns server to allow list", logger.SlogError(err))
			return nil, fmt.Errorf("failed to add downstream dns server to allow list: %w", err)
		}
	}

	serverHandler := &blockingDNSHandler{
		firewallDomains:           domains,
		downstreamClient:          downstreamClient,
		dnsFirewall:               firewall,
		DownstreamServerAddr:      downstreamServerAddr,
		allowDNSRequestForBlocked: allowDNSRequestForBlocked,
	}
	server := &dns.Server{Addr: fmt.Sprintf(":%d", listenPort), Net: "udp", Handler: serverHandler}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			slog.Error("Failed to start DNS server", logger.SlogError(err))
			panic(err)
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
				slog.Debug("DNS server not yet started", logger.SlogError(err))
				continue
			}

			conn.Close() //nolint:gosec,errcheck,revive // we don't care about the error here

			slog.Debug("DNS server started", "port", listenPort)
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
		slog.Error("Failed to shutdown DNS server", logger.SlogError(err))
		return fmt.Errorf("failed to shutdown DNS server: %w", err)
	}
	slog.Debug("DNS server shut down successfully")
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
	firewallDomains           []string
	BlockLog                  []dnsBlockResult
	blockLogMu                sync.Mutex
	dnsFirewall               *ebpf.DnsFirewall
	downstreamClient          *dns.Client
	DownstreamServerAddr      string
	allowDNSRequestForBlocked bool
}

func (b *blockingDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true

	// Somehow need to get at the udp private field on the w dns writer

	for _, q := range r.Question {
		domainMatchedFirewallDomains := false
		matchedBecause := ""

		// Refuse IPv6 requests not supported atm
		// TODO: Support IPv6
		if !b.allowDNSRequestForBlocked && q.Qtype == dns.TypeAAAA {
			m.Rcode = dns.RcodeRefused
			err := w.WriteMsg(m)
			if err != nil {
				slog.Error("Failed to write DNS response", logger.SlogError(err))
			}
			return
		}

		// Handle blocking
		for _, domain := range b.firewallDomains {
			if strings.HasSuffix(q.Name, domain+".") {
				domainMatchedFirewallDomains = true
				matchedBecause = domain
			}
		}

		requestIsNotAllowed := false

		if !domainMatchedFirewallDomains && b.dnsFirewall != nil && b.dnsFirewall.FirewallMethod == models.AllowList {
			if b.allowDNSRequestForBlocked {
				requestIsNotAllowed = true
			} else {
				m.Rcode = dns.RcodeRefused
				if err := w.WriteMsg(m); err != nil {
					slog.Error("Failed to write DNS response", logger.SlogError(err))
				}
				addToBlockLog(b, q, matchedBecause)

				slog.Warn("DNS BLOCKED",
					"reason", "NotInAllowList",
					"explaination", "Domain doesn't match any allowlist prefixes",
					"blocked", true,
					"blockedAt", "dns",
					"domain", q.Name,
					"pid", b.dnsFirewall.DnsTransactionIdToPid[r.Id],
					"cmd", b.dnsFirewall.DnsTransactionIdToCmd[r.Id],
					"firewallMethod", b.dnsFirewall.FirewallMethod.String(),
				)
				return
			}
		}

		if domainMatchedFirewallDomains && b.dnsFirewall != nil && b.dnsFirewall.FirewallMethod == models.BlockList {
			if b.allowDNSRequestForBlocked {
				requestIsNotAllowed = true
			} else {
				m.Rcode = dns.RcodeRefused
				if err := w.WriteMsg(m); err != nil {
					slog.Error("Failed to write DNS response", logger.SlogError(err))
				}
				addToBlockLog(b, q, matchedBecause)

				explaination := fmt.Sprintf("Matched Domain Prefix: %s", matchedBecause)

				slog.Warn("DNS BLOCKED",
					"reason", "InBlockList",
					"explaination", explaination,
					"blocked", true,
					"blockedAt", "dns",
					"domain", q.Name,
					"pid", b.dnsFirewall.DnsTransactionIdToPid[r.Id],
					"cmd", b.dnsFirewall.DnsTransactionIdToCmd[r.Id],
					"firewallMethod", b.dnsFirewall.FirewallMethod.String(),
				)
				return
			}
		}

		resp, _, err := b.downstreamClient.Exchange(r, b.DownstreamServerAddr)
		if err != nil {
			slog.Warn("Failed to resolve from downstream", logger.SlogError(err), "domain", q.Name, "downstream server", b.DownstreamServerAddr)
			m.Rcode = dns.RcodeServerFailure
			return
		}
		m.Answer = append(m.Answer, resp.Answer...)

		// Used for logging where an IP came from when blocking
		for _, answer := range resp.Answer {
			if a, ok := answer.(*dns.A); ok {
				b.dnsFirewall.TrackIPToDomain(a.A.String(), q.Name)
			}
		}

		if b.dnsFirewall != nil && b.dnsFirewall.FirewallMethod == models.LogOnly {
			// Do nothing
		} else if domainMatchedFirewallDomains {
			//                          👇 Don't add the ip if we're allowing dns requests for blocked stuff
			if b.dnsFirewall != nil && !requestIsNotAllowed {
				// If it did match add the IPs to the firewall ip list
				// the matching already decided on the firewall method (allow, block)
				for _, answer := range resp.Answer {
					if a, ok := answer.(*dns.A); ok {
						err = b.dnsFirewall.AddIPToFirewall(
							a.A.String(),
							&ebpf.Reason{
								Kind:    ebpf.FromDnsRequest,
								Comment: fmt.Sprintf("Matched Domain Prefix: %s", matchedBecause),
							},
						)
						if err != nil {
							slog.Error("Failed to allow IP", logger.SlogError(err))
						}
					}
				}
			}
		}
	}

	err := w.WriteMsg(m)
	if err != nil {
		slog.Error("Failed to write DNS response", logger.SlogError(err))
	}
}

func addToBlockLog(b *blockingDNSHandler, q dns.Question, matchedBecause string) {
	b.blockLogMu.Lock()
	b.BlockLog = append(b.BlockLog, dnsBlockResult{
		MatchedDomainSuffix: matchedBecause,
		DNSRequest:          q.Name,
	})
	b.blockLogMu.Unlock()
}
