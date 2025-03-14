package dns

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
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
func StartDNSMonitoringProxy(listenPort int, firewallItems models.FirewallItems, firewall ebpf.DnsFirewall, allowDNSRequestForBlocked bool) (*DNSProxy, error) {
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
	if firewall.GetFirewallMethod() == models.AllowList {
		err := firewall.AllowIPThroughFirewall(config.Servers[0], ebpf.ViaAnyPort, &models.RuleSource{
			Kind:    models.AllowUpstreamDNSServer,
			Comment: "when configured as allow list ensure we can call downstream dns server",
		})
		if err != nil {
			slog.Error("Failed to add downstream dns server to allow list", logger.SlogError(err))
			return nil, fmt.Errorf("failed to add downstream dns server to allow list: %w", err)
		}
	}

	serverHandler := &blockingDNSHandler{
		firewallItems:             firewallItems,
		downstreamClient:          downstreamClient,
		dnsFirewall:               firewall,
		DownstreamServerAddr:      downstreamServerAddr,
		allowDNSRequestForBlocked: allowDNSRequestForBlocked,
	}
	server := &dns.Server{Addr: fmt.Sprintf("0.0.0.0:%d", listenPort), Net: "udp", Handler: serverHandler}

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

// Shutdown gracefully shuts down the DNS server
func (d *DNSProxy) Shutdown() error {
	if err := d.Server.Shutdown(); err != nil {
		slog.Error("Failed to shutdown DNS server", logger.SlogError(err))
		return fmt.Errorf("failed to shutdown DNS server: %w", err)
	}
	slog.Debug("DNS server shut down successfully")
	return nil
}

type blockingDNSHandler struct {
	firewallItems             models.FirewallItems
	dnsFirewall               ebpf.DnsFirewall
	downstreamClient          *dns.Client
	DownstreamServerAddr      string
	allowDNSRequestForBlocked bool
}

func (b *blockingDNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true

	pid, err := b.dnsFirewall.GetPidFromDNSTransactionId(r.Id)
	if err != nil {
		slog.Error("Failed to get PID and command from DNS transaction ID", logger.SlogError(err))
	}

	for _, q := range r.Question {
		domainMatchedFirewallDomains := false
		ipKind := ebpf.ViaAnyPort // These are domains which are only allowed via HTTP proxy
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

		slog.Debug("Firewall Items", "httpDomains", b.firewallItems.HttpDomains, "domains", b.firewallItems.Domains)

		// Handle blocking
		// See if any domains are required due to urls like `https://bob.com/bill` in lists
		for _, domain := range b.firewallItems.HttpDomains {
			if strings.HasSuffix(q.Name, domain+".") {
				domainMatchedFirewallDomains = true
				matchedBecause = domain
				// These domains are only allowed via HTTP proxy
				ipKind = ebpf.ViaHttpProxyOnly
			}
		}

		// See if any domains are required as top level domains
		for _, domain := range b.firewallItems.Domains {
			if strings.HasSuffix(q.Name, domain+".") {
				domainMatchedFirewallDomains = true
				matchedBecause = domain
				// Everything is allowed on these domains, allow them out without a proxy
				ipKind = ebpf.ViaAnyPort
			}
		}

		slog.Debug("DNS request", "domain", q.Name, "firewallMatched", domainMatchedFirewallDomains, "ipKind", ipKind, "matchedBecause", matchedBecause)

		requestIsNotAllowed := false

		if !domainMatchedFirewallDomains && b.dnsFirewall != nil && b.dnsFirewall.GetFirewallMethod() == models.AllowList {
			if b.allowDNSRequestForBlocked {
				requestIsNotAllowed = true
			} else {
				m.Rcode = dns.RcodeRefused
				if err := w.WriteMsg(m); err != nil {
					slog.Error("Failed to write DNS response", logger.SlogError(err))
				}

				ruleSource := models.RuleSource{
					Kind:    models.MissingFromAllowList,
					Comment: "Domain doesn't match any allowlist prefixes",
				}

				logger.LogRequest(
					&logger.RequestLog{
						Because:    logger.NotInAllowListExplanation,
						Blocked:    true,
						BlockedAt:  logger.DNSRequestType,
						Domains:    q.Name,
						RuleSource: ruleSource,
						PID:        int(pid),
						OriginalIP: logger.UnknownValue,
						Port:       "53",
					},
				)

				return
			}
		}

		if domainMatchedFirewallDomains && b.dnsFirewall != nil && b.dnsFirewall.GetFirewallMethod() == models.BlockList {
			if b.allowDNSRequestForBlocked {
				requestIsNotAllowed = true
			} else {
				m.Rcode = dns.RcodeRefused
				if err := w.WriteMsg(m); err != nil {
					slog.Error("Failed to write DNS response", logger.SlogError(err))
				}

				ruleSource := models.RuleSource{
					Kind:    models.PresentOnBlockList,
					Comment: fmt.Sprintf("Domain matched blocklist prefix: %s", matchedBecause),
				}

				logger.LogRequest(
					&logger.RequestLog{
						Because:    logger.NotInAllowListExplanation,
						Blocked:    true,
						BlockedAt:  logger.DNSRequestType,
						Domains:    q.Name,
						RuleSource: ruleSource,
						PID:        int(pid),
						OriginalIP: logger.UnknownValue,
						Port:       "53",
					},
				)
				return
			}
		}
		if requestIsNotAllowed && b.allowDNSRequestForBlocked {
			slog.Debug(
				"DNS request which would have been blocked was allowed due to --allow-dns-request",
				"domain", q.Name,
				"firewallMethod", b.dnsFirewall.GetFirewallMethod().String(),
			)
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

		if b.dnsFirewall != nil && b.dnsFirewall.GetFirewallMethod() == models.LogOnly {
			// Do nothing
		} else {
			//                         👇 Don't add the ip if we're allowing dns requests for blocked stuff
			if b.dnsFirewall != nil && !requestIsNotAllowed {
				// If it did match add the IPs to the firewall ip list
				// the matching already decided on the firewall method (allow, block)
				for _, answer := range resp.Answer {
					if a, ok := answer.(*dns.A); ok {
						err = b.dnsFirewall.AllowIPThroughFirewall(
							a.A.String(),
							ipKind,
							&models.RuleSource{
								Kind:    models.AllowIPAddedByDNS,
								Comment: fmt.Sprintf("Matched Domain Prefix: %s - httpOnly: %v", matchedBecause, ipKind == ebpf.ViaHttpProxyOnly),
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

	err = w.WriteMsg(m)
	if err != nil {
		slog.Error("Failed to write DNS response", logger.SlogError(err))
	}
}
