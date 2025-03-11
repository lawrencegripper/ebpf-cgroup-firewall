package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
)

type BlockingRequestHandler struct {
	firewall        *ebpf.EgressFirewall
	firewallDomains []string
	firewallUrls    []string
}

func NewBlockingRequestHandler(firewall *ebpf.EgressFirewall, firewallDomains []string, firewallUrls []string) *BlockingRequestHandler {
	return &BlockingRequestHandler{
		firewall:        firewall,
		firewallDomains: firewallDomains,
		firewallUrls:    firewallUrls,
	}
}

func (h *BlockingRequestHandler) Handle(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	pid := getPidFromReq(req, h.firewall)
	// Ensure TLSSourcePortToConn is cleaned up when we're done with it
	// so it doesn't grow indefinitely
	defer cleanupConnMappingToSourcePort(req)

	slog.Info(
		"HTTP proxy handling request",
		slog.Int("pid", pid),
		slog.String("host", req.Host),
		slog.String("url", req.URL.String()),
		slog.String("method", req.Method),
	)

	domainMatchedFirewallDomains := false
	matchedDomain := ""
	for _, domain := range h.firewallDomains {
		if strings.HasSuffix(req.Host, domain) {
			domainMatchedFirewallDomains = true
			matchedDomain = domain
		}
	}

	if h.firewall.FirewallMethod == models.AllowList && !domainMatchedFirewallDomains {
		slog.Warn("HTTP BLOCKED",
			"reason", "NotInAllowList",
			"explaination", "Domain doesn't match any allowlist prefixes",
			"blocked", true,
			"blockedAt", "http",
			"domain", req.Host,
			"pid", pid,
			// TODO: Command tracking for http proxy
			// "cmd", b.dnsFirewall.DnsTransactionIdToCmd[r.Id],
			"firewallMethod", h.firewall.FirewallMethod.String(),
		)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
	}

	if h.firewall.FirewallMethod == models.BlockList && domainMatchedFirewallDomains {
		explaination := fmt.Sprintf("Matched Domain Prefix: %s", matchedDomain)

		// TODO: Add helper method to standardise logging on blocking with DNS proxy
		slog.Warn("HTTP BLOCKED",
			"reason", "InBlockList",
			"explaination", explaination,
			"blocked", true,
			"blockedAt", "http",
			"domain", matchedDomain,
			"pid", pid,
			// "cmd", b.dnsFirewall.DnsTransactionIdToCmd[r.Id],
			"firewallMethod", h.firewall.FirewallMethod.String(),
		)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
	}

	// Look at url blocking
	urlMatchedFirewallUrls := false
	matchedUrl := ""
	reqUrl := req.URL.String()
	// Strip the port from the url if it's the default port
	reqUrl = strings.Replace(reqUrl, ":80", "", 1)
	reqUrl = strings.Replace(reqUrl, ":443", "", 1)
	for _, firewallUrl := range h.firewallUrls {
		slog.Debug("Checking url against firewall url", slog.String("url", reqUrl), slog.String("firewallUrl", firewallUrl))
		if strings.HasPrefix(reqUrl, firewallUrl) {
			urlMatchedFirewallUrls = true
			matchedUrl = firewallUrl
			slog.Debug("Matched url", slog.String("url", reqUrl), slog.String("firewallUrl", firewallUrl))
		}
	}

	if h.firewall.FirewallMethod == models.AllowList && !urlMatchedFirewallUrls {
		slog.Warn("HTTP BLOCKED",
			"reason", "NotInAllowList",
			"explaination", "Url doesn't match any allowlist prefixes",
			"blocked", true,
			"blockedAt", "http",
			"url", reqUrl,
			"pid", pid,
			"firewallMethod", h.firewall.FirewallMethod.String(),
		)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
	}

	if h.firewall.FirewallMethod == models.BlockList && urlMatchedFirewallUrls {
		explaination := fmt.Sprintf("Matched URL Prefix: %s", matchedUrl)

		slog.Warn("HTTP BLOCKED",
			"reason", "InBlockList",
			"explaination", explaination,
			"blocked", true,
			"blockedAt", "http",
			"url", matchedUrl,
			"pid", pid,
			"firewallMethod", h.firewall.FirewallMethod.String(),
		)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
	}

	slog.Debug("HTTP request allowed", slog.String("url", req.URL.String()), slog.String("host", req.Host))

	return req, nil
}
