package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
)

type BlockingRequestHandler struct {
	firewall      *ebpf.EgressFirewall
	firewallItems models.FirewallItems
}

func NewBlockingRequestHandler(firewall *ebpf.EgressFirewall, firewallitems models.FirewallItems) *BlockingRequestHandler {
	return &BlockingRequestHandler{
		firewall:      firewall,
		firewallItems: firewallitems,
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
	fullAllowedDomains := append(h.firewallItems.Domains, h.firewallItems.HttpDomains...)
	for _, domain := range fullAllowedDomains {
		if strings.HasSuffix(req.Host, domain) {
			domainMatchedFirewallDomains = true
			matchedDomain = domain
		}
	}

	if h.firewall.FirewallMethod == models.AllowList && !domainMatchedFirewallDomains {
		logger.LogRequest(
			&logger.RequestLog{
				Because:   logger.NotInAllowListExplanation,
				Blocked:   true,
				BlockedAt: logger.HTTPRequestType,
				Domains:   req.Host,
				RuleSource: models.RuleSource{
					Kind:    models.MissingFromAllowList,
					Comment: "Domain doesn't match any allowlist prefixes",
				},
				PID:  pid,
				Port: req.URL.Port(),
				URL:  req.URL.String(),
			},
		)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
	}

	if h.firewall.FirewallMethod == models.BlockList && domainMatchedFirewallDomains {

		// TODO: Add helper method to standardise logging on blocking with DNS proxy
		logger.LogRequest(
			&logger.RequestLog{
				Because:   logger.InBlockListedExplaination,
				Blocked:   true,
				BlockedAt: logger.HTTPRequestType,
				Domains:   req.Host,
				RuleSource: models.RuleSource{
					Kind:    models.PresentOnBlockList,
					Comment: fmt.Sprintf("Matched Domain Prefix: %s", matchedDomain),
				},
				PID:  pid,
				Port: req.URL.Port(),
				URL:  req.URL.String(),
			},
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

	for _, firewallUrl := range h.firewallItems.URLs {
		slog.Debug("Checking url against firewall url", slog.String("url", reqUrl), slog.String("firewallUrl", firewallUrl))
		if strings.HasPrefix(reqUrl, firewallUrl) {
			urlMatchedFirewallUrls = true
			matchedUrl = firewallUrl
			slog.Debug("Matched url", slog.String("url", reqUrl), slog.String("firewallUrl", firewallUrl))
		}
	}

	if h.firewall.FirewallMethod == models.AllowList && !urlMatchedFirewallUrls {
		logger.LogRequest(
			&logger.RequestLog{
				Because:   logger.NotInAllowListExplanation,
				Blocked:   true,
				BlockedAt: logger.HTTPRequestType,
				Domains:   req.Host,
				RuleSource: models.RuleSource{
					Kind:    models.MissingFromAllowList,
					Comment: "URL doesn't match any allowlist prefixes",
				},
				PID:  pid,
				Port: req.URL.Port(),
				URL:  reqUrl,
			},
		)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
	}

	if h.firewall.FirewallMethod == models.BlockList && urlMatchedFirewallUrls {
		explaination := fmt.Sprintf("Matched URL Prefix: %s", matchedUrl)

		logger.LogRequest(
			&logger.RequestLog{
				Because:   logger.InBlockListedExplaination,
				Blocked:   true,
				BlockedAt: logger.HTTPRequestType,
				Domains:   req.Host,
				RuleSource: models.RuleSource{
					Kind:    models.PresentOnBlockList,
					Comment: explaination,
				},
				PID:  pid,
				Port: req.URL.Port(),
				URL:  reqUrl,
			},
		)
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
	}

	logger.LogRequest(
		&logger.RequestLog{
			Because:   logger.AllowedExplaination,
			Blocked:   false,
			BlockedAt: logger.HTTPRequestType,
			Domains:   req.Host,
			PID:       pid,
			Port:      req.URL.Port(),
			URL:       req.URL.String(),
		},
	)

	return req, nil
}
