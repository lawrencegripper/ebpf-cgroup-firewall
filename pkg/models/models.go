package models

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
)

type FirewallMethod uint16

const (
	LogOnly   FirewallMethod = 0
	AllowList FirewallMethod = 1
	BlockList FirewallMethod = 2
)

func (f FirewallMethod) String() string {
	switch f {
	case LogOnly:
		return "logonly"
	case AllowList:
		return "allowlist"
	case BlockList:
		return "blocklist"
	default:
		return "unknown"
	}
}

func IPToIntNetworkOrder(val string) uint32 {
	ip := net.ParseIP(val).To4()
	return binary.LittleEndian.Uint32(ip)
}

// TODO: Think this will fail on arm as it assumes little endian
func IntToIP(val uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, val)
	return ip
}

func IntToPort(val uint16) uint16 {
	return binary.BigEndian.Uint16([]byte{byte(val >> 8), byte(val & 0xff)})
}

type RuleKind int

const (
	AllowUserSpecifiedIP RuleKind = iota
	AllowIPAddedByDNS
	AllowUpstreamDNSServer
	MissingFromAllowList
	PresentOnBlockList
	Allowed
	Unknown
)

type RuleSource struct {
	Kind    RuleKind
	Comment string
}

func (r *RuleSource) KindHumanReadable() string {
	switch r.Kind {
	case AllowUserSpecifiedIP:
		return "UserSpecifiedIP"
	case AllowIPAddedByDNS:
		return "FromDNSRequest"
	case AllowUpstreamDNSServer:
		return "FromUpstreamDNSServer"
	case MissingFromAllowList:
		return "NotInAllowList"
	case PresentOnBlockList:
		return "MatchedBlockListDomain"
	case Unknown:
		return "Unknown"
	default:
		return "ReallyUnknown"
	}
}

type FirewallItems struct {
	IPs         []string
	Domains     []string
	HttpDomains []string
	URLs        []string
}

func SplitDomainUrlOrIPListByType(firewallMethod FirewallMethod, allowList []string) FirewallItems {
	items := FirewallItems{
		IPs:         make([]string, 0),
		Domains:     make([]string, 0),
		HttpDomains: make([]string, 0),
		URLs:        make([]string, 0),
	}

	for _, item := range allowList {
		// Simple IP check - looks for dots and numbers
		if strings.Count(item, ".") == 3 {
			isIP := true
			for _, part := range strings.Split(item, ".") {
				if len(part) == 0 {
					isIP = false
					break
				}
				for _, c := range part {
					if c < '0' || c > '9' {
						isIP = false
						break
					}
				}
			}
			if isIP {
				items.IPs = append(items.IPs, item)
				continue
			}
		}

		// Is it a url?
		// TODO: Can we do better detection?
		if strings.Contains(item, "://") {
			parsedUrl, err := url.Parse(item)
			if err != nil {
				slog.Error("Failed to parse URL", "url", item, slog.Any("error", err))
				panic(err)
			}

			items.URLs = append(items.URLs, item)
			slog.Debug("Adding domain to http domain list because of url rule", "domain", parsedUrl.Host)
			if firewallMethod == AllowList {
				items.HttpDomains = append(items.HttpDomains, parsedUrl.Host)
			}

			continue
		}

		// If not hen it's a domain
		items.Domains = append(items.Domains, item)
		// If a domain is added automatically enable all urls under that domain on http and https
		// TODO: Document this logic
		items.URLs = append(items.URLs, fmt.Sprintf("http://%s", item))
		items.URLs = append(items.URLs, fmt.Sprintf("https://%s", item))
	}

	// Deduplicate HttpDomains
	seen := make(map[string]struct{})
	uniqueHttpDomains := make([]string, 0, len(items.HttpDomains))

	for _, domain := range items.HttpDomains {
		if _, exists := seen[domain]; !exists {
			seen[domain] = struct{}{}
			uniqueHttpDomains = append(uniqueHttpDomains, domain)
		}
	}

	items.HttpDomains = uniqueHttpDomains

	return items
}
