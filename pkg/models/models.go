package models

import (
	"encoding/binary"
	"net"
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
		return "UserUserSpecifiedIP"
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
