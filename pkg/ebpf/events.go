package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"

	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
)

const (
	// These ints are defined in ./ebpf/bpf.c line 34-40
	DNS_PROXY_PACKET_BYPASS_TYPE  EventType = 1
	DNS_REDIRECT_TYPE             EventType = 11
	LOCALHOST_PACKET_BYPASS_TYPE  EventType = 12
	HTTP_PROXY_PACKET_BYPASS_TYPE EventType = 2
	HTTP_REDIRECT_TYPE            EventType = 22
	PROXY_PID_BYPASS_TYPE         EventType = 23
	PACKET_IPV6_TYPE              EventType = 24
	NORMAL_PACKET_TYPE            EventType = 0
)

// EventType represents the type of event from the eBPF program
type EventType uint8

func (e EventType) isDNSRelated() bool {
	return e == DNS_PROXY_PACKET_BYPASS_TYPE || e == DNS_REDIRECT_TYPE
}

// HumanReadable returns a human-readable string representation of the event type
func (e EventType) HumanReadable() string {
	switch e {
	case DNS_PROXY_PACKET_BYPASS_TYPE:
		return "DNS Proxy Packet Bypass"
	case DNS_REDIRECT_TYPE:
		return "DNS Redirect"
	case LOCALHOST_PACKET_BYPASS_TYPE:
		return "Localhost Packet Bypass"
	case HTTP_PROXY_PACKET_BYPASS_TYPE:
		return "HTTP Proxy Packet Bypass"
	case HTTP_REDIRECT_TYPE:
		return "HTTP Redirect"
	case PROXY_PID_BYPASS_TYPE:
		return "Proxy PID Bypass"
	case PACKET_IPV6_TYPE:
		return "IPv6 Packet"
	case NORMAL_PACKET_TYPE:
		return "Normal Packet"
	default:
		return "Unknown Event Type"
	}
}

func (e *EgressFirewall) monitorRingBufferEventfunc() {
	var event bpfEvent

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

		ruleSource, foundReason := e.FirewallIPsWithRuleSource.Load(intToIPHostByteOrder(event.Ip).String())
		if !foundReason {
			ruleSource = &models.RuleSource{
				Kind:    models.Unknown,
				Comment: "Unknown",
			}
		}

		ip := intToIPHostByteOrder(event.Ip)
		originalIp := intToIPHostByteOrder(event.OriginalIp)

		eventType := EventType(event.EventType)

		if eventType == NORMAL_PACKET_TYPE || eventType == PACKET_IPV6_TYPE {
			// These are blocked and allowed packets
			logPacket(eventType, e, ip, event, ruleSource, originalIp)
		} else {
			// These are special events where we've done something, like redirecting a DNS request to localhost
			// or bypassing the proxy for a DNS request

			// Create common logging attributes to avoid repetition
			logRedirectOrBypass(eventType, ip, event, e)
		}
	}
}

func logRedirectOrBypass(eventType EventType, ip net.IP, event bpfEvent, e *EgressFirewall) {
	sharedAttrs := []any{
		slog.String("eventType", eventType.HumanReadable()),
		slog.String("ip", ip.String()),
		slog.String("originalIp", intToIPHostByteOrder(event.Ip).String()),
		slog.Int("port", int(event.Port)),
		slog.Int("pid", int(event.Pid)),
		slog.String("cmd", logger.CmdLineFromPid(int(event.Pid))),
		slog.Bool("allowed", event.Allowed),
	}

	// Store the dns transaction id to correlate the pid and command which made the request
	if eventType.isDNSRelated() {
		if event.DnsTransactionId != 0 {
			e.dnsTransactionIdToPid.Store(event.DnsTransactionId, event.Pid)
		}

		sharedAttrs = append(sharedAttrs, slog.Any("dnsTransactionId", event.DnsTransactionId))
	}

	slog.Info(eventType.HumanReadable(), sharedAttrs...)
}

func logPacket(eventType EventType, e *EgressFirewall, ip net.IP, event bpfEvent, ruleSource *models.RuleSource, originalIp net.IP) {
	ipResolvedForDomains := "None"
	ipResolvedDomainList, foundDomainsForIp := e.ipDomainTracking.Load(ip.String())
	if foundDomainsForIp {
		ipResolvedForDomains = ipResolvedDomainList.String()
	}

	because := logger.AllowedExplaination
	if !event.Allowed {
		because = logger.PacketIPNotInAllowList
	}

	// IPv6 packets are always blocked atm
	if !event.Allowed && eventType == PACKET_IPV6_TYPE {
		because = logger.PacketIPv6Blocked
	}

	logger.LogRequest(
		&logger.RequestLog{
			Because:    because,
			Blocked:    !event.Allowed,
			BlockedAt:  logger.PacketRequestType,
			Domains:    ipResolvedForDomains,
			RuleSource: *ruleSource,
			PID:        int(event.Pid),
			IP:         ip.String(),
			OriginalIP: originalIp.String(),
			Port:       fmt.Sprint(event.Port),
		},
	)
}
