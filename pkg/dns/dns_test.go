package dns

import (
	"fmt"
	"net"
	"testing"

	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateDNSProxyForCgroup_ResolvesDomains(t *testing.T) {
	blockingFirewall := ebpf.DnsFirewall{
		FirewallMethod: models.BlockList,
	}
	domainsToBlock := []string{"bing.com"}

	proxy, err := StartDNSMonitoringProxy(55555, domainsToBlock, &blockingFirewall, false)
	require.NoError(t, err)

	defer proxy.Shutdown() //nolint:errcheck // Shutdown the proxy after test

	// Simulate a DNS request to a blocked domain
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	conn, err := client.Dial("127.0.0.1:" + fmt.Sprintf("%d", proxy.Port))
	require.NoError(t, err)
	defer conn.Close()

	err = conn.WriteMsg(msg)
	require.NoError(t, err)

	resp, err := conn.ReadMsg()
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	blockedDomains := proxy.BlockedDomains()
	assert.Empty(t, blockedDomains)
}

func TestDNSProxy_BlocksDomains(t *testing.T) {
	blockingFirewall := ebpf.DnsFirewall{
		FirewallMethod: models.BlockList,
	}
	domainsToBlock := []string{"example.com"}

	proxy, err := StartDNSMonitoringProxy(55555, domainsToBlock, &blockingFirewall, false)
	require.NoError(t, err)
	assert.NotNil(t, proxy)

	// Shutdown the proxy after test
	defer proxy.Shutdown() //nolint:errcheck

	// Simulate a DNS request to a blocked domain
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("api.example.com.", dns.TypeA)
	resp, _, err := client.Exchange(msg, "127.0.0.1:"+fmt.Sprintf("%d", proxy.Port))
	require.NoError(t, err)

	// Check the response was successful
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)

	// Check blocked domains is empty
	blockedDomains := proxy.BlockedDomains()
	assert.Contains(t, blockedDomains, "example.com")

	// Check the block log is correctly populated
	blockLog := proxy.BlockingDNSHandler.BlockLog
	require.Len(t, blockLog, 1)
	assert.Equal(t, "example.com", blockLog[0].MatchedDomainSuffix)
	assert.Equal(t, "api.example.com.", blockLog[0].DNSRequest)
}

func TestDNSProxy_Shutdown(t *testing.T) {
	domainsToBlock := []string{"example.com"}

	proxy, err := StartDNSMonitoringProxy(55555, domainsToBlock, nil, false)
	require.NoError(t, err)
	assert.NotNil(t, proxy)

	err = proxy.Shutdown()
	assert.NoError(t, err)
}

func TestFindUnusedPort(t *testing.T) {
	port, err := FindUnusedPort()
	require.NoError(t, err)
	assert.NotEqual(t, 0, port)

	// Listen on the port with UDP to valid it is actually unused
	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
	require.NoError(t, err)
	err = conn.Close()
	require.NoError(t, err)
}

func TestDNSProxy_RefusesIPv6Requests(t *testing.T) {
	domainsToBlock := []string{"example.com"}

	proxy, err := StartDNSMonitoringProxy(55555, domainsToBlock, nil, false)
	require.NoError(t, err)
	assert.NotNil(t, proxy)

	// Shutdown the proxy after test
	defer proxy.Shutdown() //nolint:errcheck

	// Simulate an IPv6 DNS request
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeAAAA)
	resp, _, err := client.Exchange(msg, "127.0.0.1:"+fmt.Sprintf("%d", proxy.Port))
	require.NoError(t, err)

	// Check that IPv6 requests are refused
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
}
