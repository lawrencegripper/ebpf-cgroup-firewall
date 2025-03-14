package dns

import (
	"fmt"
	"net"
	"testing"

	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/stretchr/testify/require"
)

func mockedBlockingFirewall(t *testing.T) *ebpf.MockDnsFirewall {
	blockingFirewall := ebpf.NewMockDnsFirewall(t)
	blockingFirewall.On("GetFirewallMethod").Return(models.BlockList).Maybe()
	blockingFirewall.On("AllowIPThroughFirewall", mock.Anything, mock.Anything).Return(nil).Maybe()
	blockingFirewall.On("TrackIPToDomain", mock.Anything, mock.Anything).Maybe()
	blockingFirewall.On("GetPidAndCommandFromDNSTransactionId", mock.Anything).Return(uint32(0), "", nil).Maybe()
	return blockingFirewall
}

func TestCreateDNSProxyForCgroup_ResolvesDomains(t *testing.T) {
	blockingFirewall := mockedBlockingFirewall(t)

	domainsToBlock := models.FirewallItems{Domains: []string{"bing.com"}}

	proxy, err := StartDNSMonitoringProxy(55555, domainsToBlock, blockingFirewall, false)
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
}

func TestDNSProxy_BlocksDomains(t *testing.T) {
	blockingFirewall := mockedBlockingFirewall(t)
	domainsToBlock := models.FirewallItems{Domains: []string{"example.com"}}

	proxy, err := StartDNSMonitoringProxy(55555, domainsToBlock, blockingFirewall, false)
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
}

func TestDNSProxy_Shutdown(t *testing.T) {
	domainsToBlock := models.FirewallItems{Domains: []string{"bing.com"}}

	blockingFirewall := mockedBlockingFirewall(t)

	proxy, err := StartDNSMonitoringProxy(55555, domainsToBlock, blockingFirewall, false)
	require.NoError(t, err)
	assert.NotNil(t, proxy)

	err = proxy.Shutdown()
	assert.NoError(t, err)
}

func TestFindUnusedPort(t *testing.T) {
	port, err := utils.FindUnusedPort()
	require.NoError(t, err)
	assert.NotEqual(t, 0, port)

	// Listen on the port with UDP to valid it is actually unused
	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
	require.NoError(t, err)
	err = conn.Close()
	require.NoError(t, err)
}

func TestDNSProxy_RefusesIPv6Requests(t *testing.T) {
	domainsToBlock := models.FirewallItems{Domains: []string{"bing.com"}}

	blockingFirewall := mockedBlockingFirewall(t)

	proxy, err := StartDNSMonitoringProxy(55555, domainsToBlock, blockingFirewall, false)
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
