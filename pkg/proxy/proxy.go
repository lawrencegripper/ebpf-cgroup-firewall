package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/dns"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
)

// Track the underlying connection against the request context for
// http requests so we can use it to get the socket cookie
type contextKey struct {
	key string
}

var ConnContextKey = &contextKey{"http-conn"}

var TLSSourcePortToConn = make(map[int]net.Conn)

func SaveConnInContext(ctx context.Context, c net.Conn) context.Context {
	slog.Debug("SaveConnInContext", slog.String("key", ConnContextKey.key), slog.Any("conn", c), slog.Any("ctx", ctx))
	return context.WithValue(ctx, ConnContextKey, c)
}
func GetConnFromContext(r *http.Request) (net.Conn, error) {
	slog.Debug("GetConn", slog.String("key", ConnContextKey.key), slog.Any("conn", r.Context().Value(ConnContextKey)), slog.Any("ctx", r.Context()))
	if conn, ok := r.Context().Value(ConnContextKey).(net.Conn); ok {
		return conn, nil
	}
	return nil, fmt.Errorf("no connection found in context")
}

// Load the mkcert root CA certificate and key
// Assumes `mkcert -install` has been run
func loadMkcertRootCA() (*tls.Certificate, error) {
	caCertPath := "/root/.local/share/mkcert/rootCA.pem"
	caCertKeyPath := "/root/.local/share/mkcert/rootCA-key.pem"

	caCertContent, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("Error reading CA certificate: %v", err)
	}

	caKeyContent, err := os.ReadFile(caCertKeyPath)
	if err != nil {
		log.Fatalf("Error reading CA key: %v", err)
	}

	parsedCert, err := tls.X509KeyPair(caCertContent, caKeyContent)
	if err != nil {
		return nil, err
	}
	if parsedCert.Leaf, err = x509.ParseCertificate(parsedCert.Certificate[0]); err != nil {
		return nil, err
	}
	return &parsedCert, nil
}

type Logger struct{}

func (l *Logger) Printf(format string, v ...interface{}) {
	// output := fmt.Sprintf(format, v...)
	// slog.Debug("goproxy logs: " + output)
}

func Start(firewall *ebpf.DnsFirewall, dnsProxy *dns.DNSProxy, firewallDomains []string, firewallUrls []string) {
	// TODO Make this dynamic and map to const in ebpf so we don't overlap with used ports
	http_addr := ":6775"
	https_addr := ":6776"

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = logger.ShowDebugLogs
	if proxy.Verbose {
		slog.Debug("Server starting up! - configured to listen on http interface %s and https interface %s", http_addr, https_addr)
	}

	proxy.Logger = &Logger{}

	cert, err := loadMkcertRootCA()
	if err != nil {
		slog.Error("Error loading mkcert root CA", logger.SlogError(err))
		panic(err)
	}

	customCaMitm := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(cert)}
	var customAlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return customCaMitm, host
	}

	// Intercept and MITM the CONNECT requests for HTTPS
	proxy.OnRequest().HandleConnect(customAlwaysMitm)

	// Blocking logic in the proxy
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		pid := getPidFromContextOrSrcPort(req, firewall)
		// Ensure TLSSourcePortToConn is cleaned up when we're done with it
		// so it doesn't grow indefinitely
		defer clearSourcePortToConnMap(req)

		slog.Info(
			"HTTP proxy handling request",
			slog.Int("pid", pid),
			slog.String("host", req.Host),
			slog.String("url", req.URL.String()),
			slog.String("method", req.Method),
		)

		domainMatchedFirewallDomains := false
		matchedDomain := ""
		for _, domain := range firewallDomains {
			if strings.HasSuffix(req.Host, domain) {
				domainMatchedFirewallDomains = true
				matchedDomain = domain
			}
		}

		if firewall.FirewallMethod == models.AllowList && !domainMatchedFirewallDomains {
			slog.Warn("HTTP BLOCKED",
				"reason", "NotInAllowList",
				"explaination", "Domain doesn't match any allowlist prefixes",
				"blocked", true,
				"blockedAt", "http",
				"domain", matchedDomain,
				"pid", pid,
				// TODO: Command tracking for http proxy
				// "cmd", b.dnsFirewall.DnsTransactionIdToCmd[r.Id],
				"firewallMethod", firewall.FirewallMethod.String(),
			)
			return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
		}

		if firewall.FirewallMethod == models.BlockList && domainMatchedFirewallDomains {
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
				"firewallMethod", firewall.FirewallMethod.String(),
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
		for _, firewallUrl := range firewallUrls {
			slog.Debug("Checking url against firewall url", slog.String("url", reqUrl), slog.String("firewallUrl", firewallUrl))
			if strings.HasPrefix(reqUrl, firewallUrl) {
				urlMatchedFirewallUrls = true
				matchedUrl = firewallUrl
			}
		}

		if firewall.FirewallMethod == models.AllowList && !urlMatchedFirewallUrls {
			slog.Warn("HTTP BLOCKED",
				"reason", "NotInAllowList",
				"explaination", "Url doesn't match any allowlist prefixes",
				"blocked", true,
				"blockedAt", "http",
				"url", reqUrl,
				"pid", pid,
				"firewallMethod", firewall.FirewallMethod.String(),
			)
			return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
		}

		if firewall.FirewallMethod == models.BlockList && urlMatchedFirewallUrls {
			explaination := fmt.Sprintf("Matched URL Prefix: %s", matchedUrl)

			slog.Warn("HTTP BLOCKED",
				"reason", "InBlockList",
				"explaination", explaination,
				"blocked", true,
				"blockedAt", "http",
				"url", matchedUrl,
				"pid", pid,
				"firewallMethod", firewall.FirewallMethod.String(),
			)
			return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
		}

		return req, nil
	})

	// Handle http requests sent to the proxy
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}

		conn, err := GetConnFromContext(req)
		port := 80
		if err != nil {
			slog.Debug("Context not set on request, likely https, falling back to source port check")
		} else {
			_, port = getOriginalIpAndPortFromConn(conn, firewall)
		}

		originalHost := req.Host
		slog.Debug("original host and port", slog.String("host", originalHost), slog.Int("port", port))

		req.URL.Scheme = "http"
		req.URL.Host = fmt.Sprintf("%s:%d", originalHost, port)

		proxy.ServeHTTP(w, req)
	})

	go func() {
		server := http.Server{
			Addr:        http_addr,
			ConnContext: SaveConnInContext,
			Handler:     proxy,
		}

		log.Fatalln(server.ListenAndServe())
	}()

	// Handle https requests sent to the proxy through transparent redirect
	// convert them to look like CONNECT requests that would be sent to the proxy by
	// client configured to use it
	go func() {
		ln, err := net.Listen("tcp", https_addr)
		if err != nil {
			slog.Error("Error listening for https connections", logger.SlogError(err))
			panic(err)
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				slog.Error("Error accepting new connection", logger.SlogError(err))
				continue
			}
			go func(c net.Conn) {
				tlsConn, err := vhost.TLS(c)

				_, port := getOriginalIpAndPortFromConn(tlsConn.Conn, firewall)

				if err != nil {
					slog.Error("Error accepting new connection", logger.SlogError(err), slog.String("remoteAddr", c.RemoteAddr().String()))
				}
				if tlsConn.Host() == "" {
					slog.Error("Cannot support non-SNI enabled clients", slog.String("remoteAddr", c.RemoteAddr().String()))
					return
				}

				connectReq := &http.Request{
					Method: http.MethodConnect,
					URL: &url.URL{
						Opaque: tlsConn.Host(),
						Host:   net.JoinHostPort(tlsConn.Host(), fmt.Sprint(port)),
					},
					Host:       tlsConn.Host(),
					Header:     make(http.Header),
					RemoteAddr: c.RemoteAddr().String(),
				}

				// TODO: Hack around tracking conn for tls as transparent proxy loses ctx between requests
				sourcePort := sourcePortFromConn(tlsConn.Conn)
				TLSSourcePortToConn[sourcePort] = tlsConn.Conn

				ctx := context.Background()
				connectReq = connectReq.WithContext(SaveConnInContext(ctx, tlsConn.Conn))
				resp := dumbResponseWriter{tlsConn}
				proxy.ServeHTTP(resp, connectReq)
			}(c)
		}
	}()
}

// getPidFromContextOrSrcPort is a helper method to get the pid from the request
// In the case of HTTP requests the conn is appended using the SaveConnInContext method
// so we can get it from there
// In the case of transparent HTTPS requests the ctx is lost along the way
// instead we use the source port to look up the conn in the TLSSourcePortToConn map
// TODO: Unbounded growth in this map over time
func getPidFromContextOrSrcPort(req *http.Request, firewall *ebpf.DnsFirewall) int {
	conn, err := GetConnFromContext(req)
	pid := -1
	if err != nil {
		slog.Debug("Error getting conn from context, calling back to src port lookup")
	}

	if conn == nil {
		sourcePort, err := getSourcePortFromReq(req)
		if err != nil {
			slog.Error("Error converting source port to int", logger.SlogError(err))
		} else {
			conn = TLSSourcePortToConn[sourcePort]
		}
	}

	if conn != nil {
		pid = getPidFromConn(conn, firewall)
	}
	return pid
}

// getSourcePortFromReq is a helper method to get the source port from the request
func getSourcePortFromReq(req *http.Request) (int, error) {
	sourcePortString := strings.Split(req.RemoteAddr, ":")[1]
	sourcePort, err := strconv.Atoi(sourcePortString)
	return sourcePort, err
}

// clearSourcePortToConnMap is a helper method to remove the conn from the
// TLSSourcePortToConn map once we no longer need it
func clearSourcePortToConnMap(req *http.Request) {
	sourcePort, err := getSourcePortFromReq(req)
	if err != nil {
		slog.Error("Error converting source port to int", logger.SlogError(err))
	} else {
		delete(TLSSourcePortToConn, sourcePort)
	}
}

func getPidFromConn(conn net.Conn, firewall *ebpf.DnsFirewall) int {
	if conn == nil {
		return -1
	}
	sourcePort := sourcePortFromConn(conn)
	pid, err := firewall.PidFromSrcPort(sourcePort)
	if err != nil {
		slog.Error("error getting pid from source port", slog.Int("sourcePort", sourcePort), logger.SlogError(err))
		return -1
	}
	return int(pid)
}

func getOriginalIpAndPortFromConn(conn net.Conn, firewall *ebpf.DnsFirewall) (net.IP, int) {
	sourcePort := sourcePortFromConn(conn)

	ip, port, err := firewall.HostAndPortFromSourcePort(sourcePort)
	if err != nil {
		slog.Error("error getting host and port from source port", slog.Int("sourcePort", sourcePort), logger.SlogError(err))
	}
	slog.Debug("eBPF lookup using source port", slog.Int("sourcePort", sourcePort), slog.String("originalIP", ip.String()), slog.Int("originalPort", port))
	return ip, port
}

func sourcePortFromConn(conn net.Conn) int {
	localAddr := conn.RemoteAddr().(*net.TCPAddr)
	sourcePort := localAddr.Port
	return sourcePort
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) LocalAddr() net.Addr {
	return dumb.Conn.RemoteAddr()
}

func (dumb dumbResponseWriter) SocketCookie() (utils.SocketCookie, error) {
	return utils.GetSocketCookie(dumb.Conn)
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}
