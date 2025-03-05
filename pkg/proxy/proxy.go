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
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/dns"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
)

// Track the underlying connection against the request context for
// http requests so we can use it to get the socket cookie
type contextKey struct {
	key string
}

var ConnContextKey = &contextKey{"http-conn"}

func SaveConnInContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, ConnContextKey, c)
}
func GetConn(r *http.Request) net.Conn {
	return r.Context().Value(ConnContextKey).(net.Conn)
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
	output := fmt.Sprintf(format, v...)
	slog.Info(output)
}

func Start(firewall *ebpf.DnsFirewall, dnsProxy *dns.DNSProxy, firewallDomains []string) {
	http_addr := ":6775"
	https_addr := ":6776"

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	if proxy.Verbose {
		log.Printf("Server starting up! - configured to listen on http interface %s and https interface %s", http_addr, https_addr)
	}

	proxy.Logger = &Logger{}

	cert, err := loadMkcertRootCA()
	if err != nil {
		log.Fatal(err)
	}

	customCaMitm := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(cert)}
	var customAlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return customCaMitm, host
	}

	// Intercept and MITM the CONNECT requests for HTTPS
	proxy.OnRequest().HandleConnect(customAlwaysMitm)

	// Blocking logic in the proxy
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		for _, domain := range firewallDomains {
			if firewall.FirewallMethod == models.AllowList {
				if !strings.Contains(req.Host, domain) {
					log.Printf("http proxy blocked domain not on allow list: %v", domain)
					return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
				}
			} else if firewall.FirewallMethod == models.BlockList {
				if strings.Contains(req.Host, domain) {
					log.Printf("http proxy blocked domain: %v", domain)
					return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Blocked by DNS monitoring proxy")
				}
			}
		}

		return req, nil
	})

	// Handle http requests sent to the proxy
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}

		conn := GetConn(req)

		_, port := getOriginalIpAndPortFromConn(conn, firewall)

		originalHost := req.Host
		slog.Info("original host", slog.String("host", originalHost))
		log.Printf("full url: %v", req.URL.String())
		log.Printf("request method: %v", req.Method)

		req.URL.Scheme = "http"
		req.URL.Host = fmt.Sprintf("%s:%d", originalHost, port)
		log.Printf("new host: %v", req.URL.Host)

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
			log.Fatalf("Error listening for https connections - %v", err)
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Printf("Error accepting new connection - %v", err)
				continue
			}
			go func(c net.Conn) {
				tlsConn, err := vhost.TLS(c)

				_, port := getOriginalIpAndPortFromConn(tlsConn.Conn, firewall)

				log.Printf("tlsConn: %v", tlsConn)
				if err != nil {
					log.Printf("Error accepting new connection - %v", err)
				}
				if tlsConn.Host() == "" {
					log.Printf("Cannot support non-SNI enabled clients")
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
				resp := dumbResponseWriter{tlsConn}
				proxy.ServeHTTP(resp, connectReq)
			}(c)
		}
	}()
}

func getOriginalIpAndPortFromConn(conn net.Conn, firewall *ebpf.DnsFirewall) (net.IP, int) {
	localAddr := conn.RemoteAddr().(*net.TCPAddr)
	sourcePort := localAddr.Port

	slog.Default().Warn("sourcePort", slog.Int("sourcePort", sourcePort))

	ip, port, err := firewall.HostAndPortFromSourcePort(sourcePort)
	if err != nil {
		log.Printf("error getting host and port from source port: %v", err)
	}
	return ip, port
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
