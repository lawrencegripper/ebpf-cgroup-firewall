package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/dns"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

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

func Start(firewall *ebpf.DnsFirewall, dnsProxy *dns.DNSProxy, firewallDomains []string) {
	http_addr := ":6775"
	https_addr := ":6776"

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	if proxy.Verbose {
		log.Printf("Server starting up! - configured to listen on http interface %s and https interface %s", http_addr, https_addr)
	}

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			defer func() {
				if e := recover(); e != nil {
					ctx.Logf("error connecting to remote: %v", e)
					client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				}
				client.Close()
			}()

			// panic("test")

			slog.Info("client type", "type", fmt.Sprintf("%T", client))
			underlyingConn, ok := client.(dumbResponseWriter)
			if !ok {
				panic("client is not a dumbResponseWriter")
			}
			socketCookie, err := underlyingConn.SocketCookie()
			if err != nil {
				ctx.Logf("error getting socket cookie: %v", err)
			}

			slog.Warn("socket cookie", "cookie", socketCookie)

			localAddr := underlyingConn.LocalAddr().(*net.TCPAddr)
			sourcePort := localAddr.Port
			log.Printf("source port: %v", sourcePort)

			ip, port, err := firewall.HostAndPortFromSourcePort(sourcePort)
			if err != nil {
				log.Printf("error getting host and port from source port: %v", err)
			}

			req.URL.Scheme = "https"
			req.URL.Host = fmt.Sprintf("%s:%d", ip, port)
			log.Printf("new host: %v", req.URL.Host)

			clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))

			remote, err := connectDial(req.Context(), proxy, "tcp", req.URL.Host)
			orPanic(err)

			ctx.Logf("remote addr: %v", remote.RemoteAddr())
			// if firewall.FirewallMethod == models.AllowList {
			// 	remote.RemoteAddr()
			// } else if firewall.FirewallMethod == models.BlockList {

			// }

			remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))
			for {
				req, err := http.ReadRequest(clientBuf.Reader)
				orPanic(err)
				orPanic(req.Write(remoteBuf))
				orPanic(remoteBuf.Flush())
				resp, err := http.ReadResponse(remoteBuf.Reader, req)
				orPanic(err)
				orPanic(resp.Write(clientBuf.Writer))
				orPanic(clientBuf.Flush())
			}
		})

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}

		conn := GetConn(req)

		localAddr := conn.RemoteAddr().(*net.TCPAddr)
		sourcePort := localAddr.Port
		log.Printf("source port: %v", sourcePort)

		ip, port, err := firewall.HostAndPortFromSourcePort(sourcePort)
		if err != nil {
			log.Printf("error getting host and port from source port: %v", err)
		}

		originalHost := req.Host
		log.Printf("original host: %v", originalHost)
		log.Printf("full url: %v", req.URL.String())
		log.Printf("request method: %v", req.Method)

		for _, domain := range firewallDomains {
			if firewall.FirewallMethod == models.AllowList {
				if !strings.Contains(originalHost, domain) {
					log.Printf("http proxy blocked domain not on allow list: %v", domain)
					conn.Close()
				}
			} else if firewall.FirewallMethod == models.BlockList {
				if strings.Contains(originalHost, domain) {
					log.Printf("http proxy blocked domain: %v", domain)
					conn.Close()
					return
				}
			}
		}

		req.URL.Scheme = "http"
		req.URL.Host = fmt.Sprintf("%s:%d", ip, port)
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

	// // listen to the TLS ClientHello but make it a CONNECT request instead
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
						Host:   net.JoinHostPort(tlsConn.Host(), "443"),
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

// copied/converted from https.go
func dial(ctx context.Context, proxy *goproxy.ProxyHttpServer, network, addr string) (c net.Conn, err error) {
	if proxy.Tr.DialContext != nil {
		return proxy.Tr.DialContext(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// copied/converted from https.go
func connectDial(ctx context.Context, proxy *goproxy.ProxyHttpServer, network, addr string) (c net.Conn, err error) {
	if proxy.ConnectDial == nil {
		return dial(ctx, proxy, network, addr)
	}
	return proxy.ConnectDial(network, addr)
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
