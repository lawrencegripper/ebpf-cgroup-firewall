package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
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
	// https_addr := flag.String("httpsaddr", ":3128", "proxy https listen address")

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	if proxy.Verbose {
		log.Printf("Server starting up! - configured to listen on http interface %s and https interface", http_addr)
	}

	// proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// 	log.Printf("resquest: %v", 1)

	// 	conn := GetConn(req)
	// 	socketCookie, err := utils.GetSocketCookie(conn)
	// 	if err != nil {
	// 		ctx.Logf("error getting socket cookie: %v", err)
	// 	}
	// 	log.Printf("socket cookie: %v", socketCookie)

	// 	return req, nil
	// })

	// proxy.OnRequest().HijackConnect()
	proxy.OnRequest().
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			defer func() {
				if e := recover(); e != nil {
					ctx.Logf("error connecting to remote: %v", e)
					client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				}
				client.Close()
			}()

			panic("test")

			ctx.Logf("hello!")

			socketCookie, err := utils.GetSocketCookie(client)
			if err != nil {
				ctx.Logf("error getting socket cookie: %v", err)
			}

			ctx.Logf("socket cookie: %v", socketCookie)
			log.Printf("socket cookie: %v", socketCookie)

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
	// ln, err := net.Listen("tcp", *https_addr)
	// if err != nil {
	// 	log.Fatalf("Error listening for https connections - %v", err)
	// }
	// for {
	// 	c, err := ln.Accept()
	// 	if err != nil {
	// 		log.Printf("Error accepting new connection - %v", err)
	// 		continue
	// 	}
	// 	go func(c net.Conn) {
	// 		tlsConn, err := vhost.TLS(c)
	// 		if err != nil {
	// 			log.Printf("Error accepting new connection - %v", err)
	// 		}
	// 		if tlsConn.Host() == "" {
	// 			log.Printf("Cannot support non-SNI enabled clients")
	// 			return
	// 		}
	// 		connectReq := &http.Request{
	// 			Method: http.MethodConnect,
	// 			URL: &url.URL{
	// 				Opaque: tlsConn.Host(),
	// 				Host:   net.JoinHostPort(tlsConn.Host(), "443"),
	// 			},
	// 			Host:       tlsConn.Host(),
	// 			Header:     make(http.Header),
	// 			RemoteAddr: c.RemoteAddr().String(),
	// 		}
	// 		resp := dumbResponseWriter{tlsConn}
	// 		proxy.ServeHTTP(resp, connectReq)
	// 	}(c)
	// }
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
