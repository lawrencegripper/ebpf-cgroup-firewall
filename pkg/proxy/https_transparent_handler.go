package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
)

type HttpsTransparentHandler struct {
	httpsPort int
	proxy     *goproxy.ProxyHttpServer
	firewall  *ebpf.EgressFirewall
}

func NewHttpsTransparentHandler(httpsPort int, proxy *goproxy.ProxyHttpServer, firewall *ebpf.EgressFirewall) *HttpsTransparentHandler {
	return &HttpsTransparentHandler{
		httpsPort: httpsPort,
		proxy:     proxy,
		firewall:  firewall,
	}
}

func (h *HttpsTransparentHandler) Start(ctx context.Context) {
	go func() {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", h.httpsPort))
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
			go h.handleHTTPSConnection(c)
		}
	}()
}

func (h *HttpsTransparentHandler) handleHTTPSConnection(c net.Conn) {
	tlsConn, err := vhost.TLS(c)
	if err != nil {
		slog.Error("Error parsing TLS clienthello", logger.SlogError(err))
		return
	}

	_, port, err := getOriginalIpAndPortFromConn(tlsConn.Conn, h.firewall)
	if err != nil {
		// TODO: Why is this needed?
		// I think we messed up the port mapping from src port somewhere in ebpf
		slog.Warn("Failed to get port for request")
		port = 443
	}

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

	// Used for mapping back to ebpf context
	saveConnForRequest(connectReq, tlsConn.Conn)

	resp := dumbResponseWriter{tlsConn}
	h.proxy.ServeHTTP(resp, connectReq)
}
