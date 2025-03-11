package proxy

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
)

type HttpTransparentHandler struct {
	firewall *ebpf.EgressFirewall
	proxy    *goproxy.ProxyHttpServer
	httpPort int
}

func NewHttpTransparentHandler(httpPort int, firewall *ebpf.EgressFirewall, proxy *goproxy.ProxyHttpServer) *HttpTransparentHandler {
	return &HttpTransparentHandler{
		firewall: firewall,
		proxy:    proxy,
		httpPort: httpPort,
	}
}

func (h *HttpTransparentHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Host == "" {
		fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
		return
	}

	ip, port, err := getOriginalIpAndPortFromReq(req, h.firewall)
	if err != nil {
		slog.Warn("Failed to get port for request. Guessing port 80")
		port = 80
	}

	originalHost := req.Host
	slog.Debug("original host and port", slog.String("host", originalHost), slog.Int("port", port), slog.String("ip", ip.String()))

	req.URL.Scheme = "http"
	req.URL.Host = fmt.Sprintf("%s:%d", originalHost, port)

	h.proxy.ServeHTTP(w, req)
}

func (h *HttpTransparentHandler) Start() {
	go func() {
		server := &http.Server{
			Addr:        fmt.Sprintf(":%d", h.httpPort),
			ConnContext: saveConnInContext,
			Handler:     h.proxy,
		}
		log.Fatalln(server.ListenAndServe())
	}()
}
