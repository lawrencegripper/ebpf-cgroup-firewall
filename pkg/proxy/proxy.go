package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/dns"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
)

// Load the mkcert root CA certificate and key
// Assumes `mkcert -install` has been run
func loadMkcertRootCA() (*tls.Certificate, error) {
	cmd := exec.Command("bash", "-c", "mkcert --CAROOT")
	cmd.Env = os.Environ()
	caRootPath, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get mkcert root CA path: %s %v", caRootPath, err)
	}

	slog.Debug("mkcert root CA path", slog.String("path", strings.TrimSpace(string(caRootPath))))
	caCertPath := strings.TrimSpace(string(caRootPath)) + "/rootCA.pem"
	caCertKeyPath := strings.TrimSpace(string(caRootPath)) + "/rootCA-key.pem"

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
	slog.Debug("goproxy logs: " + output)
}

type ProxyServer struct {
	HTTPPort  int
	HTTPSPort int
	server    *http.Server
}

// Start starts both HTTP and HTTPS proxies and returns the ports they're listening on
func Start(httpPort, httpsPort int, firewall *ebpf.EgressFirewall, dnsProxy *dns.DNSProxy, firewallDomains []string, firewallUrls []string) (*ProxyServer, error) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = logger.ShowDebugLogs
	if proxy.Verbose {
		slog.Debug("Server starting up!", "http_port", httpPort, "https_port", httpsPort)
	}

	proxy.Logger = &Logger{}

	cert, err := loadMkcertRootCA()
	if err != nil {
		slog.Error("Error loading mkcert root CA, ensure you have run 'mkcert --install' as this user", logger.SlogError(err))
		panic(err)
	}

	customCaMitm := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(cert)}
	var customAlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return customCaMitm, host
	}

	// Intercept and MITM the CONNECT requests for HTTPS
	proxy.OnRequest().HandleConnect(customAlwaysMitm)

	// Blocking logic in the proxy
	proxy.OnRequest().Do(NewBlockingRequestHandler(firewall, firewallDomains, firewallUrls))

	// Handle http requests sent to the proxy
	httpTranparentHander := NewHttpTransparentHandler(httpPort, firewall, proxy)
	httpTranparentHander.Start()
	proxy.NonproxyHandler = httpTranparentHander

	// Handle https requests sent to the proxy through transparent redirect
	httpsTransparentHandler := NewHttpsTransparentHandler(httpsPort, proxy, firewall)
	httpsTransparentHandler.Start(context.Background())

	return &ProxyServer{}, nil
}

// Shutdown gracefully shuts down the proxy server
func (p *ProxyServer) Shutdown(ctx context.Context) error {
	if p.server != nil {
		return p.server.Shutdown(ctx)
	}
	return nil
}
