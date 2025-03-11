package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
)

// Track the underlying connection against the request context for
// http requests so we can use it to get the socket cookie
type contextKey struct {
	key string
}

var SourcePortToConn = utils.GenericSyncMap[int, net.Conn]{}

var ConnContextKey = &contextKey{"http-conn"}

func saveConnInContext(ctx context.Context, c net.Conn) context.Context {
	slog.Debug("SaveConnInContext", slog.String("key", ConnContextKey.key), slog.Any("conn", c), slog.Any("ctx", ctx))
	srcPort := sourcePortFromConn(c)
	SourcePortToConn.Store(srcPort, c)
	return context.WithValue(ctx, ConnContextKey, c)
}

func saveConnForRequest(r *http.Request, c net.Conn) {
	sourcePort := sourcePortFromConn(c)
	SourcePortToConn.Store(sourcePort, c)
}

func getConnFromRequest(r *http.Request) (net.Conn, error) {
	slog.Debug("GetConn", slog.String("key", ConnContextKey.key), slog.Any("conn", r.Context().Value(ConnContextKey)), slog.Any("ctx", r.Context()))

	// Get from the sync map if it exists
	if conn, ok := SourcePortToConn.Load(getSourcePortFromReq(r)); ok {
		return conn, nil
	}

	// Otherwise, get from the context (works for http only)
	if conn, ok := r.Context().Value(ConnContextKey).(net.Conn); ok {
		return conn, nil
	}
	return nil, fmt.Errorf("no connection found in context")
}

// getSourcePortFromReq is a helper method to get the source port from the request
func getSourcePortFromReq(req *http.Request) int {
	sourcePortString := strings.Split(req.RemoteAddr, ":")[1]
	sourcePort, err := strconv.Atoi(sourcePortString)
	if err != nil {
		panic("Failed to convert source port to int. This should be impossible")
	}
	return sourcePort
}

// cleanupConnMappingToSourcePort is a helper method to remove the conn from the
// TLSSourcePortToConn map once we no longer need it
func cleanupConnMappingToSourcePort(req *http.Request) {
	sourcePort := getSourcePortFromReq(req)
	SourcePortToConn.Delete(sourcePort)
}

func getPidFromReq(req *http.Request, firewall *ebpf.EgressFirewall) int {
	conn, err := getConnFromRequest(req)
	if err != nil {
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

func getOriginalIpAndPortFromConn(conn net.Conn, firewall *ebpf.EgressFirewall) (net.IP, int, error) {
	sourcePort := sourcePortFromConn(conn)

	ip, port, err := firewall.HostAndPortFromSourcePort(sourcePort)
	if err != nil {
		slog.Error("error getting host and port from source port", slog.Int("sourcePort", sourcePort), logger.SlogError(err))
		return nil, 0, fmt.Errorf("error getting host and port from source port: %w", err)
	}
	slog.Debug("eBPF lookup using source port", slog.Int("sourcePort", sourcePort), slog.String("originalIP", ip.String()), slog.Int("originalPort", port))
	return ip, port, nil
}

func getOriginalIpAndPortFromReq(req *http.Request, firewall *ebpf.EgressFirewall) (net.IP, int, error) {
	conn, err := getConnFromRequest(req)
	if err != nil {
		slog.Error("error getting conn from request", logger.SlogError(err))
		return nil, 0, fmt.Errorf("error getting conn from request: %w", err)
	}

	return getOriginalIpAndPortFromConn(conn, firewall)
}

func sourcePortFromConn(conn net.Conn) int {
	localAddr := conn.RemoteAddr().(*net.TCPAddr)
	sourcePort := localAddr.Port
	return sourcePort
}
