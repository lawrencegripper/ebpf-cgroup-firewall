package proxy

import (
	"bufio"
	"bytes"
	"net"
	"net/http"

	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
)

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
