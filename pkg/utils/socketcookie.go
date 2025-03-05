package utils

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/inconshreveable/go-vhost"
	"golang.org/x/sys/unix"
)

type SocketCookie uint64

func GetSocketCookie(conn net.Conn) (SocketCookie, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		slog.Warn("conn is not a TCPConn")

		// Is it a TLSConn?
		tlsConn, ok := conn.(*vhost.TLSConn)
		if !ok {
			return 0, fmt.Errorf("conn is not a TLSConn")
		}

		tcpConn = tlsConn.Conn.(*net.TCPConn)
	}

	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var cookie uint64
	var sockErr error

	if err := raw.Control(func(fd uintptr) {
		cookie, sockErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil {
		return 0, fmt.Errorf("failed to control socket: %w", err)
	}

	if sockErr != nil {
		return 0, fmt.Errorf("failed to get socket cookie: %w", sockErr)
	}

	return SocketCookie(cookie), nil
}
