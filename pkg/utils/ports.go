package utils

import (
	"fmt"
	"net"
)

// FindUnusedPort Finds an unused port to listen on
func FindUnusedPort() (int, error) {
	listener, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return 0, fmt.Errorf("failed to find an unused port: %w", err)
	}
	defer listener.Close()
	addr, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("failed to assert type to *net.UDPAddr")
	}
	return addr.Port, nil
}
