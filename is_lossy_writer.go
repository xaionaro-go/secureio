package secureio

import (
	"io"
	"net"
)

// IsLossyWriter returns true if writer `w` is a known type of a writer
// which can loose traffic (currently it only looks for UDP connections).
func IsLossyWriter(w io.Writer) bool {
	switch conn := w.(type) {
	case *net.UDPConn:
		return true
	case interface{ LocalAddr() net.Addr }:
		remoteAddr := conn.LocalAddr()
		switch remoteAddr.(type) {
		case *net.TCPAddr:
			return false
		case *net.UDPAddr:
			// TODO: exclude QUIC
			return true
		case *net.UnixAddr:
			return false
		}
		return false
	default:
		return false
	}
}
