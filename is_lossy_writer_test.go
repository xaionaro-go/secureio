package secureio

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type unknownConn struct {
	net.Conn
}

func (conn *unknownConn) LocalAddr() net.Addr {
	return nil
}

type udpConn struct {
	net.Conn
}

func (conn *udpConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func TestIsLossyWriter(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		require.False(t, IsLossyWriter(&net.TCPConn{}))
	})
	t.Run("udp", func(t *testing.T) {
		require.True(t, IsLossyWriter(&net.UDPConn{}))
	})
	t.Run("udp_indirect", func(t *testing.T) {
		require.True(t, IsLossyWriter(&udpConn{}))
	})
	t.Run("unknown_network_connection", func(t *testing.T) {
		require.False(t, IsLossyWriter(&unknownConn{}))
	})
	t.Run("bytes.Buffer", func(t *testing.T) {
		require.False(t, IsLossyWriter(&bytes.Buffer{}))
	})
}
