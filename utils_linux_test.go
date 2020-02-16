// +build linux

package secureio_test

import (
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func udpSetNoFragment(conn *net.UDPConn) (err error) {
	var syscallConn syscall.RawConn
	syscallConn, err = conn.SyscallConn()
	if err != nil {
		return
	}
	err2 := syscallConn.Control(func(fd uintptr) {
		err = syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
	})
	if err != nil {
		return
	}
	err = err2
	return
}

func testUDPPair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
testUDPPairStart:
	localhost := net.ParseIP("127.0.0.1")

	conn0, err := net.DialUDP(`udp`, &net.UDPAddr{IP: localhost}, &net.UDPAddr{IP: localhost})
	assert.NoError(t, err)
	conn1, err := net.DialUDP(`udp`,
		&net.UDPAddr{IP: localhost, Port: 0},
		&net.UDPAddr{IP: localhost, Port: conn0.LocalAddr().(*net.UDPAddr).Port},
	)
	assert.NoError(t, err)
	err = conn0.Close()
	assert.NoError(t, err)
	conn0, err = net.DialUDP(`udp`,
		&net.UDPAddr{IP: localhost, Port: conn1.RemoteAddr().(*net.UDPAddr).Port},
		&net.UDPAddr{IP: localhost, Port: conn1.LocalAddr().(*net.UDPAddr).Port},
	)
	if err != nil {
		goto testUDPPairStart // somebody already took the address
	}
	assert.NoError(t, err)

	err = udpSetNoFragment(conn0)
	assert.NoError(t, err)
	err = udpSetNoFragment(conn1)
	assert.NoError(t, err)

	writeBuf := []byte("abc123")
	_, err = conn1.Write(writeBuf)
	assert.NoError(t, err)
	_, err = conn0.Write(writeBuf)
	assert.NoError(t, err)
	readBuf := make([]byte, 65536)
	n, err := conn0.Read(readBuf)
	assert.NoError(t, err)
	assert.Equal(t, writeBuf, readBuf[:n])

	return conn0, conn1
}
