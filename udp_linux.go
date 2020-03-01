// +build linux

package secureio

import (
	"net"
	"syscall"
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
