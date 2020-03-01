// +build !linux

package secureio

func udpSetNoFragment(conn *net.UDPConn) (err error) {
	return nil
}
