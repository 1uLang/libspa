package spa

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	ErrBadIP = errors.New("bad ip address")
)

// Returns if the specified byte is present in the byte slice.
func byteInSlice(elm byte, slice []byte) bool {
	return bytes.IndexByte(slice, elm) >= 0
}

// Returns if the ip parameter string is an IPv6 address. In case there is no error, false signifies that it is an
// IPv4 address and true signifies that is is an IPv6 address.
func isIPv6(ip string) (bool, error) {
	clientIPTmp := net.ParseIP(ip)

	if clientIPTmp == nil {
		return false, ErrBadIP
	}

	clientIP := clientIPTmp.To4()

	if clientIP == nil {
		return true, nil // IP is IPv6
	}

	return false, nil // IP is IPv4
}

func PrintHex(bytes []byte) {
	fmt.Printf("[ ")
	for k, v := range bytes {
		fmt.Printf("%0x ", v)
		if (k+1)%16 == 0 {
			fmt.Println()
		}
	}
	fmt.Printf("]%d\n", len(bytes))
}

func GetIP(host string) string {
	pi := strings.LastIndex(host, ":")
	if pi > 0 {
		return host[:pi]
	}
	return ""
}
func CheckPort(port int) bool {
	return port > 0 && port <= 65535
}

func GetPort() (int, error) {

	address, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		return 0, err
	}

	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
