package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
)

type PacketConn struct {
	// Connection from client
	net.PacketConn

	// Target address
	targetAddr *proxy.TargetAddr
}

// https://tools.ietf.org/html/rfc1928#section-7

//    Each UDP datagram carries a UDP request header with it:
//
//      +----+------+------+----------+----------+----------+
//      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//      +----+------+------+----------+----------+----------+
//      | 2  |  1   |  1   | Variable |    2     | Variable |
//      +----+------+------+----------+----------+----------+

// ReadFrom overrides the original function from net.PacketConn.
func (pc *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := common.GetBuffer(len(p))
	defer common.PutBuffer(buf)

	n, remoteAddr, err := pc.PacketConn.ReadFrom(buf)
	if err != nil {
		return n, remoteAddr, err
	}
	if n < 3 {
		return n, remoteAddr, errors.New("not enough size to get addr")
	}

	targetAddr, rn, err := ReadTargetAddr(bytes.NewReader(buf[3:]))
	if err != nil {
		return n, remoteAddr, fmt.Errorf("failed to read target address: %v", err)
	}
	pc.targetAddr = targetAddr

	copy(p, buf[3+rn:])
	return n, remoteAddr, nil
}

// WriteTo overrides the original function from net.PacketConn.
func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := common.GetWriteBuffer()
	defer common.PutWriteBuffer(buf)

	buf.Write([]byte{0, 0, 0})
	buf.Write(ParseAddr(pc.targetAddr.String()))
	buf.Write(p)

	return pc.PacketConn.WriteTo(buf.Bytes(), addr)
}

func (pc *PacketConn) GetTargetAddr() *proxy.TargetAddr {
	return pc.targetAddr
}
