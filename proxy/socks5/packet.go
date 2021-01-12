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
	*net.UDPConn
}

// https://tools.ietf.org/html/rfc1928#section-7

//    Each UDP datagram carries a UDP request header with it:
//
//      +----+------+------+----------+----------+----------+
//      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//      +----+------+------+----------+----------+----------+
//      | 2  |  1   |  1   | Variable |    2     | Variable |
//      +----+------+------+----------+----------+----------+

func (pc *PacketConn) ReadWithTarget(p []byte) (int, net.Addr, *proxy.Target, error) {
	buf := common.GetBuffer(len(p))
	defer common.PutBuffer(buf)

	n, remoteAddr, err := pc.UDPConn.ReadFrom(buf)
	if err != nil {
		return n, remoteAddr, nil, err
	}
	if n < 3 {
		return n, remoteAddr, nil, errors.New("not enough size to get addr")
	}

	target, rn, err := ReadTarget(bytes.NewReader(buf[3:]))
	if err != nil {
		return n, remoteAddr, target, fmt.Errorf("failed to read target address: %v", err)
	}

	copy(p, buf[3+rn:])
	return n - 3 - rn, remoteAddr, target, nil
}

func (pc *PacketConn) WriteWithTarget(p []byte, addr net.Addr, target *proxy.Target) (n int, err error) {
	buf := common.GetWriteBuffer()
	defer common.PutWriteBuffer(buf)

	buf.Write([]byte{0, 0, 0})
	buf.Write(ParseAddr(target.Addr()))
	buf.Write(p)

	return pc.UDPConn.WriteTo(buf.Bytes(), addr)
}
