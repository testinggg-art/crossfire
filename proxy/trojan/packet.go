package trojan

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	"github.com/jarvisgally/crossfire/proxy/socks5"
)

type PacketConn struct {
	// UDP over TCP
	net.Conn

	// Target address
	targetAddr *proxy.TargetAddr
}

// https://trojan-gfw.github.io/trojan/protocol

//    Each UDP packet has the following format:
//
//      +------+----------+----------+--------+---------+----------+
//	    | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
//      +------+----------+----------+--------+---------+----------+
//      |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
//      +------+----------+----------+--------+---------+----------+

// ReadFrom overrides the original function from net.PacketConn.
func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Address
	targetAddr, _, err := socks5.ReadTargetAddr(pc.Conn)
	if err != nil {
		return 0, nil, err
	}
	pc.targetAddr = targetAddr

	// Length
	if _, err = io.ReadFull(pc.Conn, b[:2]); err != nil {
		return 0, nil, err
	}

	length := int(binary.BigEndian.Uint16(b[:2]))
	if length > common.UDPBufSize {
		return 0, nil, errors.New("packet invalid")
	}

	// CRLF
	if _, err = io.ReadFull(pc.Conn, b[:2]); err != nil {
		return 0, nil, err
	}

	// Payload
	n, err := io.ReadFull(pc.Conn, b[:length])
	if err != nil {
		return 0, nil, err
	}

	return n, nil, err
}

// WriteTo overrides the original function from net.PacketConn.
func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := common.GetWriteBuffer()
	defer common.PutWriteBuffer(buf)

	buf.Write(socks5.ParseAddr(pc.targetAddr.String()))
	binary.Write(buf, binary.BigEndian, uint16(len(b)))
	buf.Write(crlf)
	buf.Write(b)

	return pc.Write(buf.Bytes())
}

func (pc *PacketConn) GetTargetAddr() *proxy.TargetAddr {
	return pc.targetAddr
}
