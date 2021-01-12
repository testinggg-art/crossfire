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
	net.Conn
}

// https://trojan-gfw.github.io/trojan/protocol

//    Each UDP packet has the following format:
//
//      +------+----------+----------+--------+---------+----------+
//	    | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
//      +------+----------+----------+--------+---------+----------+
//      |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
//      +------+----------+----------+--------+---------+----------+

func (pc *PacketConn) ReadWithTarget(p []byte) (int, net.Addr, *proxy.Target, error) {
	// Address
	target, _, err := socks5.ReadTarget(pc.Conn)
	if err != nil {
		return 0, nil, nil, err
	}

	// Length
	if _, err = io.ReadFull(pc.Conn, p[:2]); err != nil {
		return 0, nil, target, err
	}

	length := int(binary.BigEndian.Uint16(p[:2]))
	if length > common.MaxPacketSize {
		return 0, nil, target, errors.New("packet invalid")
	}

	// CRLF
	if _, err = io.ReadFull(pc.Conn, p[:2]); err != nil {
		return 0, nil, target, err
	}

	// Payload
	n, err := io.ReadFull(pc.Conn, p[:length])
	if err != nil {
		return 0, nil, target, err
	}

	return n, nil, target, err
}

func (pc *PacketConn) WriteWithTarget(p []byte, addr net.Addr, target *proxy.Target) (n int, err error) {
	buf := common.GetWriteBuffer()
	defer common.PutWriteBuffer(buf)

	buf.Write(socks5.ParseAddr(target.Addr()))
	binary.Write(buf, binary.BigEndian, uint16(len(p)))
	buf.Write(crlf)
	buf.Write(p)

	return pc.Write(buf.Bytes())
}
