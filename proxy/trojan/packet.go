package trojan

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy/socks5"
)

type PktConn struct {
	// TCP connection for UDP ASSOCIATE
	net.Conn

	// Target address
	target string
}

// NewPktConn returns a PktConn.
func NewPktConn(c net.Conn, target string) *PktConn {
	pc := &PktConn{
		Conn:   c,
		target: target,
	}
	return pc
}

// ReadFrom implements the necessary function of net.PacketConn.
func (pc *PktConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// ATYP, DST.ADDR, DST.PORT
	_, _, err := socks5.ReadTargetAddr(pc.Conn)
	if err != nil {
		return 0, nil, err
	}

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

	// TODO: check the addr in return value, it's a fake packetConn so the addr is not valid
	return n, nil, err
}

// WriteTo implements the necessary function of net.PacketConn.
func (pc *PktConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := common.GetWriteBuffer()
	defer common.PutWriteBuffer(buf)

	buf.Write(socks5.ParseAddr(pc.target))
	binary.Write(buf, binary.BigEndian, uint16(len(b)))
	buf.Write(crlf)
	buf.Write(b)
	return pc.Write(buf.Bytes())
}
