package direct

import (
	"context"
	"github.com/jarvisgally/crossfire/proxy"
	"net"
	"net/url"
)

const name = "direct"

func init() {
	proxy.RegisterClient(name, NewDirectClient)
}

func NewDirectClient(ctx context.Context, url *url.URL) (proxy.Client, error) {
	return &Direct{}, nil
}

type Direct struct{}

func (d *Direct) Name() string { return name }

func (d *Direct) Addr() string { return name }

func (d *Direct) Handshake(underlay net.Conn, target *proxy.Target) (proxy.StreamConn, error) {
	return underlay, nil
}

func (d *Direct) Pack(underlay net.Conn) (proxy.PacketConn, error) {
	return &PacketConn{
		underlay.(*net.UDPConn),
	}, nil
}

type PacketConn struct {
	*net.UDPConn
}

func (pc *PacketConn) ReadWithTarget(p []byte) (int, net.Addr, *proxy.Target, error) {
	n, remoteAddr, err := pc.UDPConn.ReadFrom(p)
	if err != nil {
		return n, remoteAddr, nil, err
	}
	return n, remoteAddr, nil, nil
}

func (pc *PacketConn) WriteWithTarget(p []byte, addr net.Addr, target *proxy.Target) (n int, err error) {
	return pc.UDPConn.WriteTo(p, addr)
}
