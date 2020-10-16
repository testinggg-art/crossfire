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

func (d *Direct) Handshake(underlay net.Conn, target string) (proxy.StreamConn, error) {
	return underlay, nil
}

func (d *Direct) Pack(underlay net.Conn) (proxy.PacketConn, error) {
	return &PacketConn{
		underlay.(net.PacketConn),
	}, nil
}

type PacketConn struct {
	net.PacketConn
}

func (pc *PacketConn) GetTargetAddr() *proxy.TargetAddr {
	return nil
}
