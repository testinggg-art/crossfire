package tls

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"net/url"
	"strings"

	"github.com/jarvisgally/crossfire/proxy"
)

func init() {
	proxy.RegisterClient("vmesss", NewTlsClient)
	proxy.RegisterClient("trojans", NewTlsClient)
}

func NewTlsClient(ctx context.Context, url *url.URL) (proxy.Client, error) {
	addr := url.Host
	sni, _, _ := net.SplitHostPort(addr)

	c := &Client{name: url.Scheme, addr: addr}
	c.tlsConfig = &stdtls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	}

	url.Scheme = strings.TrimSuffix(url.Scheme, "s")
	c.inner, _ = proxy.ClientFromURL(ctx, url.String())

	return c, nil
}

type Client struct {
	name      string
	addr      string
	tlsConfig *stdtls.Config

	inner proxy.Client
}

func (c *Client) Name() string { return c.name }

func (c *Client) Addr() string { return c.addr }

func (c *Client) Handshake(underlay net.Conn, target *proxy.Target) (proxy.StreamConn, error) {
	c0 := stdtls.Client(underlay, c.tlsConfig)
	err := c0.Handshake()
	if err != nil {
		return nil, err
	}

	return c.inner.Handshake(c0, target)
}

func (c *Client) Pack(underlay net.Conn) (proxy.PacketConn, error) {
	return c.inner.Pack(underlay)
}
