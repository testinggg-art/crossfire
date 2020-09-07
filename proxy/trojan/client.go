package trojan

import (
	"context"
	"io"
	"log"
	"net"
	"net/url"

	"github.com/jarvisgally/crossfire/api"
	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	"github.com/jarvisgally/crossfire/proxy/socks5"
)

func init() {
	proxy.RegisterClient(Name, NewTrojanClient)
}

func NewTrojanClient(ctx context.Context, url *url.URL) (proxy.Client, error) {
	addr := url.Host
	user := NewUser(ctx, url.User.Username())
	query := url.Query()

	// Create client
	c := &Client{addr: addr, user: user}

	// Run API service
	apiListenAddr := query.Get("api")
	if apiListenAddr != "" {
		go api.RunClientAPI(ctx, user, apiListenAddr)
	}
	return c, nil
}

// Client is a vmess client
type Client struct {
	addr string
	user *User
}

func (c *Client) Name() string { return Name }

func (c *Client) Addr() string { return c.addr }

func (c *Client) Handshake(underlay net.Conn, target string) (io.ReadWriteCloser, error) {
	conn := &ClientConn{Conn: underlay, target: target, user: c.user}

	// Request
	err := conn.Request()
	if err != nil {
		return nil, err
	}

	return conn, nil
}

type ClientConn struct {
	target string
	user   *User

	net.Conn
	sent uint64
	recv uint64
}

// Request sends request to server.
// https://trojan-gfw.github.io/trojan/protocol
func (c *ClientConn) Request() error {
	buf := common.GetWriteBuffer()
	defer common.PutWriteBuffer(buf)

	buf.Write([]byte(c.user.Hex))
	buf.Write(crlf)
	buf.WriteByte(socks5.CmdConnect)
	buf.Write(socks5.ParseAddr(c.target))
	buf.Write(crlf)

	n, err := c.Conn.Write(buf.Bytes())
	c.user.AddTraffic(n, 0)
	c.sent += uint64(n)

	return err
}

func (c *ClientConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.user.AddTraffic(n, 0)
	c.sent += uint64(n)
	return n, err
}

func (c *ClientConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.user.AddTraffic(0, n)
	c.recv += uint64(n)
	return n, err
}

func (c *ClientConn) Close() error {
	log.Printf("connection to %v closed, sent: %v, recv: %v", c.target, common.HumanFriendlyTraffic(c.sent), common.HumanFriendlyTraffic(c.recv))
	return c.Conn.Close()
}
