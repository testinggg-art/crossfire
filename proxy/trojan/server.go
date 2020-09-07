package trojan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jarvisgally/crossfire/api"
	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	"github.com/jarvisgally/crossfire/proxy/socks5"
	"io"
	"log"
	"net"
	"net/url"
	"time"
)

func init() {
	proxy.RegisterServer(Name, NewTrojanServer)
}

func NewTrojanServer(ctx context.Context, url *url.URL) (proxy.Server, error) {
	addr := url.Host
	userManager := NewUserManager(ctx, url.User.Username())
	query := url.Query()

	s := &Server{addr: addr, userManager: userManager}

	// Run API service
	apiListenAddr := query.Get("api")
	if apiListenAddr != "" {
		go api.RunServerAPI(ctx, s.userManager, apiListenAddr)
	}

	return s, nil
}

type Server struct {
	addr string

	// Provides user/stats control for client
	userManager *UserManager
}

func (s *Server) Name() string { return Name }

func (s *Server) Addr() string { return s.addr }

func (s *Server) Handshake(underlay net.Conn) (io.ReadWriteCloser, *proxy.TargetAddr, error) {
	// Set handshake timeout 3 seconds
	if err := underlay.SetReadDeadline(time.Now().Add(time.Second * 3)); err != nil {
		return nil, nil, err
	}
	defer underlay.SetReadDeadline(time.Time{})

	c := &ServerConn{Conn: underlay}

	rn := 0

	// Auth
	reqHex := common.GetBuffer(56)
	defer common.PutBuffer(reqHex)
	_, err := io.ReadFull(c.Conn, reqHex[:])
	if err != nil {
		return nil, nil, errors.New("failed to read hex")
	}
	rn += 56
	hex := string(reqHex[:])
	user, err := s.userManager.CheckHex(hex)
	if err != nil {
		return nil, nil, err
	}
	c.user = user

	// Check ip limit
	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse host %v: %v", c.Conn.RemoteAddr(), err)
	}
	c.ip = ip
	ok := user.AddIP(ip)
	if !ok {
		return nil, nil, fmt.Errorf("ip limit reached for user %v", user.Hash())
	}

	// CRLF
	reqCrlf := common.GetBuffer(2)
	defer common.PutBuffer(reqCrlf)
	_, err = io.ReadFull(c.Conn, reqCrlf)
	if err != nil {
		return nil, nil, err
	}
	rn += 2

	reqOneByte := common.GetBuffer(1)
	defer common.PutBuffer(reqOneByte)

	// Parse command
	_, err = io.ReadFull(c.Conn, reqOneByte)
	if err != nil {
		return nil, nil, err
	}
	rn += 1

	// Parse address
	addr := &proxy.TargetAddr{}
	_, err = io.ReadFull(c.Conn, reqOneByte)
	if err != nil {
		return nil, nil, err
	}
	rn += 1

	l := 0
	switch reqOneByte[0] {
	case socks5.ATypIP4:
		l = net.IPv4len
		addr.IP = make(net.IP, net.IPv4len)
	case socks5.ATypDomain:
		// 解码域名的长度
		_, err = io.ReadFull(c.Conn, reqOneByte)
		if err != nil {
			return nil, nil, err
		}
		rn += 1
		l = int(reqOneByte[0])
	case socks5.ATypIP6:
		l = net.IPv6len
		addr.IP = make(net.IP, net.IPv6len)
	default:
		return nil, nil, fmt.Errorf("unknown address type %v", reqOneByte[0])
	}

	reqAddr := common.GetBuffer(l + 2)
	defer common.PutBuffer(reqAddr)
	_, err = io.ReadFull(c.Conn, reqAddr)
	if err != nil {
		return nil, nil, err
	}
	rn += l + 2
	if addr.IP != nil {
		copy(addr.IP, reqAddr[:l])
	} else {
		addr.Name = string(reqAddr[:l])
	}
	addr.Port = int(binary.BigEndian.Uint16(reqAddr[l : l+2]))
	c.target = addr.String()

	// CRLF
	_, err = io.ReadFull(c.Conn, reqCrlf)
	if err != nil {
		return nil, nil, err
	}
	rn += 2

	c.sent += uint64(rn)
	c.user.AddTraffic(rn, 0)

	return c, addr, nil
}

// ServerConn wrapper a net.Conn with trojan protocol
type ServerConn struct {
	net.Conn
	sent uint64
	recv uint64
	ip   string

	target string
	user   proxy.User
}

func (c *ServerConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.sent += uint64(n)
	c.user.AddTraffic(n, 0)
	return n, err
}

func (c *ServerConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.recv += uint64(n)
	c.user.AddTraffic(0, n)
	return n, err
}

func (c *ServerConn) Close() error {
	log.Printf("user %v from %v tunneling to %v closed, sent: %v, recv: %v", c.user.Hash(), c.Conn.RemoteAddr(), c.target, common.HumanFriendlyTraffic(c.sent), common.HumanFriendlyTraffic(c.recv))
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}
