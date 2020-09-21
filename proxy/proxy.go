package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jarvisgally/crossfire/common"
)

const (
	// whitelist route mode
	whitelist = "whitelist"
	// blacklist route mode
	blacklist = "blacklist"
)

// Client is used to create connection.
type Client interface {
	Name() string
	// Address to dail
	Addr() string
	Handshake(underlay net.Conn, target string) (io.ReadWriteCloser, error)
}

// ClientCreator is a function to create client.
type ClientCreator func(ctx context.Context, url *url.URL) (Client, error)

var (
	clientMap = make(map[string]ClientCreator)
)

// RegisterClient is used to register a client.
func RegisterClient(name string, c ClientCreator) {
	clientMap[name] = c
}

// ClientFromURL calls the registered creator to create client.
// dialer is the default upstream dialer so cannot be nil, we can use Default when calling this function.
func ClientFromURL(ctx context.Context, s string) (Client, error) {
	u, err := url.Parse(s)
	if err != nil {
		log.Printf("can not parse client url %s err: %s", s, err)
		return nil, err
	}

	c, ok := clientMap[strings.ToLower(u.Scheme)]
	if ok {
		return c(ctx, u)
	}

	return nil, errors.New("unknown client scheme '" + u.Scheme + "'")
}

// Server interface
type Server interface {
	Name() string
	// Address to listen
	Addr() string
	Handshake(underlay net.Conn) (io.ReadWriteCloser, *TargetAddr, error)
}

// ServerCreator is a function to create proxy server
type ServerCreator func(ctx context.Context, url *url.URL) (Server, error)

var (
	serverMap = make(map[string]ServerCreator)
)

// RegisterServer is used to register a proxy server
func RegisterServer(name string, c ServerCreator) {
	serverMap[name] = c
}

// ServerFromURL calls the registered creator to create proxy servers
// dialer is the default upstream dialer so cannot be nil, we can use Default when calling this function
func ServerFromURL(ctx context.Context, s string) (Server, error) {
	u, err := url.Parse(s)
	if err != nil {
		log.Printf("can not parse server url %s err: %s", s, err)
		return nil, err
	}

	c, ok := serverMap[strings.ToLower(u.Scheme)]
	if ok {
		return c(ctx, u)
	}

	return nil, errors.New("unknown server scheme '" + u.Scheme + "'")
}

// An Addr represents a address that you want to access by proxy. Either Name or IP is used exclusively.
type TargetAddr struct {
	Name string // fully-qualified domain name
	IP   net.IP
	Port int
}

// Return host:port string
func (a *TargetAddr) String() string {
	port := strconv.Itoa(a.Port)
	if a.IP == nil {
		return net.JoinHostPort(a.Name, port)
	}
	return net.JoinHostPort(a.IP.String(), port)
}

// Returned host string
func (a *TargetAddr) Host() string {
	if a.IP == nil {
		return a.Name
	}
	return a.IP.String()
}

func NewTargetAddr(addr string) (*TargetAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(portStr)

	target := &TargetAddr{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		target.IP = ip
	} else {
		target.Name = host
	}
	return target, nil
}

// Proxy
type Proxy struct {
	localServer                Server
	remoteClient, directClient Client
	route                      string
	matcher                    *common.Matcher

	ctx    context.Context
	cancel context.CancelFunc
}

func (p *Proxy) Execute() error {
	listener, err := net.Listen("tcp", p.localServer.Addr())
	if err != nil {
		return fmt.Errorf("can not listen tcp on %v: %v", p.localServer.Addr(), err)
	}
	go p.tcpLoop(listener)
	return nil
}

func (p *Proxy) tcpLoop(listener net.Listener) {
	for {
		lc, err := listener.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			log.Printf("failed to accepted connection: %v", err)
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}
		go func() {
			var client Client

			// 不同的服务端协议各自实现自己的响应逻辑, 其中返回的地址则用于匹配路由
			// 常常需要额外编解码或者流量统计的功能，故需要给lc包一层以实现这些逻辑，即wlc
			wlc, targetAddr, err := p.localServer.Handshake(lc)
			if err != nil {
				lc.Close()
				log.Printf("failed in handshake from %v: %v", p.localServer.Addr(), err)
				return
			}
			defer wlc.Close()

			// 匹配路由
			if p.route == whitelist { // 白名单模式，如果匹配，则直接访问，否则使用代理访问
				if p.matcher.Check(targetAddr.Host()) {
					client = p.directClient
				} else {
					client = p.remoteClient
				}
			} else if p.route == blacklist { // 黑名单模式，如果匹配，则使用代理访问，否则直接访问
				if p.matcher.Check(targetAddr.Host()) {
					client = p.remoteClient
				} else {
					client = p.directClient
				}
			} else { // 全部流量使用代理访问
				client = p.remoteClient
			}
			log.Printf("%v to %v", client.Name(), targetAddr)

			// 连接远端地址
			dialAddr := p.remoteClient.Addr()
			if _, ok := client.(*Direct); ok { // 直接访问则直接连接目标地址
				dialAddr = targetAddr.String()
			}
			rc, err := net.Dial("tcp", dialAddr)
			if err != nil {
				log.Printf("failed to dail to %v: %v", dialAddr, err)
				return
			}

			// 不同的客户端协议各自实现自己的请求逻辑
			wrc, err := client.Handshake(rc, targetAddr.String())
			if err != nil {
				rc.Close()
				log.Printf("failed in handshake to %v: %v", dialAddr, err)
				return
			}
			defer wrc.Close()

			// 流量转发
			go io.Copy(wrc, wlc)
			io.Copy(wlc, wrc)
		}()
	}
}

func (p *Proxy) udpLoop() {
	//
}

func NewProxy(ctx context.Context, local, remote, route string) (*Proxy, error) {
	ctx, cancel := context.WithCancel(ctx)
	proxy := &Proxy{
		ctx:    ctx,
		cancel: cancel,
	}

	var err error
	proxy.localServer, err = ServerFromURL(ctx, local)
	if err != nil {
		return nil, fmt.Errorf("can not create local server: %v", err)
	}
	proxy.remoteClient, err = ClientFromURL(ctx, remote)
	if err != nil {
		return nil, fmt.Errorf("can not create remote client: %v", err)
	}
	proxy.directClient, _ = ClientFromURL(ctx, "direct://")
	proxy.route = route
	proxy.matcher = common.NewMather(route)

	return proxy, nil
}
