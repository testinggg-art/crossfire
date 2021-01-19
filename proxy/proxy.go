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
	"sync"
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
	// Handshake with TCP server
	Handshake(underlay net.Conn, target *Target) (StreamConn, error)
	// Pack underlay net.Conn
	Pack(underlay net.Conn) (PacketConn, error)
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
	// Handshake with TCP client
	Handshake(underlay net.Conn) (StreamConn, *Target, error)
	// Pack underlay net.Conn
	Pack(underlay net.Conn) (PacketConn, error)
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
type Target struct {
	Name    string // fully-qualified domain name
	IP      net.IP
	Port    int
	Network string // tcp or udp
}

// Return host:port string
func (a *Target) Addr() string {
	port := strconv.Itoa(a.Port)
	if a.IP == nil {
		return net.JoinHostPort(a.Name, port)
	}
	return net.JoinHostPort(a.IP.String(), port)
}

// Returned host string
func (a *Target) Host() string {
	if a.IP == nil {
		return a.Name
	}
	return a.IP.String()
}

// String
func (a *Target) String() string {
	return a.Addr()
}

func NewTarget(addr, network string) (*Target, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(portStr)

	target := &Target{Port: port, Network: network}
	if ip := net.ParseIP(host); ip != nil {
		target.IP = ip
	} else {
		target.Name = host
	}
	return target, nil
}

// StreamConn for tcp relay
type StreamConn interface {
	net.Conn
}

// PacketConn for udp relay
type PacketConn interface {
	ReadWithTarget(p []byte) (n int, addr net.Addr, target *Target, err error)
	WriteWithTarget(p []byte, addr net.Addr, target *Target) (n int, err error)
	io.Closer
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
	// Tcp
	listener, err := net.Listen("tcp", p.localServer.Addr())
	if err != nil {
		return fmt.Errorf("can not listen tcp on %v: %v", p.localServer.Addr(), err)
	}
	log.Printf("listening tcp on %v", p.localServer.Addr())
	go p.tcpLoop(listener)
	// Udp listening only for socks5
	if p.localServer.Name() == "socks5" {
		udpAddr, err := net.ResolveUDPAddr("udp", p.localServer.Addr())
		if err != nil {
			return fmt.Errorf("can not resolve udp address %s: %v", p.localServer.Addr(), err)
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return fmt.Errorf("can not listen udp on %v: %v", p.localServer.Addr(), err)
		}
		log.Printf("listening udp on %v", p.localServer.Addr())
		go p.udpLoop(udpConn)
	}
	return nil
}

func (p *Proxy) tcpLoop(listener net.Listener) {
	for {
		lc, err := listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				//
			}
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
			// Handshake with raw net.Conn from client and return a connection with protocol support
			wlc, target, err := p.localServer.Handshake(lc)
			if err != nil {
				lc.Close()
				log.Printf("failed in handshake from %v: %v", p.localServer.Addr(), err)
				return
			}
			// Routing logic
			client := p.pickClient(target)
			dialAddr := p.remoteClient.Addr()
			if client.Name() == "direct" {
				dialAddr = target.Addr()
			}
			if target.Network == "tcp" { // TCP
				defer wlc.Close()
				wrc, err := p.Handshake(client, dialAddr, target)
				if err != nil {
					return
				}
				defer wrc.Close()
				//
				go io.Copy(wrc, wlc)
				io.Copy(wlc, wrc)
			} else if target.Network == "udp" { // UDP
				plc, err := p.localServer.Pack(wlc)
				if err != nil {
					wlc.Close()
					log.Printf("failed in pack: %v", err)
					return
				}
				defer plc.Close()
				prc, err := p.Pack(client, dialAddr, target)
				if err != nil {
					return
				}
				defer prc.Close()
				//
				errChan := make(chan error, 2)
				relayPacket := func(left, right PacketConn) {
					for {
						buf := make([]byte, common.MaxPacketSize)
						n, _, _, err := right.ReadWithTarget(buf)
						if err != nil {
							errChan <- err
							return
						}
						if n == 0 {
							errChan <- nil
							return
						}
						n, err = left.WriteWithTarget(buf[:n], nil, target)
						if err != nil {
							errChan <- err
							return
						}
					}
				}
				go relayPacket(prc, plc)
				go relayPacket(plc, prc)
				select {
				case err = <-errChan:
					if err != nil {
						log.Printf("failed in relay: %v", err)
					}
				case <-p.ctx.Done():
					log.Printf("shutting down packet relay")
				}

			} else {
				log.Printf("unsupported target network %v", target.Network)
				return
			}
		}()
	}
}

// Routing logic
func (p *Proxy) pickClient(target *Target) Client {
	var client Client
	if p.route == whitelist {
		if p.matcher.Check(target.Host()) {
			client = p.directClient
		} else {
			client = p.remoteClient
		}
	} else if p.route == blacklist {
		if p.matcher.Check(target.Host()) {
			client = p.remoteClient
		} else {
			client = p.directClient
		}
	} else {
		client = p.remoteClient
	}
	log.Printf("%v-%v to %v", client.Name(), target.Network, target)
	return client
}

// Common logic for a client to get tcp connection for dailAddr
func (p *Proxy) Handshake(client Client, dialAddr string, target *Target) (StreamConn, error) {
	rc, err := net.Dial("tcp", dialAddr)
	if err != nil {
		log.Printf("failed to dail to %v: %v", dialAddr, err)
		return nil, err
	}
	// Read timeout
	rc.SetReadDeadline(time.Now().Add(time.Second * 10))
	// Handshake with raw net.Conn of remote server and return a connection with protocol support
	wrc, err := client.Handshake(rc, target)
	if err != nil {
		rc.Close()
		log.Printf("failed in handshake to %v: %v", dialAddr, err)
		return nil, err
	}
	return wrc, nil
}

// Common logic for a client to get udp connection for dailAddr, the connection can be udpConn or TcpConn
func (p *Proxy) Pack(client Client, dialAddr string, target *Target) (PacketConn, error) {
	var rc net.Conn
	var err error
	if client.Name() == "direct" { // UDP directly
		zeroAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		rc, err = net.ListenUDP("udp", zeroAddr)
		if err != nil {
			log.Printf("failed to init udpConn for remote %v: %v", dialAddr, err)
			return nil, err
		}
	} else { // UDP over TCP
		rc0, err := net.Dial("tcp", dialAddr)
		if err != nil {
			log.Printf("failed to dail tcp to %v: %v", dialAddr, err)
			return nil, err
		}
		rc, err = client.Handshake(rc0, target)
		if err != nil {
			rc0.Close()
			log.Printf("failed in handshake to %v: %v", dialAddr, err)
			return nil, err
		}
	}
	// Read timeout
	rc.SetReadDeadline(time.Now().Add(2 * time.Minute))
	// Parse outgoing packet and return a packet with protocol support
	prc, err := client.Pack(rc)
	if err != nil {
		rc.Close()
		log.Printf("failed to pack: %v", err)
		return nil, err
	}
	return prc, nil
}

func (p *Proxy) udpLoop(lc *net.UDPConn) {
	plc, err := p.localServer.Pack(lc)
	if err != nil {
		lc.Close()
		log.Printf("failed in pack: %v", err)
		return
	}
	defer plc.Close()
	//
	var nm sync.Map
	packetBuf := make([]byte, common.MaxPacketSize)
	for {
		n, localAddr, target, err := plc.ReadWithTarget(packetBuf) // 1. Read from local client
		if err != nil {
			log.Printf("failed in read udp: %v", err)
			continue
		}
		// Routing logic
		client := p.pickClient(target)
		dialAddr := p.remoteClient.Addr()
		if client.Name() == "direct" {
			dialAddr = target.Addr()
		}
		dailUdpAddr, err := net.ResolveUDPAddr("udp", dialAddr)
		if err != nil {
			log.Printf("failed to parse dail udp addr: %v", err)
			continue
		}

		var prc PacketConn
		// Key for reusing connection
		key := fmt.Sprintf("%v-%v", localAddr, dialAddr)
		// TODO: Use channel to limit active connections
		v, ok := nm.Load(key)
		if !ok && v == nil {
			prc, err = p.Pack(client, dialAddr, target)
			if err != nil {
				continue
			}
			nm.Store(key, prc)
			// Traffic forwarding
			go func() {
				b := common.GetBuffer(common.MaxPacketSize)
				defer common.PutBuffer(b)
				for {
					n, _, _, err := prc.ReadWithTarget(b) // 3. Read from remote server
					if err != nil {
						return
					}
					_, err = plc.WriteWithTarget(b[:n], localAddr, target) // 4. Write to local client
					if err != nil {
						return
					}
				}
				prc.Close()
				nm.Delete(key)
			}()
		} else {
			prc = v.(PacketConn)
		}
		_, err = prc.WriteWithTarget(packetBuf[:n], dailUdpAddr, target) // 2.Write to remote server
		if err != nil {
			log.Printf("failed in write udp to remote: %v", err)
			continue
		}
	}
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
	proxy.directClient, err = ClientFromURL(ctx, "direct://")
	if err != nil {
		return nil, fmt.Errorf("can not create direct client: %v", err)
	}
	proxy.route = route
	proxy.matcher = common.NewMather(route)

	return proxy, nil
}
