package socks5

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"io"
	"net"
	"strings"
	"testing"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	"golang.org/x/net/dns/dnsmessage"
	goProxy "golang.org/x/net/proxy"
)

func TestSocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Init server
	port := common.PickPort("tcp", "127.0.0.1")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "socks5://" + addr
	server, err := proxy.ServerFromURL(ctx, url)
	common.Must(err)

	// Target
	theTarget, err := proxy.NewTarget("dummy.com:80", "tcp")
	common.Must(err)

	// TCP listener
	listener, err := net.Listen("tcp", server.Addr())
	common.Must(err)
	go func() {
		for {
			lc, err := listener.Accept()
			common.Must(err)
			go func() {
				wlc, target, err := server.Handshake(lc)
				if err != nil {
					lc.Close()
					t.Logf("failed in handshake form %v: %v", server.Addr(), err)
					return
				}
				defer wlc.Close()
				if target.Addr() != theTarget.Addr() {
					t.Fail()
				}
				var hello [5]byte
				io.ReadFull(wlc, hello[:])
				if !bytes.Equal(hello[:], []byte("hello")) {
					t.Fail()
				}
				wlc.Write([]byte("world"))
			}()
		}
	}()

	// TCP client
	client, err := goProxy.SOCKS5("tcp", addr, nil, goProxy.Direct)
	common.Must(err)
	rc, err := client.Dial("tcp", theTarget.String())
	common.Must(err)
	rc.Write([]byte("hello"))
	var world [5]byte
	io.ReadFull(rc, world[:])
	if !bytes.Equal(world[:], []byte("world")) {
		t.Fail()
	}

	// UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", server.Addr())
	common.Must(err)
	udpListener, err := net.ListenUDP("udp", udpAddr)
	common.Must(err)
	go func(lc *net.UDPConn) {
		// Parse incoming packet and return a packet with protocol support
		plc, err := server.Pack(lc)
		if err != nil {
			lc.Close()
			t.Logf("failed in pack: %v", err)
			return
		}
		defer plc.Close()
		packetBuf := make([]byte, common.MaxPacketSize)
		for {
			n, remote, target, err := plc.ReadWithTarget(packetBuf)
			if err != nil {
				t.Logf("failed in read udp: %v", err)
				continue
			}
			if target.Addr() != theTarget.Addr() {
				t.Fail()
			}
			if !bytes.Equal(packetBuf[:n], []byte("hello")) {
				t.Fail()
			}
			plc.WriteWithTarget([]byte("world"), remote, target)
		}
	}(udpListener)

	// UDP client
	zeroAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	udpClient, err := net.ListenUDP("udp", zeroAddr)
	common.Must(err)
	prc := &PacketConn{udpClient}
	defer prc.Close()
	prc.WriteWithTarget([]byte("hello"), udpAddr, theTarget)
	recvBuf := common.GetBuffer(common.MaxPacketSize)
	defer common.PutBuffer(recvBuf)
	n, _, _, _ := prc.ReadWithTarget(recvBuf)
	if !bytes.Equal(recvBuf[:n], []byte("world")) {
		t.Fail()
	}
}

func TestDnsRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Init server
	port := common.PickPort("tcp", "127.0.0.1")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "socks5://" + addr
	server, err := proxy.ServerFromURL(ctx, url)
	common.Must(err)

	// Target, a public resolver
	theTarget, err := proxy.NewTarget("114.114.114.114:53", "udp")
	common.Must(err)

	// Create DNS message
	wantName := "baidu.com."
	msg := dnsmessage.Message{
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(wantName),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	buf, err := msg.Pack()
	common.Must(err)

	// UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", server.Addr())
	common.Must(err)
	udpListener, err := net.ListenUDP("udp", udpAddr)
	common.Must(err)
	go func(lc *net.UDPConn) {
		// Parse incoming packet and return a packet with protocol support
		plc, err := server.Pack(lc)
		if err != nil {
			lc.Close()
			t.Logf("failed in pack: %v", err)
			return
		}
		defer plc.Close()
		packetBuf := common.GetBuffer(common.MaxPacketSize)
		defer common.PutBuffer(packetBuf)
		for {
			n, remote, target, err := plc.ReadWithTarget(packetBuf)
			if err != nil {
				t.Logf("failed in read udp: %v", err)
				continue
			}
			if target.Addr() != theTarget.Addr() {
				t.Fail()
			}

			// Forward dns request to resolver
			zeroAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
			rc, err := net.ListenUDP("udp", zeroAddr)
			resolver, err := net.ResolveUDPAddr("udp", target.Addr())
			common.Must(err)
			_, err = rc.WriteToUDP(packetBuf[:n], resolver)

			// Got response from resolver
			common.Must(err)
			n, _, err = rc.ReadFromUDP(packetBuf)
			common.Must(err)

			// Back response
			plc.WriteWithTarget(packetBuf[:n], remote, theTarget)

			// Close
			rc.Close()
		}
	}(udpListener)

	// Udp Client
	zeroAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	udpClient, err := net.ListenUDP("udp", zeroAddr)
	common.Must(err)
	prc := &PacketConn{udpClient}
	defer prc.Close()
	prc.WriteWithTarget(buf, udpAddr, theTarget)
	recvBuf := common.GetBuffer(common.MaxPacketSize)
	defer common.PutBuffer(recvBuf)
	n, _, _, err := prc.ReadWithTarget(recvBuf)
	common.Must(err)
	var response dnsmessage.Message
	err = response.Unpack(recvBuf[:n])
	common.Must(err)
	var gotIPs []net.IP
	for _, n := range response.Answers {
		h := n.Header
		if (h.Type != dnsmessage.TypeA && h.Type != dnsmessage.TypeAAAA) || h.Class != dnsmessage.ClassINET {
			continue
		}
		if !strings.EqualFold(h.Name.String(), wantName) {
			continue
		}
		switch h.Type {
		case dnsmessage.TypeA: // IPv4
			r, _ := n.Body.(*dnsmessage.AResource)
			gotIPs = append(gotIPs, r.A[:])
		case dnsmessage.TypeAAAA: // IPv6
			r, _ := n.Body.(*dnsmessage.AAAAResource)
			gotIPs = append(gotIPs, r.AAAA[:])
		}
	}
	// log.Printf("Found A/AAAA records for name %s: %v\n", wantName, gotIPs)
	if len(gotIPs) == 0 {
		t.Fail()
	}
}

// Send dns request to a running socks5 server
func TriggerDnsRequestToRemoteServer(t *testing.T) {
	// Target, a public resolver
	theTarget, err := proxy.NewTarget("8.8.8.8:53", "udp")
	common.Must(err)

	// Create DNS message
	wantName := "baidu.com."
	msg := dnsmessage.Message{
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(wantName),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	buf, err := msg.Pack()
	common.Must(err)

	// Connect to a running socks5 server
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:1081")
	common.Must(err)

	// Udp Client
	zeroAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	udpClient, err := net.ListenUDP("udp", zeroAddr)
	common.Must(err)
	prc := &PacketConn{udpClient}
	defer prc.Close()
	prc.WriteWithTarget(buf, udpAddr, theTarget)
	recvBuf := common.GetBuffer(common.MaxPacketSize)
	defer common.PutBuffer(recvBuf)
	n, _, _, err := prc.ReadWithTarget(recvBuf)
	common.Must(err)
	var response dnsmessage.Message
	err = response.Unpack(recvBuf[:n])
	common.Must(err)
	log.Printf("got response %v", response)
	var gotIPs []net.IP
	for _, n := range response.Answers {
		h := n.Header
		if (h.Type != dnsmessage.TypeA && h.Type != dnsmessage.TypeAAAA) || h.Class != dnsmessage.ClassINET {
			continue
		}
		if !strings.EqualFold(h.Name.String(), wantName) {
			continue
		}
		switch h.Type {
		case dnsmessage.TypeA: // IPv4
			r, _ := n.Body.(*dnsmessage.AResource)
			gotIPs = append(gotIPs, r.A[:])
		case dnsmessage.TypeAAAA: // IPv6
			r, _ := n.Body.(*dnsmessage.AAAAResource)
			gotIPs = append(gotIPs, r.AAAA[:])
		}
	}
	log.Printf("Found A/AAAA records for name %s: %v\n", wantName, gotIPs)
	if len(gotIPs) == 0 {
		t.Fail()
	}
}
