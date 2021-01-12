package socks5

import (
	"bytes"
	"context"
	"fmt"
	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	golang_proxy "golang.org/x/net/proxy"
	"io"
	"net"
	"testing"
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
	client, err := golang_proxy.SOCKS5("tcp", addr, nil, golang_proxy.Direct)
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
	prc.WriteWithTarget([]byte("hello"), udpAddr, theTarget)
	recvBuf := common.GetBuffer(common.MaxPacketSize)
	defer common.PutBuffer(recvBuf)
	n, _, _, _ := prc.ReadWithTarget(recvBuf)
	if !bytes.Equal(world[:n], []byte("world")) {
		t.Fail()
	}
}
