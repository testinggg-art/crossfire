package trojan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"testing"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
)

func TestTrojan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Init server & client
	port := common.PickPort("tcp", "127.0.0.1")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "trojan://hash1234@" + addr
	server, err := proxy.ServerFromURL(ctx, url)
	common.Must(err)
	client, err := proxy.ClientFromURL(ctx, url)
	common.Must(err)

	// Target
	tcpTarget, err := proxy.NewTarget("dummy.com:80", "tcp")
	common.Must(err)
	udpTarget, err := proxy.NewTarget("dummy.com:80", "udp")
	common.Must(err)

	// TCP listener, UDP also through TCP
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
				if target.Addr() != tcpTarget.Addr() {
					t.Fail()
				}
				if target.Network == "tcp" { // TCP
					defer wlc.Close()
					var hello [5]byte
					io.ReadFull(wlc, hello[:])
					if !bytes.Equal(hello[:], []byte("hello")) {
						t.Fail()
					}
					wlc.Write([]byte("world"))
				} else if target.Network == "udp" { // UDP
					plc, err := server.Pack(wlc)
					if err != nil {
						wlc.Close()
						log.Printf("failed in pack: %v", err)
						return
					}
					defer plc.Close()
					packetBuf := make([]byte, common.MaxPacketSize)
					n, _, target, err := plc.ReadWithTarget(packetBuf)
					if err != nil {
						t.Logf("failed in read udp: %v", err)
						return
					}
					if !bytes.Equal(packetBuf[:n], []byte("hello")) {
						t.Fail()
					}
					plc.WriteWithTarget([]byte("world"), nil, target)
				}
			}()
		}
	}()

	// TCP client
	rc, err := net.Dial("tcp", server.Addr())
	common.Must(err)
	wrc, err := client.Handshake(rc, tcpTarget)
	common.Must(err)
	defer wrc.Close()
	wrc.Write([]byte("hello"))
	var world [5]byte
	io.ReadFull(wrc, world[:])
	if !bytes.Equal(world[:], []byte("world")) {
		t.Fail()
	}

	// UDP client through TCP
	rc0, err := net.Dial("tcp", server.Addr())
	common.Must(err)
	rc, err = client.Handshake(rc0, udpTarget)
	common.Must(err)
	prc, err := client.Pack(rc)
	common.Must(err)
	defer prc.Close()
	prc.WriteWithTarget([]byte("hello"), nil, udpTarget)
	recvBuf := common.GetBuffer(common.MaxPacketSize)
	defer common.PutBuffer(recvBuf)
	n, _, _, _ := prc.ReadWithTarget(recvBuf)
	if !bytes.Equal(world[:n], []byte("world")) {
		t.Fail()
	}
}
