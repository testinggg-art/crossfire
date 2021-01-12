package vmess

import (
	"bytes"
	"context"
	"fmt"
	"github.com/jarvisgally/crossfire/common"
	"io"
	"log"
	"net"
	"testing"

	"github.com/jarvisgally/crossfire/proxy"
)

func TestVMess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	port := common.PickPort("tcp", "127.0.0.1")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "vmess://a684455c-b14f-11ea-bf0d-42010aaa0003:4@" + addr
	server, err := proxy.ServerFromURL(ctx, url)
	common.Must(err)
	client, err := proxy.ClientFromURL(ctx, url)
	common.Must(err)

	theTarget, err := proxy.NewTarget("dummy.com:80", "tcp")
	common.Must(err)

	listener, err := net.Listen("tcp", server.Addr())
	common.Must(err)
	go func() {
		for {
			lc, err := listener.Accept()
			common.Must(err)
			go func() {
				defer lc.Close()
				wlc, targetAddr, err := server.Handshake(lc)
				if err != nil {
					t.Logf("failed in handshake form %v: %v", server.Addr(), err)
					return
				}

				if targetAddr.Addr() != theTarget.Addr() {
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

	rc, _ := net.Dial("tcp", server.Addr())
	defer rc.Close()

	wrc, err := client.Handshake(rc, theTarget)
	if err != nil {
		log.Printf("failed in handshake to %v: %v", server.Addr(), err)
		return
	}
	wrc.Write([]byte("hello"))

	var world [5]byte
	io.ReadFull(wrc, world[:])
	if !bytes.Equal(world[:], []byte("world")) {
		t.Fail()
	}
}
