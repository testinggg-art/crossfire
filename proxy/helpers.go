package proxy

import (
	"bytes"
	"io"
	"log"
	"net"
	"strings"
	"testing"

	"github.com/jarvisgally/crossfire/common"
	"golang.org/x/net/dns/dnsmessage"
)

// Test send/receive messages between client and server.
func HelloWorldFromClientToServer(t *testing.T, client Client, server Server) {
	// Target
	targetAddr := "youtube.com:80"
	tcpTarget, err := NewTarget(targetAddr, "tcp")
	common.Must(err)
	udpTarget, err := NewTarget(targetAddr, "udp")
	common.Must(err)

	// TCP listener, UDP also through TCP
	listener, err := net.Listen("tcp", server.Addr())
	common.Must(err)
	defer listener.Close()
	go func() {
		for {
			lc, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					break
				}
				continue
			}
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

// Test dns request between client to server
func DnsRequestFromClientToServer(t *testing.T, client Client, server Server) {
	// Target, a public resolver
	theTarget, err := NewTarget("114.114.114.114:53", "udp")
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

	// TCP listener, UDP also through TCP
	listener, err := net.Listen("tcp", server.Addr())
	common.Must(err)
	defer listener.Close()
	go func() {
		for {
			lc, err := listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "closed") {
					break
				}
				continue
			}
			go func() {
				wlc, target, err := server.Handshake(lc)
				if err != nil {
					lc.Close()
					t.Logf("failed in handshake form %v: %v", server.Addr(), err)
					return
				}
				if target.Addr() != theTarget.Addr() {
					t.Fail()
				}
				if target.Network == "tcp" { // TCP
					defer wlc.Close()
					// Dns request, failed if in this logic
					t.Fail()
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
					plc.WriteWithTarget(packetBuf[:n], nil, theTarget)

					// Close
					rc.Close()
				}
			}()
		}
	}()

	// UDP client through TCP
	rc0, err := net.Dial("tcp", server.Addr())
	common.Must(err)
	rc, err := client.Handshake(rc0, theTarget)
	common.Must(err)
	prc, err := client.Pack(rc)
	common.Must(err)
	defer prc.Close()
	prc.WriteWithTarget(buf, nil, theTarget)
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
	log.Printf("Found A/AAAA records for name %s: %v\n", wantName, gotIPs)
	if len(gotIPs) == 0 {
		t.Fail()
	}
}
