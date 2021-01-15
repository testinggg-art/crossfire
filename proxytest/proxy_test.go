package proxytest

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	_ "github.com/jarvisgally/crossfire/proxy/direct"
	"github.com/jarvisgally/crossfire/proxy/socks5"
	_ "github.com/jarvisgally/crossfire/proxy/socks5"
	_ "github.com/jarvisgally/crossfire/proxy/trojan"
	"golang.org/x/net/dns/dnsmessage"
	goProxy "golang.org/x/net/proxy"
)

// Test client <-> server
func TestProxy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socksPort := common.PickPort("tcp", "127.0.0.1")
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	socksUrl := "socks5://" + socksAddr

	trojanPort := common.PickPort("tcp", "127.0.0.1")
	trojanAddr := fmt.Sprintf("127.0.0.1:%d", trojanPort)
	trojanUrl := "trojan://hash1234@" + trojanAddr

	client, err := proxy.NewProxy(ctx, socksUrl, trojanUrl, "") // No routing, all go throw proxy
	common.Must(err)
	err = client.Execute()
	common.Must(err)

	direct := "direct://"
	server, err := proxy.NewProxy(ctx, trojanUrl, direct, "")
	common.Must(err)
	err = server.Execute()
	common.Must(err)

	// HTTP request
	httpTarget := "http://baidu.com"
	dialer, err := goProxy.SOCKS5("tcp", socksAddr, nil, goProxy.Direct)
	common.Must(err)
	// setup a http client
	httpTransport := &http.Transport{}
	httpClient := &http.Client{Transport: httpTransport}
	// set our socks5 as the dialer
	httpTransport.Dial = dialer.Dial
	// create a request
	req, err := http.NewRequest("GET", httpTarget, nil)
	common.Must(err)
	resp, err := httpClient.Do(req)
	common.Must(err)
	defer resp.Body.Close()
	bytes, err := ioutil.ReadAll(resp.Body)
	common.Must(err)
	body := string(bytes)
	log.Printf("Got response from %v: \n%v", httpTarget, body)
	if !strings.HasPrefix(body, "<html>") {
		t.Fail()
	}

	// DNS request
	dnsTarget, err := proxy.NewTarget("114.114.114.114:53", "udp")
	common.Must(err)
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
	udpAddr, err := net.ResolveUDPAddr("udp", socksAddr)
	common.Must(err)

	// Connect to socks5 by udp
	zeroAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	udpClient, err := net.ListenUDP("udp", zeroAddr)
	common.Must(err)
	prc := &socks5.PacketConn{UDPConn: udpClient}
	defer prc.Close()
	prc.WriteWithTarget(buf, udpAddr, dnsTarget)
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
