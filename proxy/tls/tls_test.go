package tls

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"testing"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	_ "github.com/jarvisgally/crossfire/proxy/trojan"
)

var cert string = `
-----BEGIN CERTIFICATE-----
MIIDZTCCAk0CFFphZh018B5iAD9F5fV4y0AlD0LxMA0GCSqGSIb3DQEBCwUAMG8x
CzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARNYXJzMRMwEQYDVQQHDAppVHJhbnN3YXJw
MRMwEQYDVQQKDAppVHJhbnN3YXJwMRMwEQYDVQQLDAppVHJhbnN3YXJwMRIwEAYD
VQQDDAlsb2NhbGhvc3QwHhcNMjAwMzMxMTAwMDUxWhcNMzAwMzI5MTAwMDUxWjBv
MQswCQYDVQQGEwJVUzENMAsGA1UECAwETWFyczETMBEGA1UEBwwKaVRyYW5zd2Fy
cDETMBEGA1UECgwKaVRyYW5zd2FycDETMBEGA1UECwwKaVRyYW5zd2FycDESMBAG
A1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
ml44fThYMkCcT627o7ibEs7mq2WOhImjDwYijYJ1684BatrCsHJNcw8PJGTuP+tg
GdngmALjA3l+RipjaE/UK4FJrAjruphA/hOCjZfWqk8KBR4qk0OltxCMWJlp/XCM
9ny1ogFdWUlBbqThs4NWSOUESgxf/Be2njeiOrngGR31qxSiLCLBvafIhKqq/4av
Rlx0Ht770uvF97MlAj1ASAvzTZICHAfUZxEdWl0J4MBbG7SNcnMBbyAF+s60eFTa
4RGMfRGnUa2Fzz/gfjhvfSIGeLQ3JRG6sl6jkc5xe0PZzhq3UNpK0gtQ48yy9CSP
neZnrynoKks7XC2bizsr3QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAHS/xuG5+F
yGU3N6V4kv+HbKqHaXNOq4zKVsCc1k7vg4MFFpKUJKxtJYooCI8n2ypp5XRUTIGQ
bmEbVcIPqm9Rf/4vHtF0falNCwieAbXDkiEHoykRmmU1UE/ccPA7X8NO9aVLJAJO
N2Li8MH0Ixgs02pQH56eyGKoRBWPR5C3ETQ9Leqvazg6Dn1iJWvmfF0mOte5228s
mZJOntF9t8MZOJdIWGdrUHn6euRfhd0btkmL/NUDzeCTwJcuPORLxkBbCP5mTC6G
GnLS5Z4oRYgCgvT2pLtcM0r48hYjwgjXFQ4zalkW6YI9LPpqwwMhhOzINlXjBaDi
Haz8uKI4EciU
-----END CERTIFICATE-----
`

var key string = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAml44fThYMkCcT627o7ibEs7mq2WOhImjDwYijYJ1684BatrC
sHJNcw8PJGTuP+tgGdngmALjA3l+RipjaE/UK4FJrAjruphA/hOCjZfWqk8KBR4q
k0OltxCMWJlp/XCM9ny1ogFdWUlBbqThs4NWSOUESgxf/Be2njeiOrngGR31qxSi
LCLBvafIhKqq/4avRlx0Ht770uvF97MlAj1ASAvzTZICHAfUZxEdWl0J4MBbG7SN
cnMBbyAF+s60eFTa4RGMfRGnUa2Fzz/gfjhvfSIGeLQ3JRG6sl6jkc5xe0PZzhq3
UNpK0gtQ48yy9CSPneZnrynoKks7XC2bizsr3QIDAQABAoIBAFpYUo9W7qdakSFA
+NS1Mm0rkm01nteLBlfAq3BOrl030DSNm+xQuWthoOcX+yiFxVTb40qURfC+plzC
ajOepPphTJDXF7+5ZDBPktTzzLsYTzD3mstdiBtAICOqhhHCUX3hNxx91/htm1H6
Re4eK921y3DbFUIhTswCm3vrVXDc4yTXtURGllVzo40K/1Of39CpufKFdpJ81HV+
h/VW++h3o+sFV4KqcqIjClxBfDxoJpBaRlOCunTiHqZNvqO+EPqPR5zdn34werjU
xQEvPzmz+ClwnaEXQxYWgIcYQii9VNsHogDxEw4R31S7lVrUt0f0atDmGJip1lPb
E7IomAECgYEAzKQ3PzBV46nUNfVO9SODpf14Z+xYfLKouPC+Qnepwp0V0JS6zY1+
Wzskyb80drjnoQraWSEvGsX+tEWeLcnjN7JuMu/U8DPKRcQ+Q2dsVo/q4sfBOgvl
VhPNMZLfa7NIkRUx2KXku++Ep0Xtak0dskrfQrZnvhymRPyWuIMM6IECgYEAwRwL
Gt/ZZdUueE/hwT3c1hNn6igeDLOwK2t6frib+Ofw5oCAQxtTROvP1ljlnWUPkeIS
uzTusmqucalcK3lCHIsyHLwApOI/B31M971pxMVBRZ0wIbBaoarCGND7gi8JUPFR
VErGcAB5YnpRlmfLPEgw2o7DpjsDc2KmdE9oNV0CgYEAmfNEWLYtNztxGTK1treD
96ELLutf2lexlIgQKgLJ5E22tpbdPXwfvdRtpZTBjDsojj+S6hCL1lFzfv0MtZe2
5xTF0G4avKXJmti6moy4tRpJ81ehZuDCJBJ7gLrkd6qFghf2yuxqenQDUK/Lnvfq
ylGHSjHdM+lrsGRxotd8I4ECgYBoo4GA9nseqv2bQ+3YgGUBu1I7l7FwwI1decfO
ksoxfb0Tqd3WfyAH4J+mTlVdjD17lzz/JBeTpisQe+ztwa8JOIPW/ih7L/1nWYYz
V/fQH/LWfe5u0tjJcXXrbJJcYJBzw8+GFV6hoiAkNJOxJF0ENToDtAhgMuoTxAje
TYjyIQKBgQCmHkLLq0Bj3FpIOVrwo2gNvQteNPa7jkkGp4lljO8JQUHhCHDGWKEH
MUJ0EFsxS/EaQa+rW6jHhs3GyBA2TxmC783stAOOEX+hO/zpcbzdCWgp6eZ0aGMW
WS94/5WE/lwHJi8ZPSjH1AURCzXhUi4fGvBrNBtry95e+jcEvP5c0g==
-----END RSA PRIVATE KEY-----
`

func TestTls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ioutil.WriteFile("server.crt", []byte(cert), 0777)
	ioutil.WriteFile("server.key", []byte(key), 0777)

	// Init server & client
	port := common.PickPort("tcp", "127.0.0.1")
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := "trojans://hash1234@" + addr + "?cert=server.crt&key=server.key"
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
