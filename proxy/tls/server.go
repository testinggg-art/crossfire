package tls

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
)

func init() {
	proxy.RegisterServer("vmesss", NewTlsServer)
	proxy.RegisterServer("trojans", NewTlsServer)
}

func NewTlsServer(ctx context.Context, url *url.URL) (proxy.Server, error) {
	addr := url.Host
	sni, _, _ := net.SplitHostPort(addr)

	query := url.Query()
	certFile := query.Get("cert")
	keyFile := query.Get("key")
	cert, err := stdtls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	fallback := query.Get("fallback")
	if fallback != "" {
		_, _, err = net.SplitHostPort(fallback)
		if err != nil {
			return nil, err
		}
	}

	s := &Server{name: url.Scheme, addr: addr, fallback: fallback}
	s.tlsConfig = &stdtls.Config{
		InsecureSkipVerify: false,
		ServerName:         sni,
		Certificates:       []stdtls.Certificate{cert},
	}

	url.Scheme = strings.TrimSuffix(url.Scheme, "s")
	s.inner, _ = proxy.ServerFromURL(ctx, url.String())

	return s, nil
}

type Server struct {
	name      string
	addr      string
	fallback  string
	tlsConfig *stdtls.Config

	inner proxy.Server
}

func (s *Server) Name() string { return s.name }

func (s *Server) Addr() string { return s.addr }

func (s *Server) Handshake(underlay net.Conn) (io.ReadWriteCloser, *proxy.TargetAddr, error) {
	tlsConn := stdtls.Server(underlay, s.tlsConfig)
	err := tlsConn.Handshake()
	if err != nil {
		return nil, nil, errors.New("invalid handshake")
	}

	sniffConn := common.NewSniffConn(tlsConn)
	t := sniffConn.Sniff()
	if t == common.TypeUnknown {
		// this is not a http request, route to next protocol
		return s.inner.Handshake(sniffConn)
	} else {
		// this is a http request
		return nil, nil, errors.New("not supported")
	}
}
