package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
)

func init() {
	proxy.RegisterServer(Name, NewSocks5Server)
}

func NewSocks5Server(ctx context.Context, url *url.URL) (proxy.Server, error) {
	addr := url.Host

	// TODO: Support Auth
	user := url.User.Username()
	password, _ := url.User.Password()

	s := &Server{
		addr:     addr,
		user:     user,
		password: password,
	}
	return s, nil
}

type Server struct {
	addr     string
	user     string
	password string
}

func (s *Server) Name() string { return Name }

func (s *Server) Addr() string { return s.addr }

func (s *Server) Handshake(underlay net.Conn) (proxy.StreamConn, *proxy.Target, error) {
	reqOneByte := common.GetBuffer(1)
	defer common.PutBuffer(reqOneByte)

	// https://www.ietf.org/rfc/rfc1928.txt

	//   The client connects to the server, and sends a version
	//   identifier/method selection message:
	//
	//                   +----+----------+----------+
	//                   |VER | NMETHODS | METHODS  |
	//                   +----+----------+----------+
	//                   | 1  |    1     | 1 to 255 |
	//                   +----+----------+----------+
	if _, err := io.ReadFull(underlay, reqOneByte); err != nil {
		return nil, nil, fmt.Errorf("failed to read socks version: %v", err)
	}
	if reqOneByte[0] != Version5 {
		return nil, nil, fmt.Errorf("invalid socks version %v", reqOneByte[0])
	}
	if _, err := io.ReadFull(underlay, reqOneByte); err != nil {
		return nil, nil, errors.New("failed to read NMETHODS")
	}
	if _, err := io.CopyN(ioutil.Discard, underlay, int64(reqOneByte[0])); err != nil {
		return nil, nil, fmt.Errorf("failed to read methods: %v", err)
	}

	//   The server selects from one of the methods given in METHODS, and
	//   sends a METHOD selection message:
	//
	//                         +----+--------+
	//                         |VER | METHOD |
	//                         +----+--------+
	//                         | 1  |   1    |
	//                         +----+--------+
	if _, err := underlay.Write([]byte{Version5, AuthNone}); err != nil {
		return nil, nil, fmt.Errorf("failed to write auth: %v", err)
	}

	//   The SOCKS request is formed as follows:
	//
	//        +----+-----+-------+------+----------+----------+
	//        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//        +----+-----+-------+------+----------+----------+
	//        | 1  |  1  | X'00' |  1   | Variable |    2     |
	//        +----+-----+-------+------+----------+----------+
	reqCmd := common.GetBuffer(3)
	defer common.PutBuffer(reqCmd)
	if _, err := io.ReadFull(underlay, reqCmd); err != nil {
		return nil, nil, fmt.Errorf("failed to read command: %v", err)
	}
	cmd := reqCmd[1]

	target, _, err := ReadTarget(underlay)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read address: %v", err)
	}
	target.Network = "tcp"

	//   The server evaluates the request, and
	//   returns a reply formed as follows:
	//
	//        +----+-----+-------+------+----------+----------+
	//        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//        +----+-----+-------+------+----------+----------+
	//        | 1  |  1  | X'00' |  1   | Variable |    2     |
	//        +----+-----+-------+------+----------+----------+
	switch cmd {
	case CmdConnect:
		_, err = underlay.Write([]byte{Version5, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case CmdUDPAssociate:
		listenAddr := ParseAddr(underlay.LocalAddr().String())
		_, err = underlay.Write(append([]byte{Version5, 0, 0}, listenAddr...))
		// Keep the connection util timeout then the socket will be free
		buf := common.GetBuffer(16)
		defer common.PutBuffer(buf)
		underlay.Read(buf)
	default:
		return nil, nil, fmt.Errorf("unsupported command %v", cmd)
	}

	return underlay, target, err
}

func (s *Server) Pack(underlay net.Conn) (proxy.PacketConn, error) {
	return &PacketConn{
		UDPConn: underlay.(*net.UDPConn),
	}, nil
}
