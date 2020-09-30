package vmess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/url"
	"time"

	"github.com/jarvisgally/crossfire/api"
	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	proxy.RegisterServer(Name, NewVmessServer)
}

func NewVmessServer(ctx context.Context, url *url.URL) (proxy.Server, error) {
	addr := url.Host

	uuidStr := url.User.Username()
	alterIDStr, ok := url.User.Password()
	if !ok {
		alterIDStr = "4"
	}

	query := url.Query()

	s := &Server{addr: addr}
	s.userManager = NewUserManager(ctx, uuidStr, alterIDStr)

	// Run API service
	apiListenAddr := query.Get("api")
	if apiListenAddr != "" {
		go api.RunServerAPI(ctx, s.userManager, apiListenAddr)
	}

	return s, nil
}

type Server struct {
	addr string

	// Provides user/stats control for client
	userManager *UserManager
}

func (s *Server) Name() string { return Name }

func (s *Server) Addr() string { return s.addr }

func (s *Server) Handshake(underlay net.Conn) (proxy.StreamConn, *proxy.TargetAddr, error) {
	// Set handshake timeout 3 seconds
	if err := underlay.SetReadDeadline(time.Now().Add(time.Second * 3)); err != nil {
		return nil, nil, err
	}
	defer underlay.SetReadDeadline(time.Time{})

	c := &ServerConn{Conn: underlay}

	//
	// 处理16字节的认证信息，匹配出目前正在访问的用户
	// NOTE: 暂不支持VMess的AEAD认证， AEAD认证是通过在客户端设置testsEnabled=VMessAEAD打开
	//

	var auth [16]byte
	_, err := io.ReadFull(c.Conn, auth[:])
	if err != nil {
		return nil, nil, err
	}

	user, timestamp, err := s.userManager.CheckAuth(auth)
	if err != nil {
		return nil, nil, err
	}
	c.user = user
	c.user.AddTraffic(0, 16)
	c.recv += uint64(16)

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse host %v: %v", c.Conn.RemoteAddr(), err)
	}

	c.ip = ip
	ok := user.AddIP(ip)
	if !ok {
		return nil, nil, fmt.Errorf("ip limit reached for user %v", user.Hash())
	}

	//
	// 解开指令部分，该部分使用了AES-128-CFB加密
	//

	fullReq := common.GetWriteBuffer()
	defer common.PutWriteBuffer(fullReq)

	block, err := aes.NewCipher(user.CmdKey[:])
	if err != nil {
		return nil, nil, err
	}
	stream := cipher.NewCFBDecrypter(block, TimestampHash(timestamp))
	// 41{1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1} + 1 + MAX{255} + MAX{15} + 4 = 362
	req := common.GetBuffer(41)
	defer common.PutBuffer(req)
	n, err := io.ReadFull(c.Conn, req)
	if err != nil {
		return nil, nil, err
	}
	c.user.AddTraffic(0, n)
	c.recv += uint64(n)
	stream.XORKeyStream(req, req)
	fullReq.Write(req)

	copy(c.reqBodyIV[:], req[1:17])   // 16 bytes, 数据加密 IV
	copy(c.reqBodyKey[:], req[17:33]) // 16 bytes, 数据加密 Key

	_, err = s.userManager.CheckSession(auth, user.UUID, c.reqBodyKey, c.reqBodyIV)
	if err != nil {
		return nil, nil, err
	}

	c.reqRespV = req[33]           // 1 byte, 直接用于响应的认证
	c.opt = req[34]                // 1 byte
	padingLen := int(req[35] >> 4) // 4 bits, 余量 P
	c.security = req[35] & 0x0F    // 4 bits, 加密方式 Sec
	cmd := req[37]                 // 1 byte, 指令 Cmd
	if cmd != CmdTCP {
		return nil, nil, fmt.Errorf("unsuppoted command %v", cmd)
	}

	// 解析地址, 从41位开始读
	addr := &proxy.TargetAddr{}
	addr.Port = int(binary.BigEndian.Uint16(req[38:40]))
	l := 0
	switch req[40] {
	case AtypIP4:
		l = net.IPv4len
		addr.IP = make(net.IP, net.IPv4len)
	case AtypDomain:
		// 解码域名的长度
		reqLength := common.GetBuffer(1)
		defer common.PutBuffer(reqLength)
		n, err = io.ReadFull(c.Conn, reqLength)
		if err != nil {
			return nil, nil, err
		}
		c.user.AddTraffic(0, n)
		c.recv += uint64(n)
		stream.XORKeyStream(reqLength, reqLength)
		fullReq.Write(reqLength)
		l = int(reqLength[0])
	case AtypIP6:
		l = net.IPv6len
		addr.IP = make(net.IP, net.IPv6len)
	default:
		return nil, nil, fmt.Errorf("unknown address type %v", req[40])
	}
	// 解码剩余部分
	reqRemaining := common.GetBuffer(l + padingLen + 4)
	defer common.PutBuffer(reqRemaining)
	n, err = io.ReadFull(c.Conn, reqRemaining)
	if err != nil {
		return nil, nil, err
	}
	c.user.AddTraffic(0, n)
	c.recv += uint64(n)
	stream.XORKeyStream(reqRemaining, reqRemaining)
	fullReq.Write(reqRemaining)

	if addr.IP != nil {
		copy(addr.IP, reqRemaining[:l])
	} else {
		addr.Name = string(reqRemaining[:l])
	}
	c.target = addr.String()
	full := fullReq.Bytes()
	// log.Printf("Request Recv %v", full)

	// 跳过余量读取四个字节的校验F
	fnv1a := fnv.New32a()
	_, err = fnv1a.Write(full[:len(full)-4])
	if err != nil {
		return nil, nil, err
	}
	actualHash := fnv1a.Sum32()
	expectedHash := binary.BigEndian.Uint32(reqRemaining[len(reqRemaining)-4:])
	if actualHash != expectedHash {
		return nil, nil, errors.New("invalid req")
	}

	return c, addr, nil
}

func (s *Server) Pack(underlay net.Conn) (proxy.PacketConn, error) {
	return nil, errors.New("implement me")
}

// ServerConn wrapper a net.Conn with vmess protocol
type ServerConn struct {
	net.Conn
	dataReader io.Reader
	dataWriter io.Writer

	target   string
	user     *User
	opt      byte
	security byte

	reqBodyIV   [16]byte
	reqBodyKey  [16]byte
	reqRespV    byte
	respBodyIV  [16]byte
	respBodyKey [16]byte

	sent uint64
	recv uint64
	ip   string
}

func (c *ServerConn) Read(b []byte) (int, error) {
	if c.dataReader == nil {
		// 解码数据部分
		c.dataReader = c.Conn
		if c.opt&OptChunkStream == OptChunkStream {
			switch c.security {
			case SecurityNone:
				c.dataReader = ChunkedReader(c.Conn)

			case SecurityAES128GCM:
				block, _ := aes.NewCipher(c.reqBodyKey[:])
				aead, _ := cipher.NewGCM(block)
				c.dataReader = AEADReader(c.Conn, aead, c.reqBodyIV[:])

			case SecurityChacha20Poly1305:
				key := common.GetBuffer(32)
				t := md5.Sum(c.reqBodyKey[:])
				copy(key, t[:])
				t = md5.Sum(key[:16])
				copy(key[16:], t[:])
				aead, _ := chacha20poly1305.New(key)
				c.dataReader = AEADReader(c.Conn, aead, c.reqBodyIV[:])
				common.PutBuffer(key)
			}
		}
	}

	n, err := c.dataReader.Read(b)
	c.user.AddTraffic(0, n)
	c.recv += uint64(n)
	return n, err
}

func (c *ServerConn) Write(b []byte) (int, error) {
	if c.dataWriter == nil {
		// 编码响应头
		// 应答头部数据使用 AES-128-CFB 加密，IV 为 MD5(数据加密 IV)，Key 为 MD5(数据加密 Key)
		buf := common.GetWriteBuffer()
		defer common.PutWriteBuffer(buf)

		buf.WriteByte(c.reqRespV) // 响应认证 V
		buf.WriteByte(c.opt)      // 选项 Opt
		buf.Write([]byte{0, 0})   // 指令 Cmd 和 长度 M, 不支持动态端口指令

		c.respBodyKey = md5.Sum(c.reqBodyKey[:])
		c.respBodyIV = md5.Sum(c.reqBodyIV[:])

		block, err := aes.NewCipher(c.respBodyKey[:])
		if err != nil {
			return 0, err
		}

		stream := cipher.NewCFBEncrypter(block, c.respBodyIV[:])
		stream.XORKeyStream(buf.Bytes(), buf.Bytes())
		_, err = c.Conn.Write(buf.Bytes())
		if err != nil {
			return 0, err
		}

		// 编码内容
		c.dataWriter = c.Conn
		if c.opt&OptChunkStream == OptChunkStream {
			switch c.security {
			case SecurityNone:
				c.dataWriter = ChunkedWriter(c.Conn)

			case SecurityAES128GCM:
				block, _ := aes.NewCipher(c.reqBodyKey[:])
				aead, _ := cipher.NewGCM(block)
				c.dataWriter = AEADWriter(c.Conn, aead, c.reqBodyIV[:])

			case SecurityChacha20Poly1305:
				key := common.GetBuffer(32)
				t := md5.Sum(c.reqBodyKey[:])
				copy(key, t[:])
				t = md5.Sum(key[:16])
				copy(key[16:], t[:])
				aead, _ := chacha20poly1305.New(key)
				c.dataWriter = AEADWriter(c.Conn, aead, c.reqBodyIV[:])
				common.PutBuffer(key)
			}
		}
	}

	n, err := c.dataWriter.Write(b)
	c.user.AddTraffic(n, 0)
	c.sent += uint64(n)
	return n, err
}

func (c *ServerConn) Close() error {
	log.Printf("user %v from %v tunneling to %v closed, sent: %v, recv: %v", c.user.Hash(), c.Conn.RemoteAddr(), c.target, common.HumanFriendlyTraffic(c.sent), common.HumanFriendlyTraffic(c.recv))
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}
