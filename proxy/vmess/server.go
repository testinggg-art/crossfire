package vmess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jarvisgally/crossfire/api"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/jarvisgally/crossfire/common"
	"github.com/jarvisgally/crossfire/proxy"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	updateInterval   = 30 * time.Second
	cacheDurationSec = 120
	sessionTimeOut   = 3 * time.Minute
)

func init() {
	proxy.RegisterServer(Name, NewVmessServer)
}

func NewVmessServer(ctx context.Context, url *url.URL) (proxy.Server, error) {
	addr := url.Host

	// uuid
	uuidStr := url.User.Username()
	user, err := NewUser(uuidStr)
	if err != nil {
		return nil, err
	}

	// alterId
	alterIDStr, ok := url.User.Password()
	if !ok {
		alterIDStr = "4"
	}
	alterID, err := strconv.ParseUint(alterIDStr, 10, 32)
	if err != nil {
		log.Printf("parse alterId err: %v", err)
		return nil, err
	}

	query := url.Query()

	// security
	security := query.Get("security")
	if security == "" {
		security = "none"
	}

	//
	s := &Server{addr: addr}
	s.users = append(s.users, user)
	s.users = append(s.users, user.GenAlterIDUsers(int(alterID))...)

	s.authenticator = proxy.NewAuthenticator(ctx, uuidStr)
	// Run API service
	apiListenAddr := query.Get("api")
	if apiListenAddr != "" {
		go api.RunServerAPI(ctx, s.authenticator, apiListenAddr)
	}

	s.baseTime = time.Now().UTC().Unix() - cacheDurationSec*2
	s.userHashes = make(map[[16]byte]*UserAtTime, 1024)
	s.sessionHistory = make(map[SessionId]time.Time, 128)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(updateInterval):
				s.Refresh()
			}
		}
	}()
	s.Refresh()

	return s, nil
}

type UserAtTime struct {
	user    *User
	timeInc int64
	tainted bool // 是否被重放攻击污染
}

type SessionId struct {
	user  [16]byte
	key   [16]byte
	nonce [16]byte
}

type Server struct {
	addr  string
	users []*User

	// userHashes用于校验VMess请求的认证信息部分
	// sessionHistory保存一段时间内的请求用来检测重放攻击
	baseTime       int64
	userHashes     map[[16]byte]*UserAtTime
	sessionHistory map[SessionId]time.Time

	// 定时刷新userHashes和sessionHistory
	mux4Hashes, mux4Sessions sync.RWMutex

	// Provides user/stats control for client
	authenticator *proxy.Authenticator
}

func (s *Server) Name() string { return Name }

func (s *Server) Addr() string { return s.addr }

func (s *Server) Handshake(underlay net.Conn) (io.ReadWriteCloser, *proxy.TargetAddr, error) {
	// Set handshake timeout 4 seconds
	if err := underlay.SetReadDeadline(time.Now().Add(time.Second * 4)); err != nil {
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
	var user *User
	var timestamp int64
	s.mux4Hashes.RLock()
	uat, found := s.userHashes[auth]
	if !found || uat.tainted {
		s.mux4Hashes.RUnlock()
		return nil, nil, errors.New("invalid user or tainted")
	}
	user = uat.user
	timestamp = uat.timeInc + s.baseTime
	s.mux4Hashes.RUnlock()
	c.user = user

	valid, meter := s.authenticator.AuthUser(user.Hash)
	if !valid {
		return nil, nil, fmt.Errorf("invalid user hash %v", user.Hash)
	}
	c.meter = meter
	c.meter.AddTraffic(0, 16)
	c.recv += uint64(16)

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse host %v: %v", c.Conn.RemoteAddr(), err)
	}

	c.ip = ip
	ok := meter.AddIP(ip)
	if !ok {
		return nil, nil, fmt.Errorf("ip limit reached for user %v", user.Hash)
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
	c.meter.AddTraffic(0, n)
	c.recv += uint64(n)
	stream.XORKeyStream(req, req)
	fullReq.Write(req)

	copy(c.reqBodyIV[:], req[1:17])   // 16 bytes, 数据加密 IV
	copy(c.reqBodyKey[:], req[17:33]) // 16 bytes, 数据加密 Key

	var sid SessionId
	copy(sid.user[:], user.UUID[:])
	sid.key = c.reqBodyKey
	sid.nonce = c.reqBodyIV
	s.mux4Sessions.Lock()
	now := time.Now().UTC()
	if expire, found := s.sessionHistory[sid]; found && expire.After(now) {
		s.mux4Sessions.Unlock()
		return nil, nil, errors.New("duplicated session id")
	}
	s.sessionHistory[sid] = now.Add(sessionTimeOut)
	s.mux4Sessions.Unlock()

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
		c.meter.AddTraffic(0, n)
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
	c.meter.AddTraffic(0, n)
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

func (s *Server) Refresh() {
	s.mux4Hashes.Lock()
	now := time.Now().UTC()
	nowSec := now.Unix()
	genBeginSec := nowSec - cacheDurationSec
	genEndSec := nowSec + cacheDurationSec
	var hashValue [16]byte
	for _, user := range s.users {
		hasher := hmac.New(md5.New, user.UUID[:])
		for ts := genBeginSec; ts <= genEndSec; ts++ {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(ts))
			hasher.Write(b[:])
			hasher.Sum(hashValue[:0])
			hasher.Reset()

			s.userHashes[hashValue] = &UserAtTime{
				user:    user,
				timeInc: ts - s.baseTime,
				tainted: false,
			}
		}
	}
	if genBeginSec > s.baseTime {
		for k, v := range s.userHashes {
			if v.timeInc+s.baseTime < genBeginSec {
				delete(s.userHashes, k)
			}
		}
	}
	s.mux4Hashes.Unlock()

	s.mux4Sessions.Lock()
	for session, expire := range s.sessionHistory {
		if expire.Before(now) {
			delete(s.sessionHistory, session)
		}
	}
	s.mux4Sessions.Unlock()
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

	meter *proxy.Meter
	sent  uint64
	recv  uint64
	ip    string
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
	c.meter.AddTraffic(0, n)
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
	c.meter.AddTraffic(n, 0)
	c.sent += uint64(n)
	return n, err
}

func (c *ServerConn) Close() error {
	log.Printf("user %v from %v tunneling to %v closed, sent: %v, recv: %v", c.user.Hash, c.Conn.RemoteAddr(), c.target, common.HumanFriendlyTraffic(c.sent), common.HumanFriendlyTraffic(c.recv))
	c.meter.DelIP(c.ip)
	return c.Conn.Close()
}
