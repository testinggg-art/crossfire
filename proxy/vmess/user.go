package vmess

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jarvisgally/crossfire/proxy"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	updateInterval   = 30 * time.Second
	cacheDurationSec = 120
	sessionTimeOut   = 3 * time.Minute
)

// VMess user
type User struct {
	*proxy.Meter
	UUID [16]byte

	// VMess协议会使用用户的UUID生成AlterId个新的UUID，随机的使用不同的UUID进行传输这个用户的流量
	// https://www.v2fly.org/config/protocols/vmess.html
	AlterId int
	UUIDs   [][16]byte
	// AES-128-CFB加密算法的Key，用于指令部分的加密
	// https://www.v2fly.org/developer/protocols/vmess.html#%E6%8C%87%E4%BB%A4%E9%83%A8%E5%88%86
	CmdKey [16]byte
}

func NewUser(ctx context.Context, uuidStr, alterIdStr string) (*User, error) {
	uuid, err := StrToUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	alterId, err := strconv.ParseUint(alterIdStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse alterId error: %v", err)
	}

	uuids := make([][16]byte, alterId)
	uuids[0] = uuid
	for i := 1; i < int(alterId); i++ {
		uuids[i] = nextID(uuids[i-1])
	}

	u := &User{
		Meter:   proxy.NewMeter(ctx, uuidStr),
		UUID:    uuid,
		AlterId: int(alterId),
		UUIDs:   uuids,
	}
	copy(u.CmdKey[:], GetKey(uuid))
	return u, nil
}

func nextID(oldID [16]byte) (newID [16]byte) {
	md5hash := md5.New()
	md5hash.Write(oldID[:])
	md5hash.Write([]byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
	for {
		md5hash.Sum(newID[:0])
		if !bytes.Equal(oldID[:], newID[:]) {
			return
		}
		md5hash.Write([]byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2"))
	}
}

// StrToUUID converts string to uuid
func StrToUUID(s string) (uuid [16]byte, err error) {
	b := []byte(strings.Replace(s, "-", "", -1))
	if len(b) != 32 {
		return uuid, errors.New("invalid UUID: " + s)
	}
	_, err = hex.Decode(uuid[:], b)
	return
}

// GetKey returns the key of AES-128-CFB encrypter
// Key：MD5(UUID + []byte('c48619fe-8f02-49e0-b9e9-edf763e17e21'))
func GetKey(uuid [16]byte) []byte {
	md5hash := md5.New()
	md5hash.Write(uuid[:])
	md5hash.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	return md5hash.Sum(nil)
}

// VMess user manager
type UserManager struct {
	// 所有用户
	users map[string]*User

	// userHashes用于校验VMess请求的认证信息部分
	// sessionHistory保存一段时间内的请求用来检测重放攻击
	baseTime       int64
	userAuths      map[[16]byte]*UserAtTime
	sessionHistory map[SessionId]time.Time

	// Mutex
	mux4Users, mux4Auths, mux4Sessions sync.RWMutex

	ctx context.Context
}

func (um *UserManager) ListUsers() []proxy.User {
	um.mux4Users.RLock()
	defer um.mux4Users.RUnlock()
	result := make([]proxy.User, len(um.users))
	i := 0
	for _, u := range um.users {
		result[i] = u
		i++
	}
	return result
}

func (um *UserManager) AuthUser(hash string) (bool, proxy.User) {
	um.mux4Users.RLock()
	defer um.mux4Users.RUnlock()
	if user, found := um.users[hash]; found {
		return true, user
	}
	return false, nil
}

// 添加用户后，平均30秒会刷新
func (um *UserManager) AddUser(hash string, more ...string) error {
	um.mux4Users.Lock()
	defer um.mux4Users.Unlock()
	if _, found := um.users[hash]; found {
		return fmt.Errorf("hash %v already exists", hash)
	}
	alterIdStr := "4"
	if len(more) > 0 {
		alterIdStr = more[0]
	}
	user, err := NewUser(um.ctx, hash, alterIdStr)
	if err != nil {
		return err
	}
	um.users[hash] = user
	return nil
}

func (um *UserManager) DelUser(hash string) error {
	um.mux4Users.Lock()
	defer um.mux4Users.Unlock()
	user, found := um.users[hash]
	if !found {
		return fmt.Errorf("hash %v not found", hash)
	}
	user.Close()
	delete(um.users, hash)
	return nil
}

type UserAtTime struct {
	user    *User
	timeInc int64
	tainted *uint32 // 是否被重放攻击污染
}

type SessionId struct {
	uuid  [16]byte
	key   [16]byte
	nonce [16]byte
}

// 处理VMess请求的认证信息
func (um *UserManager) CheckAuth(auth [16]byte) (*User, int64, error) {
	um.mux4Auths.RLock()
	defer um.mux4Auths.RUnlock()
	uat, found := um.userAuths[auth]
	if !found || atomic.LoadUint32(uat.tainted) == 1 {
		return nil, 0, errors.New("invalid user or tainted")
	}
	user := uat.user
	timestamp := uat.timeInc + um.baseTime
	return user, timestamp, nil
}

// 从VMess请求的指令部分中提取出reqBodyKey和reqBodyIV，来判断某个UUID是否已经发送过同样的值
func (um *UserManager) CheckSession(auth, uuid, reqBodyKey, reqBodyIV [16]byte) (*SessionId, error) {
	sid := SessionId{uuid: uuid, key: reqBodyKey, nonce: reqBodyIV}
	um.mux4Sessions.Lock()
	defer um.mux4Sessions.Unlock()
	now := time.Now().UTC()
	// 收到重放攻击
	if expire, found := um.sessionHistory[sid]; found && expire.After(now) {
		// 将对应的认证信息标记为已污染
		um.mux4Auths.RLock()
		defer um.mux4Auths.RUnlock()
		uat, found := um.userAuths[auth]
		if found {
			atomic.CompareAndSwapUint32(uat.tainted, 0, 1)
		}
		return nil, errors.New("duplicated session id")
	}
	// 无重放攻击，延长过期时间
	um.sessionHistory[sid] = now.Add(sessionTimeOut)
	return &sid, nil
}

// Refresh
func (um *UserManager) Refresh() {
	for {
		select {
		case <-um.ctx.Done():
			return
		case <-time.After(updateInterval):
			um.doRefresh()
		}
	}
}

func (um *UserManager) doRefresh() {
	// 刷新合法认证信息
	um.mux4Auths.Lock()
	defer um.mux4Auths.Unlock()

	now := time.Now().UTC()
	nowSec := now.Unix()
	genBeginSec := nowSec - cacheDurationSec
	genEndSec := nowSec + cacheDurationSec
	var hashValue [16]byte
	for _, user := range um.users {
		for _, uuid := range user.UUIDs {
			hasher := hmac.New(md5.New, uuid[:])
			for ts := genBeginSec; ts <= genEndSec; ts++ {
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], uint64(ts))
				hasher.Write(b[:])
				hasher.Sum(hashValue[:0])
				hasher.Reset()

				um.userAuths[hashValue] = &UserAtTime{
					user:    user,
					timeInc: ts - um.baseTime,
					tainted: new(uint32),
				}
			}
		}
	}
	if genBeginSec > um.baseTime {
		for k, v := range um.userAuths {
			if v.timeInc+um.baseTime < genBeginSec {
				delete(um.userAuths, k)
			}
		}
	}

	// 删除过期的session
	um.mux4Sessions.Lock()
	defer um.mux4Sessions.Unlock()
	for session, expire := range um.sessionHistory {
		if expire.Before(now) {
			delete(um.sessionHistory, session)
		}
	}
}

// Create a user manager with init user uuid and its alter id
func NewUserManager(ctx context.Context, uuidStr, alterId string) *UserManager {
	um := &UserManager{
		users:          make(map[string]*User),
		baseTime:       time.Now().UTC().Unix() - cacheDurationSec*2,
		userAuths:      make(map[[16]byte]*UserAtTime, 1024),
		sessionHistory: make(map[SessionId]time.Time, 128),
		ctx:            ctx,
	}
	um.AddUser(uuidStr, alterId)
	um.doRefresh()
	go um.Refresh()

	// TODO: Load other users from local file or database

	return um
}
