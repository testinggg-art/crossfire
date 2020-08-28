package proxy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type Meter struct {
	hash string // Identification of a user, can be UUID or any string

	sent        uint64
	recv        uint64
	lastSent    uint64
	lastRecv    uint64
	speedLock   sync.Mutex
	sendSpeed   uint64
	recvSpeed   uint64
	ipTableLock sync.Mutex
	ipTable     map[string]struct{}
	maxIPNum    int
	sendLimiter *rate.Limiter
	recvLimiter *rate.Limiter

	ctx    context.Context
	cancel context.CancelFunc
}

func (u *Meter) Close() error {
	u.ResetTraffic()
	u.cancel()
	return nil
}

func (u *Meter) AddIP(ip string) bool {
	if u.maxIPNum <= 0 {
		return true
	}
	u.ipTableLock.Lock()
	defer u.ipTableLock.Unlock()
	_, found := u.ipTable[ip]
	if found {
		return true
	}
	if len(u.ipTable)+1 > u.maxIPNum {
		return false
	}
	u.ipTable[ip] = struct{}{}
	return true
}

func (u *Meter) DelIP(ip string) bool {
	if u.maxIPNum <= 0 {
		return true
	}
	u.ipTableLock.Lock()
	defer u.ipTableLock.Unlock()
	_, found := u.ipTable[ip]
	if !found {
		return false
	}
	delete(u.ipTable, ip)
	return true
}

func (u *Meter) GetIP() int {
	u.ipTableLock.Lock()
	defer u.ipTableLock.Unlock()
	return len(u.ipTable)
}

func (u *Meter) SetIPLimit(n int) {
	u.maxIPNum = n
}

func (u *Meter) GetIPLimit() int {
	return u.maxIPNum
}

func (u *Meter) AddTraffic(sent, recv int) {
	if u.sendLimiter != nil && sent != 0 {
		u.sendLimiter.WaitN(u.ctx, sent)
	} else if u.recvLimiter != nil && recv != 0 {
		u.recvLimiter.WaitN(u.ctx, recv)
	}
	atomic.AddUint64(&u.sent, uint64(sent))
	atomic.AddUint64(&u.recv, uint64(recv))
}

func (u *Meter) SetSpeedLimit(send, recv int) {
	if send <= 0 {
		u.sendLimiter = nil
	} else {
		u.sendLimiter = rate.NewLimiter(rate.Limit(send), send*2)
	}
	if recv <= 0 {
		u.recvLimiter = nil
	} else {
		u.recvLimiter = rate.NewLimiter(rate.Limit(recv), recv*2)
	}
}

func (u *Meter) GetSpeedLimit() (send, recv int) {
	sendLimit := 0
	recvLimit := 0
	if u.sendLimiter != nil {
		sendLimit = int(u.sendLimiter.Limit())
	}
	if u.recvLimiter != nil {
		recvLimit = int(u.recvLimiter.Limit())
	}
	return sendLimit, recvLimit
}

func (u *Meter) Hash() string {
	return u.hash
}

func (u *Meter) SetTraffic(send, recv uint64) {
	atomic.StoreUint64(&u.sent, send)
	atomic.StoreUint64(&u.recv, recv)
}

func (u *Meter) GetTraffic() (uint64, uint64) {
	return atomic.LoadUint64(&u.sent), atomic.LoadUint64(&u.recv)
}

func (u *Meter) ResetTraffic() {
	atomic.StoreUint64(&u.sent, 0)
	atomic.StoreUint64(&u.recv, 0)
	atomic.StoreUint64(&u.lastSent, 0)
	atomic.StoreUint64(&u.lastRecv, 0)
}

func (u *Meter) GetAndResetTraffic() (uint64, uint64) {
	sent := atomic.SwapUint64(&u.sent, 0)
	recv := atomic.SwapUint64(&u.recv, 0)
	atomic.StoreUint64(&u.lastSent, 0)
	atomic.StoreUint64(&u.lastRecv, 0)
	return sent, recv
}

func (u *Meter) speedUpdater() {
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-time.After(time.Second):
			u.speedLock.Lock()
			sent, recv := u.GetTraffic()
			u.sendSpeed = sent - u.lastSent
			u.recvSpeed = recv - u.lastRecv
			u.lastSent = sent
			u.lastRecv = recv
			u.speedLock.Unlock()
		}
	}
}

func (u *Meter) GetSpeed() (uint64, uint64) {
	u.speedLock.Lock()
	defer u.speedLock.Unlock()
	return u.sendSpeed, u.recvSpeed
}

type Authenticator struct {
	sync.RWMutex

	users map[string]*Meter
	ctx   context.Context
}

func (a *Authenticator) AuthUser(hash string) (bool, *Meter) {
	a.RLock()
	defer a.RUnlock()
	if user, found := a.users[hash]; found {
		return true, user
	}
	return false, nil
}

func (a *Authenticator) AddUser(hash string) error {
	a.Lock()
	defer a.Unlock()
	if _, found := a.users[hash]; found {
		return fmt.Errorf("hash %v already exists", hash)
	}
	ctx, cancel := context.WithCancel(a.ctx)
	meter := &Meter{
		hash:    hash,
		ctx:     ctx,
		cancel:  cancel,
		ipTable: make(map[string]struct{}),
	}
	go meter.speedUpdater()
	a.users[hash] = meter
	return nil
}

func (a *Authenticator) DelUser(hash string) error {
	a.Lock()
	defer a.Unlock()
	meter, found := a.users[hash]
	if !found {
		return fmt.Errorf("hash %v not found", hash)
	}
	meter.Close()
	delete(a.users, hash)
	return nil
}

func (a *Authenticator) ListUsers() []*Meter {
	a.RLock()
	defer a.RUnlock()
	result := make([]*Meter, len(a.users))
	i := 0
	for _, u := range a.users {
		result[i] = u
		i++
	}
	return result
}

func (a *Authenticator) Close() error {
	return nil
}

// Create Authenticator from user ids
func NewAuthenticator(ctx context.Context, userIds []string) (*Authenticator, error) {
	au := &Authenticator{
		ctx:   ctx,
		users: make(map[string]*Meter),
	}
	for _, userId := range userIds {
		au.AddUser(userId)
	}
	return au, nil
}
