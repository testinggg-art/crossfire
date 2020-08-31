package proxy

import (
	"context"
	"fmt"
	"sync"
)

// Authenticator provides functions to manage users for servers.
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

// Create Authenticator from user ids
func NewAuthenticator(ctx context.Context, userIds ...string) *Authenticator {
	au := &Authenticator{
		ctx:   ctx,
		users: make(map[string]*Meter),
	}
	// TODO: Load other users from local database
	for _, userId := range userIds {
		au.AddUser(userId)
	}
	return au
}
