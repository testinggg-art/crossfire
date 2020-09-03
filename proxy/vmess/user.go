package vmess

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"
)

// Vmess user
type User struct {
	Hash   string
	UUID   [16]byte
	CmdKey [16]byte
}

func NewUser(hash string) (*User, error) {
	uuid, err := StrToUUID(hash)
	if err != nil {
		return nil, err
	}
	u := &User{Hash: hash, UUID: uuid}
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

// GenAlterIDUsers generates users according to primary user's id and alterID
func (u *User) GenAlterIDUsers(alterID int) []*User {
	users := make([]*User, alterID)
	preID := u.UUID
	for i := 0; i < alterID; i++ {
		newID := nextID(preID)
		// NOTE: alterID user is a user which have a different uuid but a same cmdkey with the primary user.
		users[i] = &User{Hash: u.Hash, UUID: newID, CmdKey: u.CmdKey}
		preID = newID
	}

	return users
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

