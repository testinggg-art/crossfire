package vmess

import (
	"crypto/md5"
	"encoding/binary"
	"github.com/jarvisgally/crossfire/common"
	"net"
	"strconv"
)

const Name = "vmess"

// https://www.v2fly.org/developer/protocols/vmess.html

// Request Options
const (
	OptBasicFormat byte = 0 // 不加密传输
	OptChunkStream byte = 1 // 分块传输，每个分块使用如下Security方法加密
	// OptReuseTCPConnection byte = 2
	// OptMetadataObfuscate  byte = 4
)

// Security types
const (
	SecurityAES128GCM        byte = 3
	SecurityChacha20Poly1305 byte = 4
	SecurityNone             byte = 5
)

// CMD types
const (
	CmdTCP byte = 1
	CmdUDP byte = 2
)

// Atyp
const (
	AtypIP4    byte = 1
	AtypDomain byte = 2
	AtypIP6    byte = 3
)

// ParseAddr parses the address in string
func ParseAddr(s string) (byte, []byte, uint16, error) {
	var atyp byte
	var addr []byte

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return 0, nil, 0, err
	}

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = make([]byte, net.IPv4len)
			atyp = AtypIP4
			copy(addr[:], ip4)
		} else {
			addr = make([]byte, net.IPv6len)
			atyp = AtypIP6
			copy(addr[:], ip)
		}
	} else {
		if len(host) > 255 {
			return 0, nil, 0, err
		}
		addr = make([]byte, 1+len(host))
		atyp = AtypDomain
		addr[0] = byte(len(host))
		copy(addr[1:], host)
	}

	portnum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, nil, 0, err
	}

	return atyp, addr, uint16(portnum), err
}

// TimestampHash returns the iv of AES-128-CFB encrypter
// IV：MD5(X + X + X + X)，X = []byte(timestamp.now) (8 bytes, Big Endian)
func TimestampHash(unixSec int64) []byte {
	ts := common.GetBuffer(8)
	defer common.PutBuffer(ts)

	binary.BigEndian.PutUint64(ts, uint64(unixSec))
	md5hash := md5.New()
	md5hash.Write(ts)
	md5hash.Write(ts)
	md5hash.Write(ts)
	md5hash.Write(ts)
	return md5hash.Sum(nil)
}
