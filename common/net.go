package common

import (
	"fmt"
	"net"
	"strconv"
)

const (
	KiB = 1024
	MiB = KiB * 1024
	GiB = MiB * 1024

	// Packet size limit
	MaxPacketSize = 1024 * 8
)

func HumanFriendlyTraffic(bytes uint64) string {
	if bytes <= KiB {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes <= MiB {
		return fmt.Sprintf("%.2f KiB", float32(bytes)/KiB)
	}
	if bytes <= GiB {
		return fmt.Sprintf("%.2f MiB", float32(bytes)/MiB)
	}
	return fmt.Sprintf("%.2f GiB", float32(bytes)/GiB)
}

// For testing only
func PickPort(network string, host string) int {
	switch network {
	case "tcp":
		for retry := 0; retry < 16; retry++ {
			l, err := net.Listen("tcp", host+":0")
			if err != nil {
				continue
			}
			defer l.Close()
			_, port, _ := net.SplitHostPort(l.Addr().String())
			p, _ := strconv.ParseInt(port, 10, 32)
			return int(p)
		}
	case "udp":
		for retry := 0; retry < 16; retry++ {
			conn, err := net.ListenPacket("udp", host+":0")
			if err != nil {
				continue
			}
			defer conn.Close()
			_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
			p, _ := strconv.ParseInt(port, 10, 32)
			return int(p)
		}
	default:
		return 0
	}
	return 0
}
