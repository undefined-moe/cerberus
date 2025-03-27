package cerberus

import (
	"errors"
	"fmt"
	"net"
)

// IPBlock represents either an IPv4 or IPv6 block
// Data representation:
// v6: Stored as first 8 bytes of the address
// v4: Stored as 2001:db8:<v4>
type IPBlock struct {
	data uint64
}

type IPBlockConfig struct {
	v4Prefix int
	v6Prefix int
}

func (c IPBlockConfig) IsEmpty() bool {
	return c.v4Prefix == 0 && c.v6Prefix == 0
}

func ValidateIPBlockConfig(cfg IPBlockConfig) bool {
	// Due to uint64 size limitation, we only allow at most /64 for IPv6
	return cfg.v4Prefix <= 32 && cfg.v6Prefix <= 64
}

// NewIPBlock creates a new IPBlock from an IP address
func NewIPBlock(ip net.IP, cfg IPBlockConfig) (IPBlock, error) {
	if ip == nil {
		return IPBlock{}, errors.New("invalid IP: nil")
	}

	ip4 := ip.To4()
	if ip4 != nil {
		ip4 = ip4.Mask(net.CIDRMask(cfg.v4Prefix, 32))
		return IPBlock{
			data: 0x20010db800000000 | uint64(ip4[0])<<24 | uint64(ip4[1])<<16 | uint64(ip4[2])<<8 | uint64(ip4[3]),
		}, nil
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return IPBlock{}, fmt.Errorf("invalid IP: %v", ip)
	}
	ip6 = ip6.Mask(net.CIDRMask(cfg.v6Prefix, 128))
	data := uint64(0)
	for i := 0; i < 8; i++ {
		data = data<<8 | uint64(ip6[i])
	}
	return IPBlock{data: data}, nil
}

func (b IPBlock) ToIPNet(cfg IPBlockConfig) *net.IPNet {
	if b.data&0xffffffff00000000 == 0x20010db800000000 {
		return &net.IPNet{
			IP:   net.IPv4(byte(b.data>>24&0xff), byte(b.data>>16&0xff), byte(b.data>>8&0xff), byte(b.data&0xff)),
			Mask: net.CIDRMask(cfg.v4Prefix, 32),
		}
	}

	ip := make(net.IP, 16)
	for i := 0; i < 8; i++ {
		ip[7-i] = byte(b.data >> (8 * i))
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(cfg.v6Prefix, 128),
	}
}

func KeyToHash(keyRaw interface{}) (uint64, uint64) {
	key := keyRaw.(IPBlock)
	return key.data, 0
}
