package cerberus

import "net"

type IPBlock struct {
	data uint64
}

func NewIPBlock(ip net.IP) IPBlock {
	if ip == nil {
		return IPBlock{}
	}

	ip4 := ip.To4()
	if ip4 != nil {
		// IPv4 - use /24 network blocks
		// Convert the first 3 bytes to uint64, leaving highest bit as 0
		return IPBlock{
			data: uint64(ip4[0])<<16 | uint64(ip4[1])<<8 | uint64(ip4[2]),
		}
	}

	// IPv6 - use /64 network blocks and set highest bit to 1
	ip6 := ip.To16()
	if ip6 == nil {
		return IPBlock{}
	}

	// Take first 8 bytes of IPv6 address (for /64 blocks)
	// Set the highest bit to 1 to indicate IPv6
	var data uint64 = 1 << 63
	for i := 0; i < 8; i++ {
		data |= uint64(ip6[i]) << (8 * (7 - i))
	}
	return IPBlock{data: data}
}

func (b IPBlock) IsEmpty() bool {
	return b.data == 0
}

func (b IPBlock) ToIP() net.IP {
	if b.data&0x8000000000000000 != 0 {
		// IPv6
		ip := make(net.IP, 16)
		for i := 0; i < 8; i++ {
			ip[i] = byte(b.data >> (8 * (7 - i)))
		}
		return ip
	}

	// IPv4
	ip := make(net.IP, 4)
	for i := 0; i < 3; i++ {
		ip[i] = byte(b.data >> (8 * (2 - i)))
	}
	return ip.To4()
}

func KeyToHash(keyRaw interface{}) (uint64, uint64) {
	key := keyRaw.(IPBlock)
	return key.data, 0
}
