package decoders

import (
	"encoding/binary"
	"net"
	"unsafe"
)

type FastHardwareAddr net.HardwareAddr

func (a FastHardwareAddr) String() string {
	const hexDigit = "0123456789abcdef"
	if len(a) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(a)*3-1)
	for i, b := range a {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return FastBytes2String(buf)
}

func Ip2String(isIp6 bool, ip4 uint32, ip6 []byte) string {
	if isIp6 {
		return net.IP(ip6[:]).String()
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip4)
	return net.IP(b[:]).String()
}

func FastBytes2String(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
