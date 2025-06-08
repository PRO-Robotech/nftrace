package headers

import (
	"encoding/binary"
	"net"

	"github.com/pkg/errors"
)

const (
	// MAC address length
	EthMACLength = 6
	// Link layer header length
	LlHeaderLen = 12
)

// Link layer header
type LinkHeader struct {
	SAddr    net.HardwareAddr
	DAddr    net.HardwareAddr
	Protocol uint16
}

// Decode - decode header from byte stream
func (h *LinkHeader) Decode(b []byte) error {
	if l := len(b); l < LlHeaderLen {
		return errors.Errorf("incorrect link layer header length=%d", l)
	}

	h.SAddr = make(net.HardwareAddr, EthMACLength)
	h.DAddr = make(net.HardwareAddr, EthMACLength)

	copy(h.DAddr, b[:6])
	copy(h.SAddr, b[6:12])

	h.Protocol = binary.BigEndian.Uint16(b[12:])

	return nil
}
