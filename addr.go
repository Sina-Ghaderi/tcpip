package tcpip

import (
	"errors"
)

// IPv4AddrLen is the length of an IPv6 address in bytes.
const IPv4AddrLen = 0x04

// IPv6AddrLen is the length of an IPv6 address in bytes.
const IPv6AddrLen = 0x10

// Addr represents an IPv6-sized IP address.
type Addr [16]byte

const (
	IPv4 = 0x04 // IPv4 identifies the IPv4 protocol version.
	IPv6 = 0x06 // IPv6 identifies the IPv6 protocol version.
)

// MinIPv4HdrLen is the minimum valid IPv4 header length in bytes.
const MinIPv4HdrLen = 0x14

// MaxIPv4HdrLen is the maximum IPv4 header length in bytes.
const MaxIPv4HdrLen = 0x3c

// FixIPv6HdrLen is the fixed IPv6 base header length in bytes.
const FixIPv6HdrLen = 0x28

const (
	ProtoTCP = 0x06 // ProtoTCP identifies TCP as an IP payload protocol.
	ProtoUDP = 0x11 // ProtoUDP identifies UDP as an IP payload protocol.
)

const (
	// IPv4FlagMF identifies the IPv4 More Fragments flag.
	IPv4FlagMF = 1 << iota
	// IPv4FlagDF identifies the IPv4 Don't Fragment flag.
	IPv4FlagDF
)

// Version returns the IP version encoded in the first byte of an IP header.
func Version(b []byte) (v uint8, err error) {
	if len(b) < 1 {
		return v, ErrShortBuffer
	}

	v = b[0] >> 4
	if v == IPv4 || v == IPv6 {
		return
	}

	return v, errors.New("invalid ip header version")
}

// TotalLen returns the total length of an IPv4 or IPv6 packet.
func TotalLen(b []byte) (int, error) {

	ipv, err := Version(b)
	if err != nil {
		return 0, err
	}

	if ipv == IPv4 {
		return IPv4TotalLen(b)
	} else {
		return IPv6TotalLen(b)
	}
}

// IPv4TotalLen validates an IPv4 header and returns the packet's total length.
func IPv4TotalLen(b []byte) (int, error) {

	if len(b) < MinIPv4HdrLen {
		return 0, ErrShortBuffer
	}

	var err error

	totalLen, hdrLen := be16(b[2:4]), (b[0]&0x0f)<<2

	switch {
	case hdrLen < MinIPv4HdrLen:
		err = errors.New("invalid ipv4 header length")
		totalLen = 0
	case totalLen < uint16(hdrLen):
		err = errors.New("invalid ipv4 packet length")
		totalLen = 0
	case len(b) < int(totalLen):
		err = ErrShortBuffer
	}

	return int(totalLen), err
}

// IPv6TotalLen validates an IPv6 base header and returns the packet's total length.
func IPv6TotalLen(b []byte) (int, error) {

	if len(b) < FixIPv6HdrLen {
		return 0, ErrShortBuffer
	}

	totalLen := FixIPv6HdrLen + int(be16(b[4:6]))
	if len(b) < totalLen {
		return totalLen, ErrShortBuffer
	}

	if totalLen > int(^uint16(0)) {
		return 0, errors.New("invalid ipv6 packet length")
	}

	return totalLen, nil
}
