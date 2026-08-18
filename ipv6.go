package tcpip

import (
	"errors"
	"unsafe"
)

// IPv6Header represents an IPv6 base header backed by a byte slice.
type IPv6Header []byte

// IPv6HeaderInfo stores the decoded fields of an IPv6 header.
type IPv6HeaderInfo struct {
	srcAddr      Addr
	dstAddr      Addr
	flowLabel    uint32
	payloadLen   uint16
	nextHeader   uint8
	hopLimit     uint8
	version      uint8
	trafficClass uint8
}

// Version returns the IPv6 version field.
func (h IPv6Header) Version() uint8 { return uint8(h[0] >> 4) }

// TrafficClass returns the IPv6 traffic class field.
func (h IPv6Header) TrafficClass() uint8 {
	return (h[0] << 4) | (h[1] >> 4)
}

// FlowLabel returns the IPv6 flow label.
func (h IPv6Header) FlowLabel() uint32 {
	return uint32(h[1]&0x0f)<<16 | uint32(h[2])<<8 | uint32(h[3])
}

// PayloadLen returns the IPv6 payload length.
func (h IPv6Header) PayloadLen() uint16 { return be16(h[4:6]) }

// HopLimit returns the IPv6 hop limit.
func (h IPv6Header) HopLimit() uint8 { return h[7] }

// NextHeader returns the protocol identifier of the next IPv6 header.
func (h IPv6Header) NextHeader() uint8 { return h[6] }

// SrcAddr returns the source IPv6 address bytes.
func (h IPv6Header) SrcAddr() (addr []byte) { return h[0x08:0x18] }

// DstAddr returns the destination IPv6 address bytes.
func (h IPv6Header) DstAddr() (addr []byte) { return h[0x18:0x28] }

// SetVersion sets the IPv6 version field.
func (h IPv6Header) SetVersion(v uint8) {
	h[0] = (h[0] & 0x0f) | ((v & 0x0f) << 4)
}

// SetTrafficClass sets the IPv6 traffic class field.
func (h IPv6Header) SetTrafficClass(v uint8) {
	h[0] = (h[0] & 0xf0) | (v >> 4)
	h[1] = (h[1] & 0x0f) | (v << 4)
}

// SetFlowLabel sets the IPv6 flow label.
func (h IPv6Header) SetFlowLabel(v uint32) {
	v &= 0x000fffff
	h[1] = (h[1] & 0xf0) | uint8(v>>16)
	h[2], h[3] = uint8(v>>8), uint8(v)
}

// SetPayloadLen sets the IPv6 payload length.
func (h IPv6Header) SetPayloadLen(v uint16) { setbe16(h[4:6], v) }

// SetHopLimit sets the IPv6 hop limit.
func (h IPv6Header) SetHopLimit(v uint8) { h[7] = v }

// SetNextHeader sets the protocol identifier of the next IPv6 header.
func (h IPv6Header) SetNextHeader(v uint8) { h[6] = v }

// SetSrcAddr sets the source IPv6 address.
func (h IPv6Header) SetSrcAddr(addr []byte) {
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&h[0x08])), IPv6AddrLen), addr[:])
}

// SetDstAddr sets the destination IPv6 address.
func (h IPv6Header) SetDstAddr(addr []byte) {
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&h[0x18])), IPv6AddrLen), addr[:])
}

// NewIPv6Header validates a byte slice and returns it as an IPv6 header.
func NewIPv6Header(b []byte) (IPv6Header, error) {

	h := IPv6Header(b)

	switch {
	case len(b) < FixIPv6HdrLen:
		return h, ErrShortBuffer
	case b[0]>>4 != IPv6:
		return h, errors.New("invalid ipv6 header version")
	}

	totalLen := FixIPv6HdrLen + int(h.PayloadLen())
	if len(b) < totalLen {
		return h, ErrShortBuffer
	}

	return h, nil
}

// Version returns the decoded IPv6 version.
func (h *IPv6HeaderInfo) Version() uint8 { return h.version }

// TrafficClass returns the decoded IPv6 traffic class.
func (h *IPv6HeaderInfo) TrafficClass() uint8 { return h.trafficClass }

// FlowLabel returns the decoded IPv6 flow label.
func (h *IPv6HeaderInfo) FlowLabel() uint32 { return h.flowLabel }

// PayloadLen returns the decoded IPv6 payload length.
func (h *IPv6HeaderInfo) PayloadLen() uint16 { return h.payloadLen }

// HopLimit returns the decoded IPv6 hop limit.
func (h *IPv6HeaderInfo) HopLimit() uint8 { return h.hopLimit }

// NextHeader returns the decoded next-header protocol identifier.
func (h *IPv6HeaderInfo) NextHeader() uint8 { return h.nextHeader }

// SrcAddr returns the decoded source IPv6 address.
func (h *IPv6HeaderInfo) SrcAddr() Addr { return h.srcAddr }

// DstAddr returns the decoded destination IPv6 address.
func (h *IPv6HeaderInfo) DstAddr() Addr { return h.dstAddr }

// SetVersion sets the IPv6 version in the header information.
func (h *IPv6HeaderInfo) SetVersion(v uint8) { h.version = v }

// SetTrafficClass sets the IPv6 traffic class in the header information.
func (h *IPv6HeaderInfo) SetTrafficClass(v uint8) { h.trafficClass = v }

// SetFlowLabel sets the IPv6 flow label in the header information.
func (h *IPv6HeaderInfo) SetFlowLabel(v uint32) { h.flowLabel = v }

// SetPayloadLen sets the IPv6 payload length in the header information.
func (h *IPv6HeaderInfo) SetPayloadLen(v uint16) { h.payloadLen = v }

// SetHopLimit sets the IPv6 hop limit in the header information.
func (h *IPv6HeaderInfo) SetHopLimit(v uint8) { h.hopLimit = v }

// SetNextHeader sets the next-header protocol identifier in the header information.
func (h *IPv6HeaderInfo) SetNextHeader(v uint8) { h.nextHeader = v }

// SetSrcAddr sets the source IPv6 address in the header information.
func (h *IPv6HeaderInfo) SetSrcAddr(addr Addr) { h.srcAddr = addr }

// SetDstAddr sets the destination IPv6 address in the header information.
func (h *IPv6HeaderInfo) SetDstAddr(addr Addr) { h.dstAddr = addr }

// Decode parses an IPv6 header from the provided buffer into the header information.
func (h *IPv6HeaderInfo) Decode(b []byte) error {

	ipHdr, err := NewIPv6Header(b)
	if err != nil {
		return err
	}

	h.version = ipHdr.Version()
	h.trafficClass = ipHdr.TrafficClass()
	h.flowLabel = ipHdr.FlowLabel()
	h.payloadLen = ipHdr.PayloadLen()
	h.hopLimit = ipHdr.HopLimit()
	h.nextHeader = ipHdr.NextHeader()
	copy(h.srcAddr[:], ipHdr.SrcAddr())
	copy(h.dstAddr[:], ipHdr.DstAddr())
	return err
}

// Encode serializes the IPv6 header information into the provided buffer.
func (h *IPv6HeaderInfo) Encode(b []byte) error {

	switch {
	case len(b) < FixIPv6HdrLen:
		return ErrShortBuffer
	case h.version != IPv6:
		return errors.New("invalid ipv6 header version")
	}

	totalLen := FixIPv6HdrLen + int(h.PayloadLen())
	if len(b) < totalLen {
		return ErrShortBuffer
	}

	ipHdr := IPv6Header(b)
	ipHdr.SetVersion(h.version)
	ipHdr.SetTrafficClass(h.trafficClass)
	ipHdr.SetFlowLabel(h.flowLabel)
	ipHdr.SetPayloadLen(h.payloadLen)
	ipHdr.SetHopLimit(h.hopLimit)
	ipHdr.SetNextHeader(h.nextHeader)
	ipHdr.SetDstAddr(h.dstAddr[:])
	ipHdr.SetSrcAddr(h.srcAddr[:])
	return nil

}
