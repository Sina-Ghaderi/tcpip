package tcpip

import (
	"errors"
)

// FixUDPHdrLen is the fixed UDP header length in bytes.
const FixUDPHdrLen = 0x08

// UDPHeader represents a UDP header backed by a byte slice.
type UDPHeader []byte

// UDPHeaderInfo stores the decoded fields of a UDP header.
type UDPHeaderInfo struct {
	srcPort  uint16
	dstPort  uint16
	totalLen uint16
	checksum uint16
}

// SrcPort returns the UDP source port.
func (h UDPHeader) SrcPort() uint16 { return be16(h[0:2]) }

// DstPort returns the UDP destination port.
func (h UDPHeader) DstPort() uint16 { return be16(h[2:4]) }

// TotalLen returns the total UDP packet length.
func (h UDPHeader) TotalLen() uint16 { return be16(h[4:6]) }

// Checksum returns the UDP checksum.
func (h UDPHeader) Checksum() uint16 { return be16(h[6:8]) }

// SetSrcPort sets the UDP source port.
func (h UDPHeader) SetSrcPort(v uint16) { setbe16(h[0:2], v) }

// SetDstPort sets the UDP destination port.
func (h UDPHeader) SetDstPort(v uint16) { setbe16(h[2:4], v) }

// SetTotalLen sets the total UDP packet length.
func (h UDPHeader) SetTotalLen(v uint16) { setbe16(h[4:6], v) }

// SetChecksum sets the UDP checksum.
func (h UDPHeader) SetChecksum(v uint16) { setbe16(h[6:8], v) }

// SrcPort returns the decoded UDP source port.
func (h *UDPHeaderInfo) SrcPort() uint16 { return h.srcPort }

// DstPort returns the decoded UDP destination port.
func (h *UDPHeaderInfo) DstPort() uint16 { return h.dstPort }

// TotalLen returns the decoded total UDP packet length.
func (h *UDPHeaderInfo) TotalLen() uint16 { return h.totalLen }

// Checksum returns the decoded UDP checksum.
func (h *UDPHeaderInfo) Checksum() uint16 { return h.checksum }

// SetSrcPort sets the UDP source port in the header information.
func (h *UDPHeaderInfo) SetSrcPort(v uint16) { h.srcPort = v }

// SetDstPort sets the UDP destination port in the header information.
func (h *UDPHeaderInfo) SetDstPort(v uint16) { h.dstPort = v }

// SetTotalLen sets the total UDP packet length in the header information.
func (h *UDPHeaderInfo) SetTotalLen(v uint16) { h.totalLen = v }

// SetChecksum sets the UDP checksum in the header information.
func (h *UDPHeaderInfo) SetChecksum(v uint16) { h.checksum = v }

// NewUDPHeader validates a byte slice and returns it as a UDP header.
func NewUDPHeader(b []byte) (UDPHeader, error) {

	h := UDPHeader(b)

	if len(b) < FixUDPHdrLen {
		return h, ErrShortBuffer
	}

	totalLen := h.TotalLen()
	if totalLen < FixUDPHdrLen {
		return h, errors.New("invalid udp packet lenght")
	}

	if len(b) < int(totalLen) {
		return h, ErrShortBuffer
	}

	return h, nil

}

// Encode serializes the UDP header information into the provided buffer.
func (h *UDPHeaderInfo) Encode(b []byte) error {

	if len(b) < FixUDPHdrLen {
		return ErrShortBuffer
	}

	if h.TotalLen() < FixUDPHdrLen {
		return errors.New("invalid udp packet lenght")
	}

	if len(b) < int(h.TotalLen()) {
		return ErrShortBuffer
	}

	udpHdr := UDPHeader(b)
	udpHdr.SetSrcPort(h.srcPort)
	udpHdr.SetDstPort(h.dstPort)
	udpHdr.SetChecksum(h.checksum)
	udpHdr.SetTotalLen(h.totalLen)
	return nil
}

// Decode parses a UDP header from the provided buffer into the header information.
func (h *UDPHeaderInfo) Decode(b []byte) error {

	udpHdr, err := NewUDPHeader(b)
	if err != nil {
		return err
	}

	h.srcPort = udpHdr.SrcPort()
	h.dstPort = udpHdr.DstPort()
	h.checksum = udpHdr.Checksum()
	h.totalLen = udpHdr.TotalLen()
	return err
}
