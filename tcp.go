package tcpip

import (
	"encoding/binary"
	"errors"
)

const (
	TCPFlagFIN = 1 << iota // TCPFlagFIN identifies the TCP FIN flag.
	TCPFlagSYN             // TCPFlagSYN identifies the TCP SYN flag.
	TCPFlagRST             // TCPFlagRST identifies the TCP RST flag.
	TCPFlagPSH             // TCPFlagPSH identifies the TCP PSH flag.
	TCPFlagACK             // TCPFlagACK identifies the TCP ACK flag.
	TCPFlagURG             // TCPFlagURG identifies the TCP URG flag.
)

// MinTCPHdrLen is the minimum TCP header length in bytes.
const MinTCPHdrLen = 0x14

// MaxTCPHdrLen is the maximum TCP header length in bytes.
const MaxTCPHdrLen = 0x3c

func be16(b []byte) uint16        { return binary.BigEndian.Uint16(b) }
func be32(b []byte) uint32        { return binary.BigEndian.Uint32(b) }
func setbe16(b []byte, pv uint16) { binary.BigEndian.PutUint16(b, pv) }
func setbe32(b []byte, pv uint32) { binary.BigEndian.PutUint32(b, pv) }

// TCPHeader represents a TCP header backed by a byte slice.
type TCPHeader []byte

// TCPHeaderInfo stores the decoded fields of a TCP header.
type TCPHeaderInfo struct {
	seqNum        uint32
	ackNum        uint32
	srcPort       uint16
	dstPort       uint16
	dataOffset    uint16
	windowSize    uint16
	checksum      uint16
	urgentPointer uint16
	flags         uint16
	hdrLen        uint8
}

// SetSrcPort sets the TCP source port.
func (h TCPHeader) SetSrcPort(v uint16) { setbe16(h[0:2], v) }

// SetDstPort sets the TCP destination port.
func (h TCPHeader) SetDstPort(v uint16) { setbe16(h[2:4], v) }

// SetSeq sets the TCP sequence number.
func (h TCPHeader) SetSeq(v uint32) { setbe32(h[4:8], v) }

// SetAck sets the TCP acknowledgment number.
func (h TCPHeader) SetAck(v uint32) { setbe32(h[8:12], v) }

// SetWindowSize sets the TCP receive window size.
func (h TCPHeader) SetWindowSize(v uint16) { setbe16(h[14:16], v) }

// SetChecksum sets the TCP checksum.
func (h TCPHeader) SetChecksum(v uint16) { setbe16(h[16:18], v) }

// SetUrgentPtr sets the TCP urgent pointer.
func (h TCPHeader) SetUrgentPtr(v uint16) { setbe16(h[18:20], v) }

// SetHdrLen sets the TCP header length in bytes.
func (h TCPHeader) SetHdrLen(v uint8) {
	v = ((v >> 2) & 0x0f) << 4
	h[12] = (h[12] & 0x0f) | v
}

// SetFlags sets the TCP control flags.
func (h TCPHeader) SetFlags(v uint16) {
	v &= 0x0fff
	h[12] = (h[12] & 0xf0) | uint8(v>>8)
	h[13] = uint8(v)
}

// SrcPort returns the TCP source port.
func (h TCPHeader) SrcPort() uint16 { return be16(h[0:2]) }

// DstPort returns the TCP destination port.
func (h TCPHeader) DstPort() uint16 { return be16(h[2:4]) }

// Seq returns the TCP sequence number.
func (h TCPHeader) Seq() uint32 { return be32(h[4:8]) }

// Ack returns the TCP acknowledgment number.
func (h TCPHeader) Ack() uint32 { return be32(h[8:12]) }

// HdrLen returns the TCP header length in bytes.
func (h TCPHeader) HdrLen() uint8 { return (h[12] >> 4) << 2 }

// WindowSize returns the TCP receive window size.
func (h TCPHeader) WindowSize() uint16 { return be16(h[14:16]) }

// Checksum returns the TCP checksum.
func (h TCPHeader) Checksum() uint16 { return be16(h[16:18]) }

// UrgentPtr returns the TCP urgent pointer.
func (h TCPHeader) UrgentPtr() uint16 { return be16(h[18:20]) }

// FlagIsSet reports whether all bits in the specified TCP flags are set.
func (h TCPHeader) FlagIsSet(x uint16) bool { return h.Flags()&x == x }

// Flags returns the TCP control flags.
func (h TCPHeader) Flags() uint16 {
	d := uint16(h[12]&0x0f) << 8
	return d | uint16(h[13])
}

// NewTCPHeader validates a byte slice and returns it as a TCP header.
func NewTCPHeader(b []byte) (TCPHeader, error) {

	h := TCPHeader(b)

	if len(b) < MinTCPHdrLen {
		return h, ErrShortBuffer
	}

	if h.HdrLen() < MinTCPHdrLen {
		return h, errors.New("invalid tcp header lenght")
	}

	if len(b) < int(h.HdrLen()) {
		return h, ErrShortBuffer
	}

	return h, nil
}

// SrcPort returns the decoded TCP source port.
func (h *TCPHeaderInfo) SrcPort() uint16 { return h.srcPort }

// DstPort returns the decoded TCP destination port.
func (h *TCPHeaderInfo) DstPort() uint16 { return h.dstPort }

// Seq returns the decoded TCP sequence number.
func (h *TCPHeaderInfo) Seq() uint32 { return h.seqNum }

// Ack returns the decoded TCP acknowledgment number.
func (h *TCPHeaderInfo) Ack() uint32 { return h.ackNum }

// HdrLen returns the decoded TCP header length.
func (h *TCPHeaderInfo) HdrLen() uint8 { return h.hdrLen }

// WindowSize returns the decoded TCP receive window size.
func (h *TCPHeaderInfo) WindowSize() uint16 { return h.windowSize }

// Checksum returns the decoded TCP checksum.
func (h *TCPHeaderInfo) Checksum() uint16 { return h.checksum }

// UrgentPtr returns the decoded TCP urgent pointer.
func (h *TCPHeaderInfo) UrgentPtr() uint16 { return h.urgentPointer }

// FlagIsSet reports whether all bits in the specified TCP flags are set.
func (h *TCPHeaderInfo) FlagIsSet(x uint16) bool { return h.flags&x == x }

// Flags returns the decoded TCP control flags.
func (h *TCPHeaderInfo) Flags() uint16 { return h.flags }

// SetSrcPort sets the TCP source port in the header information.
func (h *TCPHeaderInfo) SetSrcPort(v uint16) { h.srcPort = v }

// SetDstPort sets the TCP destination port in the header information.
func (h *TCPHeaderInfo) SetDstPort(v uint16) { h.dstPort = v }

// SetSeq sets the TCP sequence number in the header information.
func (h *TCPHeaderInfo) SetSeq(v uint32) { h.seqNum = v }

// SetAck sets the TCP acknowledgment number in the header information.
func (h *TCPHeaderInfo) SetAck(v uint32) { h.ackNum = v }

// SetHdrLen sets the TCP header length in the header information.
func (h *TCPHeaderInfo) SetHdrLen(v uint8) { h.hdrLen = v }

// SetWindowSize sets the TCP receive window size in the header information.
func (h *TCPHeaderInfo) SetWindowSize(v uint16) { h.windowSize = v }

// SetChecksum sets the TCP checksum in the header information.
func (h *TCPHeaderInfo) SetChecksum(v uint16) { h.checksum = v }

// SetUrgentPtr sets the TCP urgent pointer in the header information.
func (h *TCPHeaderInfo) SetUrgentPtr(v uint16) { h.urgentPointer = v }

// SetFlags sets the TCP control flags in the header information.
func (h *TCPHeaderInfo) SetFlags(v uint16) { h.flags = v }

// Encode serializes the TCP header information into the provided buffer.
func (h *TCPHeaderInfo) Encode(b []byte) error {

	if len(b) < MinTCPHdrLen {
		return ErrShortBuffer
	}

	switch {
	case h.HdrLen() < MinTCPHdrLen:
		fallthrough
	case h.HdrLen() > MaxTCPHdrLen:
		return errors.New("invalid tcp header lenght")
	}

	if len(b) < int(h.HdrLen()) {
		return ErrShortBuffer
	}

	tcpHdr := TCPHeader(b)
	tcpHdr.SetSrcPort(h.srcPort)
	tcpHdr.SetDstPort(h.dstPort)
	tcpHdr.SetSeq(h.seqNum)
	tcpHdr.SetAck(h.ackNum)
	tcpHdr.SetHdrLen(h.hdrLen)
	tcpHdr.SetWindowSize(h.windowSize)
	tcpHdr.SetChecksum(h.checksum)
	tcpHdr.SetUrgentPtr(h.urgentPointer)
	tcpHdr.SetFlags(h.flags)
	return nil
}

// Decode parses a TCP header from the provided buffer into the header information.
func (h *TCPHeaderInfo) Decode(b []byte) error {

	tcpHdr, err := NewTCPHeader(b)
	if err != nil {
		return err
	}

	h.srcPort = tcpHdr.SrcPort()
	h.dstPort = tcpHdr.DstPort()
	h.seqNum = tcpHdr.Seq()
	h.ackNum = tcpHdr.Ack()
	h.hdrLen = tcpHdr.HdrLen()
	h.windowSize = tcpHdr.WindowSize()
	h.checksum = tcpHdr.Checksum()
	h.urgentPointer = tcpHdr.UrgentPtr()
	h.flags = tcpHdr.Flags()
	return err
}
