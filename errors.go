package tcpip

import "errors"

// ErrShortBuffer indicates that the provided packet buffer is too short.
var ErrShortBuffer = errors.New("short packet")
