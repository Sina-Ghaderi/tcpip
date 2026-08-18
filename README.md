# tcpip

A lightweight Go package for parsing, validating, encoding, and decoding TCP/IP protocol headers.

## Features

* IPv4 header parsing and encoding
* IPv6 header parsing and encoding
* TCP header parsing and encoding
* UDP header parsing and encoding
* Packet length validation
* Protocol and flag constants
* Zero-copy access to packet headers using byte slices

## Installation

```bash
go get github.com/sina-ghaderi/tcpip
```

## Usage

### Parse an IPv4 Header

```go
hdr, err := tcpip.NewIPv4Header(packet)
if err != nil {
    return err
}

src := hdr.SrcAddr()
dst := hdr.DstAddr()
proto := hdr.Protocol()
```

### Parse a TCP Header

```go
tcpHdr, err := tcpip.NewTCPHeader(segment)
if err != nil {
    return err
}

srcPort := tcpHdr.SrcPort()
dstPort := tcpHdr.DstPort()
flags := tcpHdr.Flags()
```

### Build a UDP Header

```go
buf := make([]byte, tcpip.FixUDPHdrLen)

udp := tcpip.UDPHeader(buf)
udp.SetSrcPort(12345)
udp.SetDstPort(53)
udp.SetTotalLen(uint16(len(buf)))
```


## Validation

The package validates:

* Header versions
* Header lengths
* Packet lengths
* Buffer boundaries

Invalid packets return descriptive errors.

## Testing

```bash
go test ./...
```

## License
Apache License Version 2.0, January 2004