# tcpip

A lightweight Go package for parsing, validating, encoding, and decoding TCP/IP protocol headers.

The package provides simple, low-level APIs for working directly with network packet bytes. It is designed for applications that need to inspect or construct IPv4, IPv6, TCP, and UDP headers without unnecessary data copying.

## Features

* IPv4 header parsing and encoding
* IPv6 header parsing and encoding
* TCP header parsing and encoding
* UDP header parsing and encoding
* Packet length validation
* Protocol and flag constants
* Zero-copy access to packet headers using byte slices
* Validation of header and packet boundaries
* Descriptive errors for malformed packets

## Installation

```bash
go get github.com/sina-ghaderi/tcpip
```

## Usage

### Parse an IPv4 Header

An IPv4 packet contains an IPv4 header followed by a payload. The header provides important information such as the source address, destination address, and the protocol carried by the packet.

```go
hdr, err := tcpip.NewIPv4Header(packet)
if err != nil {
    return err
}

src := hdr.SrcAddr()
dst := hdr.DstAddr()
proto := hdr.Protocol()
```

`NewIPv4Header` parses the IPv4 header directly from the provided byte slice. Before returning the header, the package validates the available buffer and the IPv4 header fields to make sure the packet is large enough and contains a valid header.

The returned header can then be used to access individual fields.

#### Source Address

```go
src := hdr.SrcAddr()
```

`SrcAddr()` returns the source IPv4 address. This identifies the host that sent the packet.

For example:

```text
192.168.1.10
```

#### Destination Address

```go
dst := hdr.DstAddr()
```

`DstAddr()` returns the destination IPv4 address. This identifies the host that should receive the packet.

For example:

```text
8.8.8.8
```

#### Protocol

```go
proto := hdr.Protocol()
```

`Protocol()` returns the protocol identifier stored in the IPv4 header. This field tells the receiver what type of data follows the IPv4 header.

Common protocol values include:

```text
ICMP  = 1
TCP   = 6
UDP   = 17
```

For example, when the protocol is TCP, the packet can be interpreted as:

```text
IPv4 Header
    |
    +-- TCP Header
            |
            +-- TCP Data
```

This makes it possible to parse a packet layer by layer.

### Parse a TCP Header

A TCP segment consists of a TCP header followed by optional application data. The TCP header contains information such as source and destination ports, sequence numbers, acknowledgment information, and control flags.

```go
tcpHdr, err := tcpip.NewTCPHeader(segment)
if err != nil {
    return err
}

srcPort := tcpHdr.SrcPort()
dstPort := tcpHdr.DstPort()
flags := tcpHdr.Flags()
```

`NewTCPHeader` interprets the provided byte slice as a TCP header and validates that enough data is available before allowing the header to be accessed.

#### Source Port

```go
srcPort := tcpHdr.SrcPort()
```

`SrcPort()` returns the TCP source port.

For example:

```text
Source port: 51532
```

The source port normally identifies the application or connection that sent the TCP segment.

#### Destination Port

```go
dstPort := tcpHdr.DstPort()
```

`DstPort()` returns the TCP destination port.

For example:

```text
Destination port: 443
```

Port `443` is commonly used for HTTPS traffic.

A TCP connection may therefore look like:

```text
192.168.1.10:51532 -> 142.250.x.x:443
```

#### TCP Flags

```go
flags := tcpHdr.Flags()
```

`Flags()` returns the control flags contained in the TCP header.

TCP commonly uses flags such as:

```text
SYN
ACK
FIN
RST
PSH
URG
```

These flags are used to control the TCP connection.

For example, a typical TCP connection starts with a three-way handshake:

```text
Client -> Server: SYN
Server -> Client: SYN + ACK
Client -> Server: ACK
```

Reading the TCP flags allows applications such as packet analyzers and network debugging tools to determine the state and purpose of individual TCP segments.

## Build a UDP Header

Unlike the previous examples, which parse existing network data, this example creates a UDP header from a byte slice.

A UDP header has a fixed size of 8 bytes and contains:

```text
+-------------------+
| Source Port       |
+-------------------+
| Destination Port  |
+-------------------+
| Length            |
+-------------------+
| Checksum          |
+-------------------+
```

A UDP packet can then be represented as:

```text
+-------------------+
| UDP Header        |
|     8 bytes       |
+-------------------+
| UDP Payload       |
+-------------------+
```

The following example creates an empty UDP header:

```go
buf := make([]byte, tcpip.FixUDPHdrLen)

udp := tcpip.UDPHeader(buf)
udp.SetSrcPort(12345)
udp.SetDstPort(53)
udp.SetTotalLen(uint16(len(buf)))
```

### Allocate the Header Buffer

```go
buf := make([]byte, tcpip.FixUDPHdrLen)
```

This allocates enough space for a fixed-size UDP header.

`FixUDPHdrLen` represents the size of the UDP header, which is 8 bytes.

Initially, the buffer contains empty header fields. The UDP header API allows those fields to be populated directly in the buffer.

### Create the UDP Header

```go
udp := tcpip.UDPHeader(buf)
```

This interprets the byte slice as a UDP header.

The package is designed to work directly with byte slices, which allows header fields to be read or written without creating unnecessary copies of the packet data.

### Set the Source Port

```go
udp.SetSrcPort(12345)
```

This writes `12345` into the UDP source-port field.

The source port identifies the application or connection sending the UDP datagram.

### Set the Destination Port

```go
udp.SetDstPort(53)
```

This writes `53` into the destination-port field.

Port `53` is commonly used by DNS servers, so this could represent a UDP datagram being sent to a DNS service.

### Set the Total Length

```go
udp.SetTotalLen(uint16(len(buf)))
```

The UDP length field represents the total size of the UDP datagram, including both the UDP header and its payload.

For example:

```text
UDP Header  = 8 bytes
Payload     = 20 bytes
-----------------------
Total       = 28 bytes
```

Therefore, when a payload is present, the total UDP length must include the payload as well.

The example above allocates only the fixed UDP header, so `len(buf)` is equal to the header size.

## Packet Structure

The package can be used to process packets layer by layer.

For example, a typical IPv4/TCP packet has the following structure:

```text
+---------------------------+
| IPv4 Header               |
|                           |
| Source IP                 |
| Destination IP            |
| Protocol = TCP            |
+---------------------------+
| TCP Header                |
|                           |
| Source Port               |
| Destination Port          |
| Flags                     |
+---------------------------+
| TCP Payload               |
+---------------------------+
```

A UDP packet follows a similar structure:

```text
+---------------------------+
| IPv4 Header               |
| Protocol = UDP            |
+---------------------------+
| UDP Header                |
|                           |
| Source Port               |
| Destination Port          |
| Length                    |
| Checksum                  |
+---------------------------+
| UDP Payload               |
+---------------------------+
```

This allows the package to be used to inspect a packet progressively:

```text
Packet
  |
  +-- IPv4 Header
          |
          +-- Protocol = TCP
                  |
                  +-- TCP Header
                          |
                          +-- TCP Payload
```

## Validation

The package validates packet data before exposing header fields.

Validation includes:

* Header versions
* Header lengths
* Packet lengths
* Buffer boundaries
* Minimum header sizes
* Protocol-specific header requirements

Malformed or truncated packets return descriptive errors instead of allowing the caller to access data outside the provided buffer.

For example, if a buffer is shorter than the minimum IPv4 header size, parsing the packet will fail rather than reading beyond the end of the slice.

This is particularly useful when processing untrusted network traffic, where packets may be incomplete, malformed, or intentionally crafted with invalid lengths.

## Zero-Copy Access

The package operates directly on byte slices whenever possible.

For example:

```go
udp := tcpip.UDPHeader(buf)
```

The UDP header can access the data already stored in `buf` instead of requiring a separate copy of the header.

This approach can reduce memory allocations and unnecessary data movement, which is useful when processing a large number of packets.

The same design can be used when parsing packets received from a network interface or another packet-processing system.

## Encoding and Decoding

The package supports both directions of packet processing.

### Decoding

Decoding means interpreting existing bytes as protocol headers:

```text
[]byte
  |
  +-- IPv4Header
  |
  +-- TCPHeader
  |
  +-- UDPHeader
```

This is useful for packet inspection, network monitoring, debugging, and protocol analysis.

### Encoding

Encoding means creating protocol headers from Go values:

```text
Go values
   |
   +-- Source port
   +-- Destination port
   +-- Length
          |
          v
      []byte packet
```

This is useful for applications that need to construct network packets or protocol messages.

## Testing

Run the complete test suite with:

```bash
go test ./...
```

The tests verify parsing, encoding, validation, packet boundaries, and protocol-specific behavior.

## License

Apache License Version 2.0, January 2004
