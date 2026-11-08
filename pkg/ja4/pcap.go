package ja4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	ErrInvalidPCAPMagic   = errors.New("invalid or unsupported PCAP magic number")
	ErrUnsupportedLink    = errors.New("unsupported link layer type")
	ErrTruncatedPacket    = errors.New("packet data truncated")
	ErrUnsupportedNetwork = errors.New("unsupported network layer")
)

const (
	PCAPMagicSameEndian     uint32 = 0xa1b2c3d4
	PCAPMagicSwappedEndian  uint32 = 0xd4c3b2a1
	PCAPMagicNanoSameEndian uint32 = 0xa1b23c4d
	PCAPMagicNanoSwapped    uint32 = 0x4d3cb2a1

	LinkTypeEthernet = 1
	LinkTypeRawIP    = 12
	LinkTypeLinuxSLL = 113

	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86dd
	EtherTypeVLAN = 0x8100

	IPProtoTCP = 6
	IPProtoUDP = 17
)

// Packet represents a parsed network packet from PCAP.
type Packet struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TCPFlags  uint8
	SeqNum    uint32
	AckNum    uint32
	Payload   []byte
}

// PCAPReader provides streaming access to packet records in a PCAP capture.
type PCAPReader struct {
	r          io.Reader
	order      binary.ByteOrder
	nano       bool
	LinkType   uint32
	SnapLen    uint32
	packetBuf  []byte
	headerBuf  [16]byte
}

// NewPCAPReader initializes a zero-allocation streaming PCAP reader.
func NewPCAPReader(r io.Reader) (*PCAPReader, error) {
	var ghdr [24]byte
	if _, err := io.ReadFull(r, ghdr[:]); err != nil {
		return nil, fmt.Errorf("failed to read PCAP global header: %w", err)
	}

	magic := binary.BigEndian.Uint32(ghdr[0:4])
	var order binary.ByteOrder
	nano := false

	switch magic {
	case PCAPMagicSameEndian:
		order = binary.BigEndian
	case PCAPMagicSwappedEndian:
		order = binary.LittleEndian
	case PCAPMagicNanoSameEndian:
		order = binary.BigEndian
		nano = true
	case PCAPMagicNanoSwapped:
		order = binary.LittleEndian
		nano = true
	default:
		// Check little-endian interpretation
		magicLE := binary.LittleEndian.Uint32(ghdr[0:4])
		if magicLE == PCAPMagicSameEndian {
			order = binary.LittleEndian
		} else if magicLE == PCAPMagicNanoSameEndian {
			order = binary.LittleEndian
			nano = true
		} else {
			return nil, ErrInvalidPCAPMagic
		}
	}

	snapLen := order.Uint32(ghdr[16:20])
	linkType := order.Uint32(ghdr[20:24])

	return &PCAPReader{
		r:         r,
		order:     order,
		nano:      nano,
		LinkType:  linkType,
		SnapLen:   snapLen,
		packetBuf: make([]byte, 65536),
	}, nil
}

// NextPacket reads and decodes the next network packet.
func (pr *PCAPReader) NextPacket() (*Packet, error) {
	for {
		if _, err := io.ReadFull(pr.r, pr.headerBuf[:]); err != nil {
			return nil, err // io.EOF when stream concludes
		}

		tsSec := pr.order.Uint32(pr.headerBuf[0:4])
		tsSub := pr.order.Uint32(pr.headerBuf[4:8])
		inclLen := int(pr.order.Uint32(pr.headerBuf[8:12]))

		if inclLen < 0 || inclLen > 262144 {
			return nil, ErrTruncatedPacket
		}

		if len(pr.packetBuf) < inclLen {
			pr.packetBuf = make([]byte, inclLen)
		}

		raw := pr.packetBuf[:inclLen]
		if _, err := io.ReadFull(pr.r, raw); err != nil {
			return nil, err
		}

		var ts time.Time
		if pr.nano {
			ts = time.Unix(int64(tsSec), int64(tsSub))
		} else {
			ts = time.Unix(int64(tsSec), int64(tsSub)*1000)
		}

		pkt, err := pr.dissect(raw, ts)
		if err != nil {
			// Skip unrecognized non-IP / non-TCP frame and continue
			continue
		}

		return pkt, nil
	}
}

func (pr *PCAPReader) dissect(raw []byte, ts time.Time) (*Packet, error) {
	var ipData []byte

	switch pr.LinkType {
	case LinkTypeEthernet:
		if len(raw) < 14 {
			return nil, ErrTruncatedPacket
		}
		etherType := binary.BigEndian.Uint16(raw[12:14])
		offset := 14
		if etherType == EtherTypeVLAN {
			if len(raw) < 18 {
				return nil, ErrTruncatedPacket
			}
			etherType = binary.BigEndian.Uint16(raw[16:18])
			offset = 18
		}
		if etherType != EtherTypeIPv4 && etherType != EtherTypeIPv6 {
			return nil, ErrUnsupportedNetwork
		}
		ipData = raw[offset:]

	case LinkTypeLinuxSLL:
		if len(raw) < 16 {
			return nil, ErrTruncatedPacket
		}
		protoType := binary.BigEndian.Uint16(raw[14:16])
		if protoType != EtherTypeIPv4 && protoType != EtherTypeIPv6 {
			return nil, ErrUnsupportedNetwork
		}
		ipData = raw[16:]

	case LinkTypeRawIP:
		ipData = raw

	default:
		return nil, ErrUnsupportedLink
	}

	if len(ipData) == 0 {
		return nil, ErrTruncatedPacket
	}

	version := ipData[0] >> 4
	var srcIP, dstIP net.IP
	var protocol uint8
	var tcpData []byte

	if version == 4 {
		if len(ipData) < 20 {
			return nil, ErrTruncatedPacket
		}
		ihl := int(ipData[0]&0x0f) * 4
		if len(ipData) < ihl || ihl < 20 {
			return nil, ErrTruncatedPacket
		}
		protocol = ipData[9]
		srcIP = net.IP(ipData[12:16])
		dstIP = net.IP(ipData[16:20])
		tcpData = ipData[ihl:]
	} else if version == 6 {
		if len(ipData) < 40 {
			return nil, ErrTruncatedPacket
		}
		protocol = ipData[6]
		srcIP = net.IP(ipData[8:24])
		dstIP = net.IP(ipData[24:40])
		tcpData = ipData[40:]
	} else {
		return nil, ErrUnsupportedNetwork
	}

	if protocol != IPProtoTCP || len(tcpData) < 20 {
		return nil, ErrUnsupportedNetwork
	}

	srcPort := binary.BigEndian.Uint16(tcpData[0:2])
	dstPort := binary.BigEndian.Uint16(tcpData[2:4])
	seq := binary.BigEndian.Uint32(tcpData[4:8])
	ack := binary.BigEndian.Uint32(tcpData[8:12])
	dataOffset := int((tcpData[12]>>4)&0x0f) * 4
	if len(tcpData) < dataOffset || dataOffset < 20 {
		return nil, ErrTruncatedPacket
	}
	flags := tcpData[13]
	payload := tcpData[dataOffset:]

	return &Packet{
		Timestamp: ts,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		TCPFlags:  flags,
		SeqNum:    seq,
		AckNum:    ack,
		Payload:   payload,
	}, nil
}
