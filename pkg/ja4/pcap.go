package ja4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"
)

var (
	ErrInvalidPCAPMagic   = errors.New("invalid or unsupported PCAP magic number")
	ErrUnsupportedLink    = errors.New("unsupported link layer type")
	ErrTruncatedPacket    = errors.New("packet data truncated")
	ErrUnsupportedNetwork = errors.New("unsupported network layer")
	ErrMalformedPCAPNG    = errors.New("malformed PCAP-NG block")
)

const (
	CaptureFormatPCAP   = "pcap"
	CaptureFormatPCAPNG = "pcapng"

	PCAPMagicSameEndian     uint32 = 0xa1b2c3d4
	PCAPMagicSwappedEndian  uint32 = 0xd4c3b2a1
	PCAPMagicNanoSameEndian uint32 = 0xa1b23c4d
	PCAPMagicNanoSwapped    uint32 = 0x4d3cb2a1

	// PCAP-NG block types and magic.
	PCAPNGBlockSHB            uint32 = 0x0a0d0d0a
	PCAPNGBlockIDB            uint32 = 0x00000001
	PCAPNGBlockSPB            uint32 = 0x00000003
	PCAPNGBlockNRB            uint32 = 0x00000004
	PCAPNGBlockISB            uint32 = 0x00000005
	PCAPNGBlockEPB            uint32 = 0x00000006
	PCAPNGByteOrderMagic      uint32 = 0x1a2b3c4d
	PCAPNGOptEndOfOpt         uint16 = 0
	PCAPNGOptIfName           uint16 = 2
	PCAPNGOptIfTSResol        uint16 = 9
	maxPCAPNGBlockLen                = 16 * 1024 * 1024
	maxClassicPCAPPacketBytes        = 262144

	// Link-layer header types (DLT / LINKTYPE).
	LinkTypeNull      = 0
	LinkTypeEthernet  = 1
	LinkTypeRawIP     = 12
	LinkTypeRawIPAlt  = 101
	LinkTypeLinuxSLL  = 113
	LinkTypeLinuxSLL2 = 276

	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86dd
	EtherTypeVLAN = 0x8100
	EtherTypeQinQ = 0x88a8

	IPProtoHopByHop = 0
	IPProtoTCP      = 6
	IPProtoUDP      = 17
	IPProtoRouting  = 43
	IPProtoFragment = 44
	IPProtoDestOpts = 60

	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
)

// Packet represents a parsed network packet from PCAP or PCAP-NG.
type Packet struct {
	Timestamp   time.Time
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	TCPFlags    uint8
	SeqNum      uint32
	AckNum      uint32
	Payload     []byte
	InterfaceID uint32
}

// PCAPNGInterface describes a capture interface parsed from a PCAP-NG IDB block.
type PCAPNGInterface struct {
	ID       uint32
	Name     string
	LinkType uint32
	SnapLen  uint32
	TSResol  uint8 // Raw if_tsresol option value; default 6 (10^-6 s)
}

// PCAPReader provides streaming access to packet records in classic PCAP and PCAP-NG captures.
type PCAPReader struct {
	r          io.Reader
	Format     string
	order      binary.ByteOrder
	nano       bool
	LinkType   uint32
	SnapLen    uint32
	interfaces []PCAPNGInterface
	packetBuf  []byte
	headerBuf  [16]byte
}

// NewPCAPReader initializes a streaming capture reader, auto-detecting classic PCAP
// (microsecond/nanosecond, big/little endian) and PCAP-NG formats.
func NewPCAPReader(r io.Reader) (*PCAPReader, error) {
	var magicBuf [4]byte
	if _, err := io.ReadFull(r, magicBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read capture magic header: %w", err)
	}

	magicBE := binary.BigEndian.Uint32(magicBuf[:])
	if magicBE == PCAPNGBlockSHB {
		pr := &PCAPReader{
			r:         r,
			Format:    CaptureFormatPCAPNG,
			packetBuf: make([]byte, 65536),
		}
		if err := pr.readSHBAfterType(); err != nil {
			return nil, err
		}
		return pr, nil
	}

	var restHdr [20]byte
	if _, err := io.ReadFull(r, restHdr[:]); err != nil {
		return nil, fmt.Errorf("failed to read PCAP global header: %w", err)
	}

	var order binary.ByteOrder
	nano := false

	switch magicBE {
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
		magicLE := binary.LittleEndian.Uint32(magicBuf[:])
		if magicLE == PCAPMagicSameEndian {
			order = binary.LittleEndian
		} else if magicLE == PCAPMagicNanoSameEndian {
			order = binary.LittleEndian
			nano = true
		} else {
			return nil, ErrInvalidPCAPMagic
		}
	}

	snapLen := order.Uint32(restHdr[12:16])
	linkType := order.Uint32(restHdr[16:20])

	return &PCAPReader{
		r:         r,
		Format:    CaptureFormatPCAP,
		order:     order,
		nano:      nano,
		LinkType:  linkType,
		SnapLen:   snapLen,
		packetBuf: make([]byte, 65536),
	}, nil
}

// Interfaces returns a copy of parsed PCAP-NG interface descriptors.
func (pr *PCAPReader) Interfaces() []PCAPNGInterface {
	if len(pr.interfaces) == 0 {
		return nil
	}
	out := make([]PCAPNGInterface, len(pr.interfaces))
	copy(out, pr.interfaces)
	return out
}

func (pr *PCAPReader) readSHBAfterType() error {
	var shbPrefix [8]byte // blockTotalLen (4) + byteOrderMagic (4)
	if _, err := io.ReadFull(pr.r, shbPrefix[:]); err != nil {
		return fmt.Errorf("failed to read PCAP-NG section header: %w", err)
	}
	return pr.finishSHB(shbPrefix[0:4], shbPrefix[4:8])
}

func (pr *PCAPReader) finishSHB(lenRaw, bomRaw []byte) error {
	if binary.BigEndian.Uint32(bomRaw) == PCAPNGByteOrderMagic {
		pr.order = binary.BigEndian
	} else if binary.LittleEndian.Uint32(bomRaw) == PCAPNGByteOrderMagic {
		pr.order = binary.LittleEndian
	} else {
		return ErrInvalidPCAPMagic
	}

	blockTotalLen := pr.order.Uint32(lenRaw)
	if blockTotalLen < 28 || blockTotalLen > maxPCAPNGBlockLen || blockTotalLen%4 != 0 {
		return ErrMalformedPCAPNG
	}

	remaining := int(blockTotalLen) - 12
	if err := discardExact(pr.r, remaining); err != nil {
		return fmt.Errorf("truncated PCAP-NG section header: %w", err)
	}

	// New section resets interface list.
	pr.interfaces = pr.interfaces[:0]
	return nil
}

// NextPacket reads and decodes the next TCP/IP network packet from PCAP or PCAP-NG.
func (pr *PCAPReader) NextPacket() (*Packet, error) {
	if pr.Format == CaptureFormatPCAPNG {
		return pr.nextPCAPNGPacket()
	}
	return pr.nextClassicPacket()
}

func (pr *PCAPReader) nextClassicPacket() (*Packet, error) {
	for {
		if _, err := io.ReadFull(pr.r, pr.headerBuf[:]); err != nil {
			return nil, err
		}

		tsSec := pr.order.Uint32(pr.headerBuf[0:4])
		tsSub := pr.order.Uint32(pr.headerBuf[4:8])
		inclLen := int(pr.order.Uint32(pr.headerBuf[8:12]))

		if inclLen < 0 || inclLen > maxClassicPCAPPacketBytes {
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

		pkt, err := pr.dissect(raw, ts, pr.LinkType, 0)
		if err != nil {
			continue
		}

		return pkt, nil
	}
}

func (pr *PCAPReader) nextPCAPNGPacket() (*Packet, error) {
	var blkHdr [8]byte
	for {
		if _, err := io.ReadFull(pr.r, blkHdr[:]); err != nil {
			return nil, err
		}

		// SHB block type is palindromic (0x0a0d0d0a) and may change section endianness.
		if binary.BigEndian.Uint32(blkHdr[0:4]) == PCAPNGBlockSHB {
			var bom [4]byte
			if _, err := io.ReadFull(pr.r, bom[:]); err != nil {
				return nil, err
			}
			if err := pr.finishSHB(blkHdr[4:8], bom[:]); err != nil {
				return nil, err
			}
			continue
		}

		blockType := pr.order.Uint32(blkHdr[0:4])
		blockTotalLen := pr.order.Uint32(blkHdr[4:8])
		if blockTotalLen < 12 || blockTotalLen > maxPCAPNGBlockLen || blockTotalLen%4 != 0 {
			return nil, ErrMalformedPCAPNG
		}

		bodyAndTrailerLen := int(blockTotalLen) - 8
		if len(pr.packetBuf) < bodyAndTrailerLen {
			pr.packetBuf = make([]byte, bodyAndTrailerLen)
		}
		buf := pr.packetBuf[:bodyAndTrailerLen]
		if _, err := io.ReadFull(pr.r, buf); err != nil {
			return nil, err
		}

		body := buf[:bodyAndTrailerLen-4]
		trailerLen := pr.order.Uint32(buf[bodyAndTrailerLen-4:])
		if trailerLen != blockTotalLen {
			return nil, ErrMalformedPCAPNG
		}

		switch blockType {
		case PCAPNGBlockIDB:
			if len(body) < 8 {
				return nil, ErrMalformedPCAPNG
			}
			iface := PCAPNGInterface{
				ID:       uint32(len(pr.interfaces)),
				LinkType: uint32(pr.order.Uint16(body[0:2])),
				SnapLen:  pr.order.Uint32(body[4:8]),
				TSResol:  6, // Default PCAP-NG resolution: 10^-6 s (microseconds)
			}
			pr.parseIDBOptions(body[8:], &iface)
			pr.interfaces = append(pr.interfaces, iface)
			if len(pr.interfaces) == 1 {
				pr.LinkType = iface.LinkType
				pr.SnapLen = iface.SnapLen
			}

		case PCAPNGBlockEPB:
			if len(body) < 20 {
				continue
			}
			ifaceID := pr.order.Uint32(body[0:4])
			tsHigh := pr.order.Uint32(body[4:8])
			tsLow := pr.order.Uint32(body[8:12])
			capLen := int(pr.order.Uint32(body[12:16]))
			if capLen < 0 || 20+capLen > len(body) {
				continue
			}
			if int(ifaceID) >= len(pr.interfaces) {
				continue
			}
			iface := pr.interfaces[ifaceID]
			rawTS := (uint64(tsHigh) << 32) | uint64(tsLow)
			ts := decodePCAPNGTimestamp(rawTS, iface.TSResol)

			pkt, err := pr.dissect(body[20:20+capLen], ts, iface.LinkType, ifaceID)
			if err != nil {
				continue
			}
			return pkt, nil

		case PCAPNGBlockSPB:
			if len(body) < 4 || len(pr.interfaces) == 0 {
				continue
			}
			iface := pr.interfaces[0]
			origLen := int(pr.order.Uint32(body[0:4]))
			data := body[4:]
			if iface.SnapLen > 0 && int(iface.SnapLen) < origLen {
				origLen = int(iface.SnapLen)
			}
			if origLen < len(data) {
				data = data[:origLen]
			}
			pkt, err := pr.dissect(data, time.Time{}, iface.LinkType, 0)
			if err != nil {
				continue
			}
			return pkt, nil

		default:
			// Skip ISB, NRB, decryption secrets, and custom blocks cleanly.
			continue
		}
	}
}

func (pr *PCAPReader) parseIDBOptions(opts []byte, iface *PCAPNGInterface) {
	offset := 0
	for offset+4 <= len(opts) {
		optCode := pr.order.Uint16(opts[offset : offset+2])
		optLen := int(pr.order.Uint16(opts[offset+2 : offset+4]))
		offset += 4
		if optCode == PCAPNGOptEndOfOpt {
			break
		}
		if offset+optLen > len(opts) {
			break
		}
		val := opts[offset : offset+optLen]
		switch optCode {
		case PCAPNGOptIfName:
			iface.Name = string(val)
		case PCAPNGOptIfTSResol:
			if len(val) >= 1 {
				iface.TSResol = val[0]
			}
		}
		padded := (optLen + 3) &^ 3
		offset += padded
	}
}

func decodePCAPNGTimestamp(raw uint64, tsResol uint8) time.Time {
	if tsResol&0x80 == 0 {
		// Decimal power-of-10 units per second.
		exp := int(tsResol & 0x7f)
		if exp == 0 {
			return time.Unix(int64(raw), 0)
		}
		if exp <= 9 {
			scale := uint64(1)
			for i := 0; i < exp; i++ {
				scale *= 10
			}
			sec := raw / scale
			rem := raw % scale
			mul := uint64(1)
			for i := 0; i < 9-exp; i++ {
				mul *= 10
			}
			return time.Unix(int64(sec), int64(rem*mul))
		}
		if exp <= 18 {
			scale := uint64(1)
			for i := 0; i < exp; i++ {
				scale *= 10
			}
			div := uint64(1)
			for i := 0; i < exp-9; i++ {
				div *= 10
			}
			sec := raw / scale
			rem := raw % scale
			return time.Unix(int64(sec), int64(rem/div))
		}
		secs := float64(raw) / math.Pow10(exp)
		whole, frac := math.Modf(secs)
		return time.Unix(int64(whole), int64(frac*1e9))
	}

	// Binary power-of-2 units per second.
	exp := uint(tsResol & 0x7f)
	if exp == 0 {
		return time.Unix(int64(raw), 0)
	}
	if exp < 64 {
		sec := raw >> exp
		rem := raw & ((uint64(1) << exp) - 1)
		nsec := uint64((float64(rem) / math.Exp2(float64(exp))) * 1e9)
		return time.Unix(int64(sec), int64(nsec))
	}
	secs := float64(raw) / math.Exp2(float64(exp))
	whole, frac := math.Modf(secs)
	return time.Unix(int64(whole), int64(frac*1e9))
}

func discardExact(r io.Reader, n int) error {
	if n <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

func (pr *PCAPReader) dissect(raw []byte, ts time.Time, linkType uint32, ifaceID uint32) (*Packet, error) {
	var ipData []byte

	switch linkType {
	case LinkTypeEthernet:
		if len(raw) < 14 {
			return nil, ErrTruncatedPacket
		}
		etherType := binary.BigEndian.Uint16(raw[12:14])
		offset := 14
		// Unwrap single or stacked 802.1Q / 802.1ad QinQ VLAN tags.
		for tags := 0; (etherType == EtherTypeVLAN || etherType == EtherTypeQinQ) && tags < 4; tags++ {
			if len(raw) < offset+4 {
				return nil, ErrTruncatedPacket
			}
			etherType = binary.BigEndian.Uint16(raw[offset+2 : offset+4])
			offset += 4
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
		offset := 16
		for tags := 0; (protoType == EtherTypeVLAN || protoType == EtherTypeQinQ) && tags < 4; tags++ {
			if len(raw) < offset+4 {
				return nil, ErrTruncatedPacket
			}
			protoType = binary.BigEndian.Uint16(raw[offset+2 : offset+4])
			offset += 4
		}
		if protoType != EtherTypeIPv4 && protoType != EtherTypeIPv6 {
			return nil, ErrUnsupportedNetwork
		}
		ipData = raw[offset:]

	case LinkTypeLinuxSLL2:
		if len(raw) < 20 {
			return nil, ErrTruncatedPacket
		}
		protoType := binary.BigEndian.Uint16(raw[0:2])
		if protoType != EtherTypeIPv4 && protoType != EtherTypeIPv6 {
			return nil, ErrUnsupportedNetwork
		}
		ipData = raw[20:]

	case LinkTypeNull:
		if len(raw) < 4 {
			return nil, ErrTruncatedPacket
		}
		familyLE := binary.LittleEndian.Uint32(raw[0:4])
		familyBE := binary.BigEndian.Uint32(raw[0:4])
		if !isLoopbackIPFamily(familyLE) && !isLoopbackIPFamily(familyBE) {
			return nil, ErrUnsupportedNetwork
		}
		ipData = raw[4:]

	case LinkTypeRawIP, LinkTypeRawIPAlt:
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

	switch version {
	case 4:
		if len(ipData) < 20 {
			return nil, ErrTruncatedPacket
		}
		ihl := int(ipData[0]&0x0f) * 4
		if len(ipData) < ihl || ihl < 20 {
			return nil, ErrTruncatedPacket
		}
		totalLen := int(binary.BigEndian.Uint16(ipData[2:4]))
		if totalLen >= ihl && totalLen <= len(ipData) {
			ipData = ipData[:totalLen]
		}
		protocol = ipData[9]
		srcIP = make(net.IP, 4)
		copy(srcIP, ipData[12:16])
		dstIP = make(net.IP, 4)
		copy(dstIP, ipData[16:20])
		tcpData = ipData[ihl:]

	case 6:
		if len(ipData) < 40 {
			return nil, ErrTruncatedPacket
		}
		payloadLen := int(binary.BigEndian.Uint16(ipData[4:6]))
		protocol = ipData[6]
		srcIP = make(net.IP, 16)
		copy(srcIP, ipData[8:24])
		dstIP = make(net.IP, 16)
		copy(dstIP, ipData[24:40])
		nextData := ipData[40:]
		if payloadLen > 0 && payloadLen <= len(nextData) {
			nextData = nextData[:payloadLen]
		}
		var err error
		protocol, tcpData, err = walkIPv6Extensions(protocol, nextData)
		if err != nil {
			return nil, err
		}

	default:
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

	var payload []byte
	if rawPayload := tcpData[dataOffset:]; len(rawPayload) > 0 {
		payload = make([]byte, len(rawPayload))
		copy(payload, rawPayload)
	}

	return &Packet{
		Timestamp:   ts,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     srcPort,
		DstPort:     dstPort,
		Protocol:    protocol,
		TCPFlags:    flags,
		SeqNum:      seq,
		AckNum:      ack,
		Payload:     payload,
		InterfaceID: ifaceID,
	}, nil
}

func isLoopbackIPFamily(f uint32) bool {
	// AF_INET = 2; AF_INET6 = 10 (Linux), 24 (OpenBSD/NetBSD), 28 (FreeBSD), 30 (macOS)
	return f == 2 || f == 10 || f == 24 || f == 28 || f == 30
}

func walkIPv6Extensions(nextHdr uint8, data []byte) (uint8, []byte, error) {
	for depth := 0; depth < 8; depth++ {
		switch nextHdr {
		case IPProtoHopByHop, IPProtoRouting, IPProtoDestOpts:
			if len(data) < 2 {
				return 0, nil, ErrTruncatedPacket
			}
			extLen := (int(data[1]) + 1) * 8
			if len(data) < extLen {
				return 0, nil, ErrTruncatedPacket
			}
			nextHdr = data[0]
			data = data[extLen:]
		case IPProtoFragment:
			if len(data) < 8 {
				return 0, nil, ErrTruncatedPacket
			}
			// Only inspect first fragment (fragment offset == 0).
			fragOffset := binary.BigEndian.Uint16(data[2:4]) >> 3
			if fragOffset != 0 {
				return 0, nil, ErrUnsupportedNetwork
			}
			nextHdr = data[0]
			data = data[8:]
		default:
			return nextHdr, data, nil
		}
	}
	return nextHdr, data, nil
}
