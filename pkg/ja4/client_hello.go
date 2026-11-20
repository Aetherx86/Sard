package ja4

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

var (
	ErrNotTLS           = errors.New("not a TLS record")
	ErrNotClientHello   = errors.New("not a ClientHello handshake")
	ErrNotServerHello   = errors.New("not a ServerHello handshake")
	ErrNotCertificate   = errors.New("not a Certificate handshake")
	ErrBufferTooShort   = errors.New("buffer too short for TLS packet")
	ErrMalformedPayload = errors.New("malformed TLS payload")
)

// TLS record types (RFC 5246 / RFC 8446).
const (
	RecordTypeChangeCipherSpec = 0x14
	RecordTypeAlert            = 0x15
	RecordTypeHandshake        = 0x16
	RecordTypeApplicationData  = 0x17
)

// TLS handshake message types.
const (
	HandshakeTypeClientHello = 0x01
	HandshakeTypeServerHello = 0x02
	HandshakeTypeCertificate = 0x0b
)

// Common TLS extension identifiers.
const (
	ExtServerName          = 0x0000
	ExtSupportedGroups     = 0x000a
	ExtECPointFormats      = 0x000b
	ExtSupportedAlgorithms = 0x000d
	ExtALPN                = 0x0010
	ExtCompressCertificate = 0x001b
	ExtSessionTicket       = 0x0023
	ExtSupportedVersions   = 0x002b
	ExtPSKKeyExchangeModes = 0x002d
	ExtKeyShare            = 0x0033
)

// ClientHelloSummary contains all parsed fields from a TLS ClientHello.
type ClientHelloSummary struct {
	Version             uint16
	EffectiveVersion    uint16
	Transport           byte // 't' for TCP, 'q' for QUIC, 'd' for DTLS
	SNI                 string
	HasSNI              bool
	IsDomainSNI         bool
	ALPN                string
	ALPNs               []string
	SessionIDLen        int
	CompressionMethods  []uint8
	CipherSuites        []uint16
	FilteredCiphers     []uint16
	Extensions          []uint16
	FilteredExtensions  []uint16
	SupportedVersions   []uint16
	SupportedGroups     []uint16
	ECPointFormats      []uint8
	SignatureAlgorithms []uint16
	GREASECount         int
	RawLength           int
}

// IsGREASE determines whether a 16-bit identifier is a GREASE value per RFC 8701.
func IsGREASE(v uint16) bool {
	return (v&0x0f0f == 0x0a0a) && ((v>>8)&0xff == v&0xff)
}

// ParseClientHello extracts TLS ClientHello metadata from a TLS record byte slice.
func ParseClientHello(data []byte) (*ClientHelloSummary, error) {
	if len(data) < 5 {
		return nil, ErrBufferTooShort
	}

	if data[0] != RecordTypeHandshake {
		return nil, ErrNotTLS
	}

	recVersion := binary.BigEndian.Uint16(data[1:3])
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return nil, ErrBufferTooShort
	}

	payload := data[5 : 5+recLen]
	if len(payload) < 4 {
		return nil, ErrBufferTooShort
	}

	if payload[0] != HandshakeTypeClientHello {
		return nil, ErrNotClientHello
	}

	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+hsLen {
		// Handle ClientHello fragmented across multiple contiguous TLS handshake records.
		msgs, consumed, err := ExtractHandshakeMessages(data)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Type == HandshakeTypeClientHello {
				summary, err := ParseClientHelloBody(m.Body, recVersion, 't')
				if err != nil {
					return nil, err
				}
				summary.RawLength = consumed
				return summary, nil
			}
		}
		return nil, ErrNotClientHello
	}

	summary, err := ParseClientHelloBody(payload[4:4+hsLen], recVersion, 't')
	if err != nil {
		return nil, err
	}
	summary.RawLength = 5 + recLen
	return summary, nil
}

// ParseClientHelloBody parses a raw ClientHello handshake body (without the 5-byte TLS
// record header or 4-byte handshake header).
func ParseClientHelloBody(ch []byte, recordVersion uint16, transport byte) (*ClientHelloSummary, error) {
	if len(ch) < 34 { // 2 version + 32 random
		return nil, ErrMalformedPayload
	}
	if transport == 0 {
		transport = 't'
	}

	summary := &ClientHelloSummary{
		Version:          recordVersion,
		EffectiveVersion: binary.BigEndian.Uint16(ch[0:2]),
		Transport:        transport,
		RawLength:        len(ch),
	}

	offset := 34 // skip client_version (2) + random (32)

	// Session ID
	if offset >= len(ch) {
		return nil, ErrMalformedPayload
	}
	sessionIDLen := int(ch[offset])
	summary.SessionIDLen = sessionIDLen
	offset += 1 + sessionIDLen
	if offset+2 > len(ch) {
		return nil, ErrMalformedPayload
	}

	// Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(ch[offset : offset+2]))
	offset += 2
	if cipherLen%2 != 0 || offset+cipherLen > len(ch) {
		return nil, ErrMalformedPayload
	}

	numCiphers := cipherLen / 2
	summary.CipherSuites = make([]uint16, 0, numCiphers)
	summary.FilteredCiphers = make([]uint16, 0, numCiphers)

	for i := 0; i < cipherLen; i += 2 {
		c := binary.BigEndian.Uint16(ch[offset+i : offset+i+2])
		summary.CipherSuites = append(summary.CipherSuites, c)
		if IsGREASE(c) {
			summary.GREASECount++
		} else {
			summary.FilteredCiphers = append(summary.FilteredCiphers, c)
		}
	}
	offset += cipherLen

	// Compression Methods
	if offset >= len(ch) {
		return summary, nil
	}
	compLen := int(ch[offset])
	offset++
	if offset+compLen > len(ch) {
		return nil, ErrMalformedPayload
	}
	if compLen > 0 {
		summary.CompressionMethods = make([]uint8, compLen)
		copy(summary.CompressionMethods, ch[offset:offset+compLen])
	}
	offset += compLen

	if offset >= len(ch) {
		return summary, nil
	}

	// Extensions
	if offset+2 > len(ch) {
		return summary, nil
	}
	extsLen := int(binary.BigEndian.Uint16(ch[offset : offset+2]))
	offset += 2
	if offset+extsLen > len(ch) {
		return nil, ErrMalformedPayload
	}

	extEnd := offset + extsLen
	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(ch[offset : offset+2])
		extLength := int(binary.BigEndian.Uint16(ch[offset+2 : offset+4]))
		offset += 4
		if offset+extLength > extEnd {
			return nil, ErrMalformedPayload
		}
		extData := ch[offset : offset+extLength]
		offset += extLength

		summary.Extensions = append(summary.Extensions, extType)
		if IsGREASE(extType) {
			summary.GREASECount++
		} else {
			summary.FilteredExtensions = append(summary.FilteredExtensions, extType)
		}

		switch extType {
		case ExtServerName:
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+listLen && listLen > 0 {
					subOffset := 2
					for subOffset+3 <= 2+listLen {
						nameType := extData[subOffset]
						nameLen := int(binary.BigEndian.Uint16(extData[subOffset+1 : subOffset+3]))
						subOffset += 3
						if subOffset+nameLen <= 2+listLen {
							if nameType == 0 && !summary.HasSNI { // host_name
								summary.SNI = string(extData[subOffset : subOffset+nameLen])
								summary.HasSNI = true
								if summary.SNI != "" && net.ParseIP(summary.SNI) == nil {
									summary.IsDomainSNI = true
								}
							}
						}
						subOffset += nameLen
					}
				}
			}

		case ExtALPN:
			if len(extData) >= 2 {
				alpnLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+alpnLen && alpnLen > 0 {
					subOffset := 2
					limit := 2 + alpnLen
					for subOffset < limit {
						protoLen := int(extData[subOffset])
						subOffset++
						if protoLen == 0 || subOffset+protoLen > limit {
							break
						}
						proto := string(extData[subOffset : subOffset+protoLen])
						summary.ALPNs = append(summary.ALPNs, proto)
						if summary.ALPN == "" {
							summary.ALPN = proto
						}
						subOffset += protoLen
					}
				}
			}

		case ExtSupportedVersions:
			if len(extData) >= 1 {
				vLen := int(extData[0])
				if len(extData) >= 1+vLen {
					bestRank := -1
					var bestVer uint16
					for i := 1; i+1 < 1+vLen; i += 2 {
						v := binary.BigEndian.Uint16(extData[i : i+2])
						if IsGREASE(v) {
							summary.GREASECount++
							continue
						}
						summary.SupportedVersions = append(summary.SupportedVersions, v)
						if r := tlsVersionRank(v); r > bestRank {
							bestRank = r
							bestVer = v
						}
					}
					if bestRank >= 0 {
						summary.EffectiveVersion = bestVer
					}
				}
			}

		case ExtSupportedAlgorithms:
			if len(extData) >= 2 {
				sigLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+sigLen {
					for i := 2; i+1 < 2+sigLen; i += 2 {
						sig := binary.BigEndian.Uint16(extData[i : i+2])
						if IsGREASE(sig) {
							summary.GREASECount++
						} else {
							summary.SignatureAlgorithms = append(summary.SignatureAlgorithms, sig)
						}
					}
				}
			}

		case ExtSupportedGroups:
			if len(extData) >= 2 {
				grpLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+grpLen {
					for i := 2; i+1 < 2+grpLen; i += 2 {
						g := binary.BigEndian.Uint16(extData[i : i+2])
						if IsGREASE(g) {
							summary.GREASECount++
						} else {
							summary.SupportedGroups = append(summary.SupportedGroups, g)
						}
					}
				}
			}

		case ExtECPointFormats:
			if len(extData) >= 1 {
				fmtLen := int(extData[0])
				if len(extData) >= 1+fmtLen && fmtLen > 0 {
					summary.ECPointFormats = make([]uint8, fmtLen)
					copy(summary.ECPointFormats, extData[1:1+fmtLen])
				}
			}
		}
	}

	return summary, nil
}

// ComputeJA4 generates the canonical JA4 fingerprint from a parsed ClientHello.
// Format: [t|q|d][ver2][d|i][ciphers2][exts2][alpn2]_[cipher_hash12]_[extension_hash12]
// Per the JA4 specification, Part A counts all non-GREASE extensions (including SNI and ALPN),
// while Part C hashes sorted non-GREASE extensions excluding SNI (0x0000) and ALPN (0x0010),
// followed by unsorted non-GREASE signature algorithms.
func (s *ClientHelloSummary) ComputeJA4() string {
	var out [36]byte
	s.writeJA4PartA(out[0:10])
	out[10] = '_'

	// Part B: SHA-256[:12] of sorted non-GREASE cipher suites.
	if len(s.FilteredCiphers) == 0 {
		copy(out[11:23], "000000000000")
	} else {
		var stackCiphers [64]uint16
		var sortedCiphers []uint16
		if len(s.FilteredCiphers) <= len(stackCiphers) {
			sortedCiphers = stackCiphers[:len(s.FilteredCiphers)]
		} else {
			sortedCiphers = make([]uint16, len(s.FilteredCiphers))
		}
		copy(sortedCiphers, s.FilteredCiphers)
		sortUint16Slice(sortedCiphers)

		var stackCSV [320]byte
		csvBuf := appendUint16CSV(stackCSV[:0], sortedCiphers)
		writeSHA256Trunc12(out[11:23], csvBuf)
	}

	out[23] = '_'

	// Part C: SHA-256[:12] of sorted non-GREASE extensions (excluding SNI/ALPN) + "_" + sig_algs.
	var stackExts [64]uint16
	extList := stackExts[:0]
	if len(s.FilteredExtensions) > len(stackExts) {
		extList = make([]uint16, 0, len(s.FilteredExtensions))
	}
	for _, ext := range s.FilteredExtensions {
		if ext != ExtServerName && ext != ExtALPN {
			extList = append(extList, ext)
		}
	}

	if len(extList) == 0 && len(s.SignatureAlgorithms) == 0 {
		copy(out[24:36], "000000000000")
	} else {
		sortUint16Slice(extList)
		var stackPartC [512]byte
		partCBuf := appendJA4PartCInput(stackPartC[:0], extList, s.SignatureAlgorithms)
		writeSHA256Trunc12(out[24:36], partCBuf)
	}

	return string(out[:])
}

// ComputeJA4Raw returns the unhashed JA4_r representation with sorted ciphers and extensions.
func (s *ClientHelloSummary) ComputeJA4Raw() string {
	var partA [10]byte
	s.writeJA4PartA(partA[:])
	sortedCiphers := sortedUint16Copy(s.FilteredCiphers)
	extList := s.hashableExtensions()
	sortUint16Slice(extList)

	return string(partA[:]) + "_" + formatUint16CSV(sortedCiphers) + "_" + formatJA4PartCInput(extList, s.SignatureAlgorithms)
}

// ComputeJA4Original returns the JA4_o fingerprint preserving wire order for both ciphers
// and all non-GREASE extensions (including SNI and ALPN).
func (s *ClientHelloSummary) ComputeJA4Original() string {
	var out [36]byte
	s.writeJA4PartA(out[0:10])
	out[10] = '_'

	if len(s.FilteredCiphers) == 0 {
		copy(out[11:23], "000000000000")
	} else {
		var stackCSV [320]byte
		csvBuf := appendUint16CSV(stackCSV[:0], s.FilteredCiphers)
		writeSHA256Trunc12(out[11:23], csvBuf)
	}

	out[23] = '_'

	if len(s.FilteredExtensions) == 0 && len(s.SignatureAlgorithms) == 0 {
		copy(out[24:36], "000000000000")
	} else {
		var stackPartC [512]byte
		partCBuf := appendJA4PartCInput(stackPartC[:0], s.FilteredExtensions, s.SignatureAlgorithms)
		writeSHA256Trunc12(out[24:36], partCBuf)
	}

	return string(out[:])
}

func (s *ClientHelloSummary) writeJA4PartA(dst []byte) {
	transport := s.Transport
	if transport == 0 {
		transport = 't'
	}

	verStr := formatTLSVersion(s.EffectiveVersion)

	dest := byte('i')
	if s.HasSNI && s.IsDomainSNI {
		dest = 'd'
	}

	cCount := len(s.FilteredCiphers)
	if cCount > 99 {
		cCount = 99
	}

	eCount := len(s.FilteredExtensions)
	if eCount > 99 {
		eCount = 99
	}

	alpn0, alpn1 := formatALPNBytes(s.ALPN)

	dst[0] = transport
	dst[1] = verStr[0]
	dst[2] = verStr[1]
	dst[3] = dest
	dst[4] = byte('0' + cCount/10)
	dst[5] = byte('0' + cCount%10)
	dst[6] = byte('0' + eCount/10)
	dst[7] = byte('0' + eCount%10)
	dst[8] = alpn0
	dst[9] = alpn1
}

func (s *ClientHelloSummary) hashableExtensions() []uint16 {
	extList := make([]uint16, 0, len(s.FilteredExtensions))
	for _, ext := range s.FilteredExtensions {
		if ext != ExtServerName && ext != ExtALPN {
			extList = append(extList, ext)
		}
	}
	return extList
}

// TLSVersionName returns a human-readable protocol version label.
func TLSVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	case 0x0300:
		return "SSL 3.0"
	case 0x0002:
		return "SSL 2.0"
	case 0xfefc:
		return "DTLS 1.3"
	case 0xfefd:
		return "DTLS 1.2"
	case 0xfeff:
		return "DTLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func tlsVersionRank(v uint16) int {
	switch v {
	case 0x0304, 0xfefc:
		return 5
	case 0x0303, 0xfefd:
		return 4
	case 0x0302:
		return 3
	case 0x0301, 0xfeff:
		return 2
	case 0x0300:
		return 1
	case 0x0002:
		return 0
	default:
		return -1
	}
}

func formatTLSVersion(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfefc:
		return "d3"
	case 0xfefd:
		return "d2"
	case 0xfeff:
		return "d1"
	default:
		return "00"
	}
}

func isASCIIAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

const hexDigits = "0123456789abcdef"

func formatALPNBytes(alpn string) (byte, byte) {
	if len(alpn) == 0 {
		return '0', '0'
	}
	first := alpn[0]
	last := alpn[len(alpn)-1]
	if isASCIIAlnum(first) && isASCIIAlnum(last) {
		return first, last
	}
	return hexDigits[first>>4], hexDigits[last&0x0f]
}

// formatALPN formats the 2-character JA4/JA4S ALPN indicator.
// If the first or last byte is non-alphanumeric, returns the first hex nibble of the
// first byte and the last hex nibble of the last byte per the JA4 specification.
func formatALPN(alpn string) string {
	b0, b1 := formatALPNBytes(alpn)
	return string([]byte{b0, b1})
}

func sortedUint16Copy(in []uint16) []uint16 {
	if len(in) == 0 {
		return nil
	}
	out := make([]uint16, len(in))
	copy(out, in)
	sortUint16Slice(out)
	return out
}

func sortUint16Slice(s []uint16) {
	if len(s) <= 1 {
		return
	}
	// Insertion sort is faster and allocation-free for typical TLS cipher/extension counts.
	if len(s) <= 32 {
		for i := 1; i < len(s); i++ {
			v := s[i]
			j := i - 1
			for j >= 0 && s[j] > v {
				s[j+1] = s[j]
				j--
			}
			s[j+1] = v
		}
		return
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

func appendUint16Hex(dst []byte, v uint16) []byte {
	return append(dst,
		hexDigits[(v>>12)&0x0f],
		hexDigits[(v>>8)&0x0f],
		hexDigits[(v>>4)&0x0f],
		hexDigits[v&0x0f],
	)
}

func appendUint16CSV(dst []byte, vals []uint16) []byte {
	for i, v := range vals {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendUint16Hex(dst, v)
	}
	return dst
}

func formatUint16CSV(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(vals)*5-1)
	buf = appendUint16CSV(buf, vals)
	return string(buf)
}

func appendJA4PartCInput(dst []byte, exts, sigAlgs []uint16) []byte {
	dst = appendUint16CSV(dst, exts)
	if len(sigAlgs) > 0 {
		dst = append(dst, '_')
		dst = appendUint16CSV(dst, sigAlgs)
	}
	return dst
}

func formatJA4PartCInput(exts, sigAlgs []uint16) string {
	var b strings.Builder
	capHint := 0
	if len(exts) > 0 {
		capHint += len(exts)*5 - 1
	}
	if len(sigAlgs) > 0 {
		capHint += 1 + len(sigAlgs)*5 - 1
	}
	b.Grow(capHint)

	var hexBuf [4]byte
	for i, e := range exts {
		if i > 0 {
			b.WriteByte(',')
		}
		hexBuf[0] = hexDigits[(e>>12)&0x0f]
		hexBuf[1] = hexDigits[(e>>8)&0x0f]
		hexBuf[2] = hexDigits[(e>>4)&0x0f]
		hexBuf[3] = hexDigits[e&0x0f]
		b.Write(hexBuf[:])
	}
	if len(sigAlgs) > 0 {
		b.WriteByte('_')
		for i, s := range sigAlgs {
			if i > 0 {
				b.WriteByte(',')
			}
			hexBuf[0] = hexDigits[(s>>12)&0x0f]
			hexBuf[1] = hexDigits[(s>>8)&0x0f]
			hexBuf[2] = hexDigits[(s>>4)&0x0f]
			hexBuf[3] = hexDigits[s&0x0f]
			b.Write(hexBuf[:])
		}
	}
	return b.String()
}

func writeSHA256Trunc12(dst []byte, data []byte) {
	h := sha256.Sum256(data)
	for i := 0; i < 6; i++ {
		dst[i*2] = hexDigits[h[i]>>4]
		dst[i*2+1] = hexDigits[h[i]&0x0f]
	}
}

func sha256Trunc12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}
