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
	ErrBufferTooShort   = errors.New("buffer too short for TLS packet")
	ErrMalformedPayload = errors.New("malformed TLS payload")
)

// Record types
const (
	RecordTypeHandshake = 0x16
)

// Handshake types
const (
	HandshakeTypeClientHello = 0x01
)

// TLS extension types
const (
	ExtServerName          = 0x0000
	ExtSupportedAlgorithms = 0x000d
	ExtALPN                = 0x0010
	ExtSupportedVersions   = 0x002b
)

// ClientHelloSummary contains all parsed fields from a TLS ClientHello.
type ClientHelloSummary struct {
	Version             uint16
	EffectiveVersion    uint16
	Transport           byte // 't' for TCP, 'q' for QUIC
	SNI                 string
	HasSNI              bool
	IsDomainSNI         bool
	ALPN                string
	CipherSuites        []uint16
	FilteredCiphers     []uint16
	Extensions          []uint16
	FilteredExtensions  []uint16
	SignatureAlgorithms []uint16
	RawLength           int
}

// IsGREASE determines whether a 16-bit identifier is a GREASE value per RFC 8701.
func IsGREASE(v uint16) bool {
	return (v&0x0f0f == 0x0a0a) && ((v>>8)&0xff == v&0xff)
}

// ParseClientHello extracts TLS ClientHello metadata from a byte slice.
func ParseClientHello(data []byte) (*ClientHelloSummary, error) {
	if len(data) < 5 {
		return nil, ErrBufferTooShort
	}

	// 1. Verify TLS Record Header
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

	// 2. Verify Handshake Type
	if payload[0] != HandshakeTypeClientHello {
		return nil, ErrNotClientHello
	}

	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+hsLen {
		return nil, ErrBufferTooShort
	}

	ch := payload[4 : 4+hsLen]
	if len(ch) < 34 { // 2 version + 32 random
		return nil, ErrMalformedPayload
	}

	summary := &ClientHelloSummary{
		Version:   recVersion,
		Transport: 't',
		RawLength: 5 + recLen,
	}

	summary.EffectiveVersion = binary.BigEndian.Uint16(ch[0:2])
	offset := 34 // skip version (2) + random (32)

	// Session ID
	if offset >= len(ch) {
		return nil, ErrMalformedPayload
	}
	sessionIDLen := int(ch[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(ch) {
		return nil, ErrMalformedPayload
	}

	// Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(ch[offset : offset+2]))
	offset += 2
	if offset+cipherLen > len(ch) {
		return nil, ErrMalformedPayload
	}

	numCiphers := cipherLen / 2
	summary.CipherSuites = make([]uint16, 0, numCiphers)
	summary.FilteredCiphers = make([]uint16, 0, numCiphers)

	for i := 0; i < cipherLen; i += 2 {
		c := binary.BigEndian.Uint16(ch[offset+i : offset+i+2])
		summary.CipherSuites = append(summary.CipherSuites, c)
		if !IsGREASE(c) {
			summary.FilteredCiphers = append(summary.FilteredCiphers, c)
		}
	}
	offset += cipherLen

	// Compression Methods
	if offset >= len(ch) {
		// Valid ClientHello without extensions
		return summary, nil
	}
	compLen := int(ch[offset])
	offset += 1 + compLen

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
			break
		}
		extData := ch[offset : offset+extLength]
		offset += extLength

		summary.Extensions = append(summary.Extensions, extType)
		if !IsGREASE(extType) {
			summary.FilteredExtensions = append(summary.FilteredExtensions, extType)
		}

		switch extType {
		case ExtServerName:
			// SNI parsing
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+listLen && listLen > 0 {
					subOffset := 2
					for subOffset+3 <= 2+listLen {
						nameType := extData[subOffset]
						nameLen := int(binary.BigEndian.Uint16(extData[subOffset+1 : subOffset+3]))
						subOffset += 3
						if subOffset+nameLen <= len(extData) {
							if nameType == 0 { // host_name
								summary.SNI = string(extData[subOffset : subOffset+nameLen])
								summary.HasSNI = true
								// Check if domain vs IP
								if net.ParseIP(summary.SNI) == nil {
									summary.IsDomainSNI = true
								}
							}
						}
						subOffset += nameLen
					}
				}
			}

		case ExtALPN:
			// ALPN parsing
			if len(extData) >= 2 {
				alpnLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+alpnLen && alpnLen > 0 {
					subOffset := 2
					if subOffset < len(extData) {
						protoLen := int(extData[subOffset])
						subOffset++
						if subOffset+protoLen <= len(extData) {
							summary.ALPN = string(extData[subOffset : subOffset+protoLen])
						}
					}
				}
			}

		case ExtSupportedVersions:
			// Check for TLS 1.3 (0x0304)
			if len(extData) >= 1 {
				vLen := int(extData[0])
				if len(extData) >= 1+vLen {
					for i := 1; i+1 < 1+vLen; i += 2 {
						v := binary.BigEndian.Uint16(extData[i : i+2])
						if v == 0x0304 {
							summary.EffectiveVersion = 0x0304
							break
						}
					}
				}
			}

		case ExtSupportedAlgorithms:
			// Signature Algorithms
			if len(extData) >= 2 {
				sigLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+sigLen {
					for i := 2; i+1 < 2+sigLen; i += 2 {
						sig := binary.BigEndian.Uint16(extData[i : i+2])
						if !IsGREASE(sig) {
							summary.SignatureAlgorithms = append(summary.SignatureAlgorithms, sig)
						}
					}
				}
			}
		}
	}

	return summary, nil
}

// ComputeJA4 generates the canonical JA4 fingerprint from a parsed ClientHello.
// Format: [t|q][12|13|00][d|i][ciphers2][exts2][alpn2]_[cipher_hash12]_[extension_hash12]
func (s *ClientHelloSummary) ComputeJA4() string {
	// 1. Transport
	transport := s.Transport
	if transport == 0 {
		transport = 't'
	}

	// 2. Protocol Version
	var verStr string
	switch s.EffectiveVersion {
	case 0x0304:
		verStr = "13"
	case 0x0303:
		verStr = "12"
	case 0x0302:
		verStr = "11"
	case 0x0301:
		verStr = "10"
	case 0x0300:
		verStr = "s3"
	default:
		verStr = "00"
	}

	// 3. SNI Destination (d = domain, i = ip or no SNI)
	dest := "i"
	if s.HasSNI && s.IsDomainSNI {
		dest = "d"
	}

	// 4. Cipher count (max 99, 2 digits)
	cCount := len(s.FilteredCiphers)
	if cCount > 99 {
		cCount = 99
	}
	cCountStr := fmt.Sprintf("%02d", cCount)

	// 5. Extension count (excluding SNI 0x0000 and ALPN 0x0010 per standard JA4)
	extList := make([]uint16, 0, len(s.FilteredExtensions))
	for _, ext := range s.FilteredExtensions {
		if ext != ExtServerName && ext != ExtALPN {
			extList = append(extList, ext)
		}
	}
	eCount := len(extList)
	if eCount > 99 {
		eCount = 99
	}
	eCountStr := fmt.Sprintf("%02d", eCount)

	// 6. ALPN (first and last char of first protocol, or "00" if none)
	var alpnStr string
	if s.ALPN == "" {
		alpnStr = "00"
	} else if len(s.ALPN) == 1 {
		alpnStr = string(s.ALPN[0]) + string(s.ALPN[0])
	} else {
		alpnStr = string(s.ALPN[0]) + string(s.ALPN[len(s.ALPN)-1])
	}

	partA := fmt.Sprintf("%c%s%s%s%s%s", transport, verStr, dest, cCountStr, eCountStr, alpnStr)

	// 7. Part B: Sorted Ciphers Hash (12 hex chars)
	var partB string
	if len(s.FilteredCiphers) == 0 {
		partB = "000000000000"
	} else {
		sortedCiphers := make([]uint16, len(s.FilteredCiphers))
		copy(sortedCiphers, s.FilteredCiphers)
		sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })

		var cipherHexes []string
		for _, c := range sortedCiphers {
			cipherHexes = append(cipherHexes, fmt.Sprintf("%04x", c))
		}
		cipherStr := strings.Join(cipherHexes, ",")
		h := sha256.Sum256([]byte(cipherStr))
		partB = hex.EncodeToString(h[:6]) // first 12 hex chars
	}

	// 8. Part C: Sorted Extensions & Signature Algorithms Hash (12 hex chars)
	var partC string
	if len(extList) == 0 && len(s.SignatureAlgorithms) == 0 {
		partC = "000000000000"
	} else {
		sortedExts := make([]uint16, len(extList))
		copy(sortedExts, extList)
		sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })

		var extHexes []string
		for _, e := range sortedExts {
			extHexes = append(extHexes, fmt.Sprintf("%04x", e))
		}
		extStr := strings.Join(extHexes, ",")

		if len(s.SignatureAlgorithms) > 0 {
			var sigHexes []string
			for _, s := range s.SignatureAlgorithms {
				sigHexes = append(sigHexes, fmt.Sprintf("%04x", s))
			}
			extStr += "_" + strings.Join(sigHexes, ",")
		}

		h := sha256.Sum256([]byte(extStr))
		partC = hex.EncodeToString(h[:6])
	}

	return fmt.Sprintf("%s_%s_%s", partA, partB, partC)
}
