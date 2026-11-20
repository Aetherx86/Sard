package ja4

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
)

// RFC 8446 Section 4.1.3 HelloRetryRequest special random sentinel.
var helloRetryRequestRandom = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// HandshakeMessage represents a reassembled TLS handshake message extracted
// from one or more TLS Handshake (0x16) records.
type HandshakeMessage struct {
	Type          uint8
	RecordVersion uint16
	Body          []byte
}

// ExtractHandshakeMessages parses one or more contiguous TLS Handshake records from data,
// reassembling handshake messages that span multiple records and separating coalesced
// handshake messages within a single record.
//
// It returns the parsed handshake messages, the number of record bytes consumed, and any
// error. If data starts with a valid TLS handshake record that is incomplete, it returns
// ErrBufferTooShort along with any already-complete handshake messages and bytes consumed.
func ExtractHandshakeMessages(data []byte) ([]HandshakeMessage, int, error) {
	if len(data) < 5 {
		return nil, 0, ErrBufferTooShort
	}
	if data[0] != RecordTypeHandshake {
		return nil, 0, ErrNotTLS
	}

	var hsStream []byte
	var firstRecordVersion uint16
	offset := 0
	recordCount := 0
	incomplete := false

	for offset < len(data) {
		if len(data)-offset < 5 {
			incomplete = true
			break
		}
		recType := data[offset]
		if recType != RecordTypeHandshake {
			break
		}
		recVer := binary.BigEndian.Uint16(data[offset+1 : offset+3])
		recLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		// Validate TLS record major version (0x03xx) and RFC record limit (16384 + overhead).
		if (recVer>>8) != 0x03 && recVer != 0xfeff && recVer != 0xfefd && recVer != 0xfefc {
			if recordCount == 0 {
				return nil, 0, ErrNotTLS
			}
			break
		}
		if recLen == 0 || recLen > 18432 {
			if recordCount == 0 {
				return nil, 0, ErrMalformedPayload
			}
			break
		}
		if len(data)-offset < 5+recLen {
			incomplete = true
			break
		}
		if recordCount == 0 {
			firstRecordVersion = recVer
		}
		recPayload := data[offset+5 : offset+5+recLen]
		hsStream = append(hsStream, recPayload...)
		offset += 5 + recLen
		recordCount++
	}

	if recordCount == 0 {
		if incomplete {
			return nil, 0, ErrBufferTooShort
		}
		return nil, 0, ErrNotTLS
	}

	var msgs []HandshakeMessage
	hsOff := 0
	hsIncomplete := false
	for hsOff < len(hsStream) {
		if len(hsStream)-hsOff < 4 {
			hsIncomplete = true
			break
		}
		msgType := hsStream[hsOff]
		msgLen := int(hsStream[hsOff+1])<<16 | int(hsStream[hsOff+2])<<8 | int(hsStream[hsOff+3])
		if msgLen > 131072 {
			if len(msgs) > 0 {
				return msgs, offset, nil
			}
			return nil, 0, ErrMalformedPayload
		}
		if len(hsStream)-hsOff < 4+msgLen {
			hsIncomplete = true
			break
		}
		body := make([]byte, msgLen)
		copy(body, hsStream[hsOff+4:hsOff+4+msgLen])
		msgs = append(msgs, HandshakeMessage{
			Type:          msgType,
			RecordVersion: firstRecordVersion,
			Body:          body,
		})
		hsOff += 4 + msgLen
	}

	if len(msgs) == 0 && (incomplete || hsIncomplete) {
		return nil, 0, ErrBufferTooShort
	}
	if hsIncomplete {
		return msgs, offset, ErrBufferTooShort
	}
	return msgs, offset, nil
}

// ServerHelloSummary contains parsed fields from a TLS ServerHello message.
type ServerHelloSummary struct {
	Version             uint16
	ServerVersion       uint16
	EffectiveVersion    uint16
	Transport           byte // 't' for TCP, 'q' for QUIC, 'd' for DTLS
	Random              [32]byte
	IsHelloRetryRequest bool
	SessionIDLen        int
	CipherSuite         uint16
	CompressionMethod   uint8
	Extensions          []uint16
	ALPN                string
	KeyShareGroup       uint16
	RawLength           int
}

// ParseServerHello extracts TLS ServerHello metadata from a TLS record byte slice.
func ParseServerHello(data []byte) (*ServerHelloSummary, error) {
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
	if payload[0] != HandshakeTypeServerHello {
		return nil, ErrNotServerHello
	}

	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload) < 4+hsLen {
		return nil, ErrBufferTooShort
	}

	summary, err := ParseServerHelloBody(payload[4:4+hsLen], recVersion, 't')
	if err != nil {
		return nil, err
	}
	summary.RawLength = 5 + recLen
	return summary, nil
}

// ParseServerHelloBody parses a raw ServerHello handshake body (without the 5-byte TLS
// record header or 4-byte handshake header).
func ParseServerHelloBody(sh []byte, recordVersion uint16, transport byte) (*ServerHelloSummary, error) {
	if len(sh) < 38 { // 2 version + 32 random + 1 sessionIDLen + 2 cipher + 1 compression
		return nil, ErrMalformedPayload
	}
	if transport == 0 {
		transport = 't'
	}

	serverVer := binary.BigEndian.Uint16(sh[0:2])
	summary := &ServerHelloSummary{
		Version:          recordVersion,
		ServerVersion:    serverVer,
		EffectiveVersion: serverVer,
		Transport:        transport,
		RawLength:        len(sh),
	}
	copy(summary.Random[:], sh[2:34])
	summary.IsHelloRetryRequest = summary.Random == helloRetryRequestRandom

	offset := 34
	sessionIDLen := int(sh[offset])
	summary.SessionIDLen = sessionIDLen
	offset += 1 + sessionIDLen
	if offset+3 > len(sh) {
		return nil, ErrMalformedPayload
	}

	summary.CipherSuite = binary.BigEndian.Uint16(sh[offset : offset+2])
	summary.CompressionMethod = sh[offset+2]
	offset += 3

	if offset >= len(sh) {
		return summary, nil
	}
	if offset+2 > len(sh) {
		return nil, ErrMalformedPayload
	}

	extsLen := int(binary.BigEndian.Uint16(sh[offset : offset+2]))
	offset += 2
	if offset+extsLen > len(sh) {
		return nil, ErrMalformedPayload
	}

	extEnd := offset + extsLen
	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(sh[offset : offset+2])
		extLength := int(binary.BigEndian.Uint16(sh[offset+2 : offset+4]))
		offset += 4
		if offset+extLength > extEnd {
			return nil, ErrMalformedPayload
		}
		extData := sh[offset : offset+extLength]
		offset += extLength

		summary.Extensions = append(summary.Extensions, extType)

		switch extType {
		case ExtSupportedVersions:
			// In ServerHello, supported_versions contains a single 2-byte selected version.
			if len(extData) >= 2 {
				v := binary.BigEndian.Uint16(extData[0:2])
				if !IsGREASE(v) {
					summary.EffectiveVersion = v
				}
			}

		case ExtALPN:
			if len(extData) >= 2 {
				alpnLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if len(extData) >= 2+alpnLen && alpnLen > 0 {
					protoLen := int(extData[2])
					if protoLen > 0 && 3+protoLen <= 2+alpnLen {
						summary.ALPN = string(extData[3 : 3+protoLen])
					}
				}
			}

		case ExtKeyShare:
			if len(extData) >= 2 {
				summary.KeyShareGroup = binary.BigEndian.Uint16(extData[0:2])
			}
		}
	}

	return summary, nil
}

// ComputeJA4S generates the canonical JA4S TLS ServerHello fingerprint.
// Format: [t|q|d][ver2][exts2][alpn2]_[cipher4]_[ext_hash12]
// Extensions in JA4S are kept in their original wire order (unsorted).
func (s *ServerHelloSummary) ComputeJA4S() string {
	var out [25]byte
	s.writeJA4SPartA(out[0:7])
	out[7] = '_'
	out[8] = hexDigits[(s.CipherSuite>>12)&0x0f]
	out[9] = hexDigits[(s.CipherSuite>>8)&0x0f]
	out[10] = hexDigits[(s.CipherSuite>>4)&0x0f]
	out[11] = hexDigits[s.CipherSuite&0x0f]
	out[12] = '_'

	if len(s.Extensions) == 0 {
		copy(out[13:25], "000000000000")
	} else {
		var stackCSV [256]byte
		csvBuf := appendUint16CSV(stackCSV[:0], s.Extensions)
		writeSHA256Trunc12(out[13:25], csvBuf)
	}
	return string(out[:])
}

// ComputeJA4SRaw returns the unhashed JA4S_r representation.
func (s *ServerHelloSummary) ComputeJA4SRaw() string {
	var partA [7]byte
	s.writeJA4SPartA(partA[:])
	partB := string(appendUint16Hex(make([]byte, 0, 4), s.CipherSuite))
	return string(partA[:]) + "_" + partB + "_" + formatUint16CSV(s.Extensions)
}

func (s *ServerHelloSummary) writeJA4SPartA(dst []byte) {
	transport := s.Transport
	if transport == 0 {
		transport = 't'
	}
	verStr := formatTLSVersion(s.EffectiveVersion)
	extCount := len(s.Extensions)
	if extCount > 99 {
		extCount = 99
	}
	alpn0, alpn1 := formatALPNBytes(s.ALPN)

	dst[0] = transport
	dst[1] = verStr[0]
	dst[2] = verStr[1]
	dst[3] = byte('0' + extCount/10)
	dst[4] = byte('0' + extCount%10)
	dst[5] = alpn0
	dst[6] = alpn1
}

// IsDeprecatedTLSVersion reports whether a negotiated or advertised TLS version is
// deprecated by RFC 8996 (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1).
func IsDeprecatedTLSVersion(v uint16) bool {
	switch v {
	case 0x0002, 0x0300, 0x0301, 0x0302:
		return true
	default:
		return false
	}
}

// IsWeakCipherSuite reports whether a TLS cipher suite uses broken or weak primitives
// (NULL, EXPORT, RC4, DES/3DES, or anonymous DH/ECDH).
func IsWeakCipherSuite(c uint16) bool {
	switch c {
	// NULL ciphers
	case 0x0000, 0x0001, 0x0002, 0x003b, 0xc001, 0xc006, 0xc00b, 0xc010, 0xc015:
		return true
	// EXPORT ciphers
	case 0x0003, 0x0006, 0x0008, 0x000b, 0x000e, 0x0011, 0x0014, 0x0017, 0x0019,
		0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066:
		return true
	// RC4 ciphers
	case 0x0004, 0x0005, 0x0018, 0xc002, 0xc007, 0xc00c, 0xc011, 0xc016:
		return true
	// DES / 3DES ciphers
	case 0x0009, 0x000a, 0x000c, 0x000d, 0x000f, 0x0010, 0x0012, 0x0013, 0x0015,
		0x0016, 0x001a, 0x001b, 0xc003, 0xc008, 0xc00d, 0xc012, 0xc017:
		return true
	// Anonymous DH / ECDH
	case 0x0034, 0x003a, 0x006c, 0x006d, 0x00a6, 0x00a7, 0xc018, 0xc019:
		return true
	default:
		return false
	}
}

// CertificateSummary contains parsed X.509 metadata and JA4X fields from a leaf certificate.
type CertificateSummary struct {
	ChainLength   int
	SubjectCN     string
	IssuerCN      string
	DNSNames      []string
	NotBefore     time.Time
	NotAfter      time.Time
	IsSelfSigned  bool
	IssuerOIDs    []string // hex-encoded DER OID value bytes in wire order
	SubjectOIDs   []string // hex-encoded DER OID value bytes in wire order
	ExtensionOIDs []string // hex-encoded DER OID value bytes in wire order
}

// IsExpiredAt reports whether the certificate is outside its validity window at timestamp t.
func (c *CertificateSummary) IsExpiredAt(t time.Time) bool {
	if c == nil || t.IsZero() || c.NotAfter.IsZero() {
		return false
	}
	return t.After(c.NotAfter) || (!c.NotBefore.IsZero() && t.Before(c.NotBefore))
}

// ComputeJA4X generates the canonical JA4X X.509 certificate fingerprint.
// Format: [issuer_oids_hash12]_[subject_oids_hash12]_[extension_oids_hash12]
func (c *CertificateSummary) ComputeJA4X() string {
	return hashOIDList(c.IssuerOIDs) + "_" + hashOIDList(c.SubjectOIDs) + "_" + hashOIDList(c.ExtensionOIDs)
}

// ComputeJA4XRaw returns the unhashed JA4X_r representation.
func (c *CertificateSummary) ComputeJA4XRaw() string {
	return strings.Join(c.IssuerOIDs, ",") + "_" + strings.Join(c.SubjectOIDs, ",") + "_" + strings.Join(c.ExtensionOIDs, ",")
}

func hashOIDList(oids []string) string {
	if len(oids) == 0 {
		return "000000000000"
	}
	return sha256Trunc12(strings.Join(oids, ","))
}

// ParseCertificateMessage extracts the leaf certificate from a TLS Certificate record (0x0b).
func ParseCertificateMessage(data []byte) (*CertificateSummary, error) {
	msgs, _, err := ExtractHandshakeMessages(data)
	if err != nil && len(msgs) == 0 {
		return nil, err
	}
	for _, m := range msgs {
		if m.Type == HandshakeTypeCertificate {
			return ParseCertificateBody(m.Body)
		}
	}
	return nil, ErrNotCertificate
}

// ParseCertificateBody parses a TLS 1.2 Certificate handshake body (3-byte total length
// followed by 3-byte length-prefixed DER certificates).
func ParseCertificateBody(body []byte) (*CertificateSummary, error) {
	if len(body) < 3 {
		return nil, ErrMalformedPayload
	}
	totalLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	if totalLen == 0 || len(body) < 3+totalLen {
		return nil, ErrMalformedPayload
	}

	offset := 3
	limit := 3 + totalLen
	var leafDER []byte
	chainLen := 0

	for offset+3 <= limit {
		certLen := int(body[offset])<<16 | int(body[offset+1])<<8 | int(body[offset+2])
		offset += 3
		if certLen == 0 || offset+certLen > limit {
			return nil, ErrMalformedPayload
		}
		if chainLen == 0 {
			leafDER = body[offset : offset+certLen]
		}
		chainLen++
		offset += certLen
	}
	if leafDER == nil {
		return nil, ErrNotCertificate
	}

	summary, err := ParseX509DER(leafDER)
	if err != nil {
		return nil, err
	}
	summary.ChainLength = chainLen
	return summary, nil
}

type rawX509Cert struct {
	TBS                rawTBSCertificate
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

type rawTBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	UniqueID           asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString `asn1:"optional,tag:2"`
	Extensions         []rawX509Ext   `asn1:"optional,explicit,tag:3"`
}

type rawX509Ext struct {
	ID       asn1.RawValue
	Critical bool `asn1:"optional"`
	Value    []byte
}

type rawATV struct {
	Type  asn1.RawValue
	Value asn1.RawValue
}

// ParseX509DER parses a DER-encoded X.509 certificate to extract wire-order JA4X OIDs
// and forensic certificate metadata.
func ParseX509DER(der []byte) (*CertificateSummary, error) {
	var raw rawX509Cert
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, ErrMalformedPayload
	}

	issuerOIDs, err := extractNameOIDs(raw.TBS.Issuer)
	if err != nil {
		return nil, ErrMalformedPayload
	}
	subjectOIDs, err := extractNameOIDs(raw.TBS.Subject)
	if err != nil {
		return nil, ErrMalformedPayload
	}

	extOIDs := make([]string, 0, len(raw.TBS.Extensions))
	for _, ext := range raw.TBS.Extensions {
		if ext.ID.Tag == asn1.TagOID && len(ext.ID.Bytes) > 0 {
			extOIDs = append(extOIDs, hex.EncodeToString(ext.ID.Bytes))
		}
	}

	summary := &CertificateSummary{
		ChainLength:   1,
		IssuerOIDs:    issuerOIDs,
		SubjectOIDs:   subjectOIDs,
		ExtensionOIDs: extOIDs,
	}

	if cert, err := x509.ParseCertificate(der); err == nil {
		summary.SubjectCN = cert.Subject.CommonName
		summary.IssuerCN = cert.Issuer.CommonName
		if len(cert.DNSNames) > 0 {
			summary.DNSNames = append([]string(nil), cert.DNSNames...)
		}
		summary.NotBefore = cert.NotBefore
		summary.NotAfter = cert.NotAfter
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			summary.IsSelfSigned = true
		}
	}

	return summary, nil
}

func extractNameOIDs(nameRV asn1.RawValue) ([]string, error) {
	if nameRV.Tag != asn1.TagSequence || !nameRV.IsCompound {
		return nil, ErrMalformedPayload
	}
	var oids []string
	rest := nameRV.Bytes
	for len(rest) > 0 {
		var rdn asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rdn)
		if err != nil {
			return nil, err
		}
		rdnRest := rdn.Bytes
		for len(rdnRest) > 0 {
			var atv rawATV
			rdnRest, err = asn1.Unmarshal(rdnRest, &atv)
			if err != nil {
				return nil, err
			}
			if atv.Type.Tag == asn1.TagOID && len(atv.Type.Bytes) > 0 {
				oids = append(oids, hex.EncodeToString(atv.Type.Bytes))
			}
		}
	}
	return oids, nil
}
