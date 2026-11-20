package ja4

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Helper to construct a synthetic TLS ClientHello record.
func buildSyntheticClientHello(sni string, alpn string, tls13 bool, ciphers []uint16, exts []uint16) []byte {
	return buildSyntheticClientHelloFull(sni, nonEmptySlice(alpn), tls13, 0x0303, ciphers, exts, nil)
}

func nonEmptySlice(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func buildSyntheticClientHelloFull(sni string, alpns []string, tls13 bool, legacyVer uint16, ciphers []uint16, exts []uint16, sigAlgs []uint16) []byte {
	var chBody bytes.Buffer

	binary.Write(&chBody, binary.BigEndian, legacyVer)
	chBody.Write(make([]byte, 32)) // Random
	chBody.WriteByte(0x00)         // Session ID len

	binary.Write(&chBody, binary.BigEndian, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		binary.Write(&chBody, binary.BigEndian, c)
	}

	chBody.Write([]byte{0x01, 0x00}) // Compression: null

	var extsBuf bytes.Buffer

	if sni != "" {
		binary.Write(&extsBuf, binary.BigEndian, uint16(ExtServerName))
		sniData := []byte(sni)
		serverNameListLen := uint16(len(sniData) + 3)
		binary.Write(&extsBuf, binary.BigEndian, serverNameListLen+2)
		binary.Write(&extsBuf, binary.BigEndian, serverNameListLen)
		extsBuf.WriteByte(0x00)
		binary.Write(&extsBuf, binary.BigEndian, uint16(len(sniData)))
		extsBuf.Write(sniData)
	}

	if len(alpns) > 0 {
		var alpnList bytes.Buffer
		for _, a := range alpns {
			alpnList.WriteByte(byte(len(a)))
			alpnList.WriteString(a)
		}
		binary.Write(&extsBuf, binary.BigEndian, uint16(ExtALPN))
		binary.Write(&extsBuf, binary.BigEndian, uint16(alpnList.Len()+2))
		binary.Write(&extsBuf, binary.BigEndian, uint16(alpnList.Len()))
		extsBuf.Write(alpnList.Bytes())
	}

	if tls13 {
		binary.Write(&extsBuf, binary.BigEndian, uint16(ExtSupportedVersions))
		binary.Write(&extsBuf, binary.BigEndian, uint16(5))
		extsBuf.WriteByte(0x04) // GREASE + TLS 1.3
		binary.Write(&extsBuf, binary.BigEndian, uint16(0x2a2a))
		binary.Write(&extsBuf, binary.BigEndian, uint16(0x0304))
	}

	if len(sigAlgs) > 0 {
		binary.Write(&extsBuf, binary.BigEndian, uint16(ExtSupportedAlgorithms))
		binary.Write(&extsBuf, binary.BigEndian, uint16(len(sigAlgs)*2+2))
		binary.Write(&extsBuf, binary.BigEndian, uint16(len(sigAlgs)*2))
		for _, sa := range sigAlgs {
			binary.Write(&extsBuf, binary.BigEndian, sa)
		}
	}

	for _, ext := range exts {
		binary.Write(&extsBuf, binary.BigEndian, ext)
		binary.Write(&extsBuf, binary.BigEndian, uint16(0))
	}

	if extsBuf.Len() > 0 {
		binary.Write(&chBody, binary.BigEndian, uint16(extsBuf.Len()))
		chBody.Write(extsBuf.Bytes())
	}

	return wrapTLSHandshakeRecord(HandshakeTypeClientHello, 0x0301, chBody.Bytes())
}

func buildSyntheticServerHello(serverVer, negVer, cipher uint16, alpn string, extOrder []uint16, hrr bool) []byte {
	var shBody bytes.Buffer
	binary.Write(&shBody, binary.BigEndian, serverVer)
	if hrr {
		shBody.Write(helloRetryRequestRandom[:])
	} else {
		shBody.Write(make([]byte, 32))
	}
	shBody.WriteByte(0x00) // Session ID len
	binary.Write(&shBody, binary.BigEndian, cipher)
	shBody.WriteByte(0x00) // Compression

	var extsBuf bytes.Buffer
	for _, ext := range extOrder {
		switch ext {
		case ExtSupportedVersions:
			binary.Write(&extsBuf, binary.BigEndian, uint16(ExtSupportedVersions))
			binary.Write(&extsBuf, binary.BigEndian, uint16(2))
			binary.Write(&extsBuf, binary.BigEndian, negVer)
		case ExtKeyShare:
			binary.Write(&extsBuf, binary.BigEndian, uint16(ExtKeyShare))
			binary.Write(&extsBuf, binary.BigEndian, uint16(6))
			binary.Write(&extsBuf, binary.BigEndian, uint16(0x001d)) // x25519
			binary.Write(&extsBuf, binary.BigEndian, uint16(2))
			extsBuf.Write([]byte{0xaa, 0xbb})
		case ExtALPN:
			if alpn != "" {
				binary.Write(&extsBuf, binary.BigEndian, uint16(ExtALPN))
				listLen := uint16(1 + len(alpn))
				binary.Write(&extsBuf, binary.BigEndian, listLen+2)
				binary.Write(&extsBuf, binary.BigEndian, listLen)
				extsBuf.WriteByte(byte(len(alpn)))
				extsBuf.WriteString(alpn)
			}
		default:
			binary.Write(&extsBuf, binary.BigEndian, ext)
			binary.Write(&extsBuf, binary.BigEndian, uint16(0))
		}
	}

	if extsBuf.Len() > 0 {
		binary.Write(&shBody, binary.BigEndian, uint16(extsBuf.Len()))
		shBody.Write(extsBuf.Bytes())
	}

	return wrapTLSHandshakeRecord(HandshakeTypeServerHello, 0x0303, shBody.Bytes())
}

func buildSyntheticCertificateRecord(certsDER ...[]byte) []byte {
	var listBuf bytes.Buffer
	for _, der := range certsDER {
		n := len(der)
		listBuf.WriteByte(byte(n >> 16))
		listBuf.WriteByte(byte(n >> 8))
		listBuf.WriteByte(byte(n))
		listBuf.Write(der)
	}
	var body bytes.Buffer
	total := listBuf.Len()
	body.WriteByte(byte(total >> 16))
	body.WriteByte(byte(total >> 8))
	body.WriteByte(byte(total))
	body.Write(listBuf.Bytes())

	return wrapTLSHandshakeRecord(HandshakeTypeCertificate, 0x0303, body.Bytes())
}

func wrapTLSHandshakeRecord(hsType uint8, recVer uint16, body []byte) []byte {
	var hsBuf bytes.Buffer
	hsBuf.WriteByte(hsType)
	hsLen := len(body)
	hsBuf.WriteByte(byte(hsLen >> 16))
	hsBuf.WriteByte(byte(hsLen >> 8))
	hsBuf.WriteByte(byte(hsLen))
	hsBuf.Write(body)

	var recBuf bytes.Buffer
	recBuf.WriteByte(RecordTypeHandshake)
	binary.Write(&recBuf, binary.BigEndian, recVer)
	binary.Write(&recBuf, binary.BigEndian, uint16(hsBuf.Len()))
	recBuf.Write(hsBuf.Bytes())
	return recBuf.Bytes()
}

func generateTestCertDER(t *testing.T, cn string, org string, dnsNames []string, withExts bool, notBefore, notAfter time.Time) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating ECDSA key: %v", err)
	}
	subj := pkix.Name{CommonName: cn}
	if org != "" {
		subj.Organization = []string{org}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      subj,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	if withExts {
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.DNSNames = dnsNames
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed creating X.509 certificate: %v", err)
	}
	return der
}

func buildEthIPv4TCPFrame(srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, vlanTags ...uint16) []byte {
	var frame bytes.Buffer
	frame.Write(make([]byte, 12)) // MACs
	for i, tag := range vlanTags {
		if i == 0 && len(vlanTags) > 1 {
			binary.Write(&frame, binary.BigEndian, uint16(EtherTypeQinQ))
		} else {
			binary.Write(&frame, binary.BigEndian, uint16(EtherTypeVLAN))
		}
		binary.Write(&frame, binary.BigEndian, tag)
	}
	binary.Write(&frame, binary.BigEndian, uint16(EtherTypeIPv4))
	frame.Write(buildIPv4TCPPacket(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload))
	return frame.Bytes()
}

func buildIPv4TCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	var pkt bytes.Buffer
	ipLen := uint16(20 + 20 + len(payload))
	pkt.WriteByte(0x45)
	pkt.WriteByte(0x00)
	binary.Write(&pkt, binary.BigEndian, ipLen)
	binary.Write(&pkt, binary.BigEndian, uint16(0x1234))
	binary.Write(&pkt, binary.BigEndian, uint16(0))
	pkt.WriteByte(64)
	pkt.WriteByte(IPProtoTCP)
	binary.Write(&pkt, binary.BigEndian, uint16(0))
	pkt.Write(net.ParseIP(srcIP).To4())
	pkt.Write(net.ParseIP(dstIP).To4())

	pkt.Write(buildTCPSegment(srcPort, dstPort, seq, ack, flags, payload))
	return pkt.Bytes()
}

func buildIPv6TCPPacket(srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte, withExtHdr bool) []byte {
	tcpSeg := buildTCPSegment(srcPort, dstPort, seq, ack, flags, payload)
	var body bytes.Buffer
	nextHdr := uint8(IPProtoTCP)
	if withExtHdr {
		nextHdr = IPProtoHopByHop
		// 8-byte Hop-by-Hop header pointing to Destination Options
		body.Write([]byte{IPProtoDestOpts, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		// 8-byte Destination Options header pointing to TCP
		body.Write([]byte{IPProtoTCP, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
	body.Write(tcpSeg)

	var pkt bytes.Buffer
	pkt.Write([]byte{0x60, 0x00, 0x00, 0x00}) // IPv6 version 6
	binary.Write(&pkt, binary.BigEndian, uint16(body.Len()))
	pkt.WriteByte(nextHdr)
	pkt.WriteByte(64)
	pkt.Write(net.ParseIP(srcIP).To16())
	pkt.Write(net.ParseIP(dstIP).To16())
	pkt.Write(body.Bytes())
	return pkt.Bytes()
}

func buildTCPSegment(srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	var seg bytes.Buffer
	binary.Write(&seg, binary.BigEndian, srcPort)
	binary.Write(&seg, binary.BigEndian, dstPort)
	binary.Write(&seg, binary.BigEndian, seq)
	binary.Write(&seg, binary.BigEndian, ack)
	seg.WriteByte(0x50)
	seg.WriteByte(flags)
	binary.Write(&seg, binary.BigEndian, uint16(65535))
	binary.Write(&seg, binary.BigEndian, uint16(0))
	binary.Write(&seg, binary.BigEndian, uint16(0))
	seg.Write(payload)
	return seg.Bytes()
}

func writePCAPNGBlock(w *bytes.Buffer, order binary.ByteOrder, blockType uint32, body []byte) {
	pad := (4 - (len(body) % 4)) % 4
	totalLen := uint32(12 + len(body) + pad)
	order.Uint32(make([]byte, 4)) // sanity
	binary.Write(w, order, blockType)
	binary.Write(w, order, totalLen)
	w.Write(body)
	for i := 0; i < pad; i++ {
		w.WriteByte(0)
	}
	binary.Write(w, order, totalLen)
}

func buildPCAPNGSHB(order binary.ByteOrder) []byte {
	var body bytes.Buffer
	binary.Write(&body, order, PCAPNGByteOrderMagic)
	binary.Write(&body, order, uint16(1)) // major
	binary.Write(&body, order, uint16(0)) // minor
	binary.Write(&body, order, int64(-1)) // section length unspecified
	var out bytes.Buffer
	writePCAPNGBlock(&out, order, PCAPNGBlockSHB, body.Bytes())
	return out.Bytes()
}

func buildPCAPNGIDB(order binary.ByteOrder, linkType uint16, snapLen uint32, name string, tsResol uint8) []byte {
	var body bytes.Buffer
	binary.Write(&body, order, linkType)
	binary.Write(&body, order, uint16(0)) // reserved
	binary.Write(&body, order, snapLen)

	writeOpt := func(code uint16, val []byte) {
		binary.Write(&body, order, code)
		binary.Write(&body, order, uint16(len(val)))
		body.Write(val)
		for pad := (4 - (len(val) % 4)) % 4; pad > 0; pad-- {
			body.WriteByte(0)
		}
	}
	if name != "" {
		writeOpt(PCAPNGOptIfName, []byte(name))
	}
	if tsResol != 0 {
		writeOpt(PCAPNGOptIfTSResol, []byte{tsResol})
	}
	// End of options
	binary.Write(&body, order, uint16(0))
	binary.Write(&body, order, uint16(0))

	var out bytes.Buffer
	writePCAPNGBlock(&out, order, PCAPNGBlockIDB, body.Bytes())
	return out.Bytes()
}

func buildPCAPNGEPB(order binary.ByteOrder, ifaceID uint32, rawTS uint64, frame []byte) []byte {
	var body bytes.Buffer
	binary.Write(&body, order, ifaceID)
	binary.Write(&body, order, uint32(rawTS>>32))
	binary.Write(&body, order, uint32(rawTS&0xffffffff))
	binary.Write(&body, order, uint32(len(frame)))
	binary.Write(&body, order, uint32(len(frame)))
	body.Write(frame)
	for pad := (4 - (len(frame) % 4)) % 4; pad > 0; pad-- {
		body.WriteByte(0)
	}

	var out bytes.Buffer
	writePCAPNGBlock(&out, order, PCAPNGBlockEPB, body.Bytes())
	return out.Bytes()
}

func TestIsGREASE(t *testing.T) {
	greaseList := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, g := range greaseList {
		if !IsGREASE(g) {
			t.Errorf("expected 0x%04x to be GREASE", g)
		}
	}

	nonGrease := []uint16{0x0000, 0x002f, 0x1301, 0x1302, 0xc02b, 0x000a, 0x0a1a}
	for _, ng := range nonGrease {
		if IsGREASE(ng) {
			t.Errorf("expected 0x%04x NOT to be GREASE", ng)
		}
	}
}

func TestParseClientHelloAndJA4(t *testing.T) {
	ciphers := []uint16{0x1303, 0x1301, 0x1302, 0x0a0a} // 0x0a0a is GREASE
	exts := []uint16{0x000b, 0x000a, 0x1a1a}            // 0x1a1a is GREASE
	sigAlgs := []uint16{0x0403, 0x0804, 0x3a3a}         // 0x3a3a is GREASE

	raw := buildSyntheticClientHelloFull("api.example.com", []string{"h2", "http/1.1"}, true, 0x0303, ciphers, exts, sigAlgs)

	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if ch.SNI != "api.example.com" || !ch.IsDomainSNI {
		t.Errorf("unexpected SNI: %q (isDomain=%v)", ch.SNI, ch.IsDomainSNI)
	}
	if ch.ALPN != "h2" || len(ch.ALPNs) != 2 || ch.ALPNs[1] != "http/1.1" {
		t.Errorf("unexpected ALPNs: primary=%q all=%v", ch.ALPN, ch.ALPNs)
	}
	if ch.EffectiveVersion != 0x0304 {
		t.Errorf("expected TLS 1.3 (0x0304), got 0x%04x", ch.EffectiveVersion)
	}
	if len(ch.FilteredCiphers) != 3 {
		t.Errorf("expected 3 non-GREASE ciphers, got %d", len(ch.FilteredCiphers))
	}
	if ch.GREASECount != 4 { // cipher + ext + supported_versions + sig_alg
		t.Errorf("expected 4 GREASE values counted, got %d", ch.GREASECount)
	}

	ja4 := ch.ComputeJA4()
	if len(ja4) != 36 {
		t.Errorf("invalid JA4 length: %s (len %d)", ja4, len(ja4))
	}

	// Part A: t13d0306h2 -> 3 non-GREASE ciphers, 6 non-GREASE extensions
	// (SNI 0x0000, ALPN 0x0010, supported_versions 0x002b, sig_algs 0x000d, 0x000b, 0x000a).
	if ja4[:10] != "t13d0306h2" {
		t.Errorf("unexpected JA4 part A: got %s, want t13d0306h2", ja4[:10])
	}

	// Verify JA4_r (sorted ciphers, sorted exts excluding SNI & ALPN, unsorted sigalgs).
	wantRaw := "t13d0306h2_1301,1302,1303_000a,000b,000d,002b_0403,0804"
	if gotRaw := ch.ComputeJA4Raw(); gotRaw != wantRaw {
		t.Errorf("unexpected JA4_r:\n got: %s\nwant: %s", gotRaw, wantRaw)
	}

	// Verify JA4_o differs from JA4 because wire cipher & extension orders were unsorted.
	ja4o := ch.ComputeJA4Original()
	if ja4o == ja4 {
		t.Errorf("expected JA4_o (%s) to differ from sorted JA4 (%s)", ja4o, ja4)
	}
}

func TestClientHelloNonAlnumALPNAndIPSNI(t *testing.T) {
	// Non-alphanumeric ALPN bytes: first byte 0x9a -> '9', last byte 0x1b -> 'b' => "9b"
	raw := buildSyntheticClientHelloFull("198.51.100.10", []string{"\x9a\x1b"}, false, 0x0303, []uint16{0xc02f}, []uint16{0x0017}, nil)
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}
	if ch.IsDomainSNI {
		t.Errorf("expected IP-literal SNI not to be marked as domain")
	}
	ja4 := ch.ComputeJA4()
	// t12i01039b (1 cipher, 3 exts: SNI, ALPN, 0x0017, ALPN="9b")
	if !strings.HasPrefix(ja4, "t12i01039b_") {
		t.Errorf("unexpected JA4 prefix for IP SNI + binary ALPN: got %s", ja4)
	}
}

func TestClientHelloMultiRecordFragmentation(t *testing.T) {
	full := buildSyntheticClientHello("frag.example.org", "h2", true, []uint16{0x1301, 0x1302}, []uint16{0x000a, 0x000b})
	hsPayload := full[5:]
	split := len(hsPayload) / 2

	// Split a single ClientHello handshake message across two TLS Handshake records.
	var twoRecords bytes.Buffer
	twoRecords.WriteByte(RecordTypeHandshake)
	binary.Write(&twoRecords, binary.BigEndian, uint16(0x0301))
	binary.Write(&twoRecords, binary.BigEndian, uint16(split))
	twoRecords.Write(hsPayload[:split])

	twoRecords.WriteByte(RecordTypeHandshake)
	binary.Write(&twoRecords, binary.BigEndian, uint16(0x0301))
	binary.Write(&twoRecords, binary.BigEndian, uint16(len(hsPayload)-split))
	twoRecords.Write(hsPayload[split:])

	ch, err := ParseClientHello(twoRecords.Bytes())
	if err != nil {
		t.Fatalf("ParseClientHello on fragmented records failed: %v", err)
	}
	if ch.SNI != "frag.example.org" {
		t.Errorf("expected SNI frag.example.org, got %q", ch.SNI)
	}
}

func TestParseServerHelloAndJA4S(t *testing.T) {
	// Standard TLS 1.3 ServerHello: supported_versions (0x002b), key_share (0x0033), cipher 0x1301.
	shRaw1 := buildSyntheticServerHello(0x0303, 0x0304, 0x1301, "", []uint16{ExtSupportedVersions, ExtKeyShare}, false)
	sh1, err := ParseServerHello(shRaw1)
	if err != nil {
		t.Fatalf("ParseServerHello failed: %v", err)
	}
	if sh1.EffectiveVersion != 0x0304 || sh1.CipherSuite != 0x1301 || sh1.IsHelloRetryRequest {
		t.Fatalf("unexpected ServerHello summary: %+v", sh1)
	}
	wantJA4S := "t130200_1301_a56c5b993250"
	if got := sh1.ComputeJA4S(); got != wantJA4S {
		t.Errorf("JA4S mismatch: got %s, want %s", got, wantJA4S)
	}
	if gotRaw := sh1.ComputeJA4SRaw(); gotRaw != "t130200_1301_002b,0033" {
		t.Errorf("JA4S_r mismatch: got %s", gotRaw)
	}

	// Reversed extension order MUST change JA4S hash (extensions are NOT sorted in JA4S).
	shRaw2 := buildSyntheticServerHello(0x0303, 0x0304, 0x1301, "", []uint16{ExtKeyShare, ExtSupportedVersions}, false)
	sh2, err := ParseServerHello(shRaw2)
	if err != nil {
		t.Fatalf("ParseServerHello reversed failed: %v", err)
	}
	if got := sh2.ComputeJA4S(); got != "t130200_1301_234ea6891581" {
		t.Errorf("JA4S wire-order mismatch: got %s, want t130200_1301_234ea6891581", got)
	}

	// HelloRetryRequest + weak cipher check.
	hrrRaw := buildSyntheticServerHello(0x0303, 0x0304, 0x0005, "h2", []uint16{ExtALPN}, true)
	hrr, err := ParseServerHello(hrrRaw)
	if err != nil {
		t.Fatalf("ParseServerHello HRR failed: %v", err)
	}
	if !hrr.IsHelloRetryRequest {
		t.Errorf("expected IsHelloRetryRequest=true")
	}
	if !IsWeakCipherSuite(hrr.CipherSuite) {
		t.Errorf("expected cipher 0x0005 (RC4-SHA) to be flagged weak")
	}
	if !strings.HasPrefix(hrr.ComputeJA4S(), "t1201h2_0005_") {
		t.Errorf("unexpected HRR JA4S: %s", hrr.ComputeJA4S())
	}
}

func TestParseCertificateAndJA4X(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	// Minimal CN-only self-signed certificate with no v3 extensions.
	minimalDER := generateTestCertDER(t, "c2-implant.local", "", nil, false, now.Add(-time.Hour), now.Add(time.Hour))
	certRec := buildSyntheticCertificateRecord(minimalDER)

	cs, err := ParseCertificateMessage(certRec)
	if err != nil {
		t.Fatalf("ParseCertificateMessage failed: %v", err)
	}
	if cs.SubjectCN != "c2-implant.local" || !cs.IsSelfSigned || cs.ChainLength != 1 {
		t.Errorf("unexpected minimal cert metadata: %+v", cs)
	}
	wantJA4X := "7022c563de38_7022c563de38_000000000000"
	if got := cs.ComputeJA4X(); got != wantJA4X {
		t.Errorf("JA4X mismatch: got %s (raw=%s), want %s", got, cs.ComputeJA4XRaw(), wantJA4X)
	}
	if cs.IsExpiredAt(now) {
		t.Errorf("expected cert to be valid at now")
	}
	if !cs.IsExpiredAt(now.Add(2 * time.Hour)) {
		t.Errorf("expected cert to be expired 2h later")
	}

	// Full v3 certificate with SANs and Organization.
	fullDER := generateTestCertDER(t, "api.aether.io", "Aether Lab", []string{"api.aether.io", "edge.aether.io"}, true, now.Add(-time.Hour), now.Add(24*time.Hour))
	chainRec := buildSyntheticCertificateRecord(fullDER, minimalDER)
	cs2, err := ParseCertificateMessage(chainRec)
	if err != nil {
		t.Fatalf("ParseCertificateMessage chain failed: %v", err)
	}
	if cs2.ChainLength != 2 {
		t.Errorf("expected chain length 2, got %d", cs2.ChainLength)
	}
	if len(cs2.ExtensionOIDs) == 0 {
		t.Errorf("expected non-empty X.509v3 extension OIDs")
	}
	if len(cs2.DNSNames) != 2 {
		t.Errorf("expected 2 SAN DNSNames, got %v", cs2.DNSNames)
	}
	if len(cs2.ComputeJA4X()) != 38 { // 12 + 1 + 12 + 1 + 12
		t.Errorf("unexpected JA4X length: %s", cs2.ComputeJA4X())
	}
}

func TestShannonEntropy(t *testing.T) {
	zeros := make([]byte, 100)
	if ent := ComputeShannonEntropy(zeros); ent != 0.0 {
		t.Errorf("expected 0 entropy for uniform data, got %f", ent)
	}

	fullByteRange := make([]byte, 256)
	for i := 0; i < 256; i++ {
		fullByteRange[i] = byte(i)
	}
	if ent := ComputeShannonEntropy(fullByteRange); ent < 7.99 || ent > 8.01 {
		t.Errorf("expected 8.0 entropy for complete byte spectrum, got %f", ent)
	}
}

func TestPCAPReaderClassicAndVLANAndIPv6(t *testing.T) {
	var pcapBuf bytes.Buffer
	binary.Write(&pcapBuf, binary.BigEndian, PCAPMagicSameEndian)
	binary.Write(&pcapBuf, binary.BigEndian, uint16(2))
	binary.Write(&pcapBuf, binary.BigEndian, uint16(4))
	binary.Write(&pcapBuf, binary.BigEndian, int32(0))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(0))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(65535))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(LinkTypeEthernet))

	// Packet 1: Double-tagged QinQ VLAN + IPv4 + trailing Ethernet zero padding.
	tlsPayload1 := buildSyntheticClientHello("telemetry.aether.local", "http/1.1", false, []uint16{0xc02b, 0xc02f}, nil)
	frame1 := buildEthIPv4TCPFrame("192.168.1.50", "10.0.0.1", 54321, 443, 100, 0, TCPFlagPSH|TCPFlagACK, tlsPayload1, 100, 200)
	frame1 = append(frame1, 0x00, 0x00, 0x00, 0x00) // Simulated Ethernet trailer padding

	binary.Write(&pcapBuf, binary.BigEndian, uint32(1700000000))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(500000))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(len(frame1)))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(len(frame1)))
	pcapBuf.Write(frame1)

	// Packet 2: IPv6 with Hop-by-Hop + Destination Options extension headers.
	tlsPayload2 := buildSyntheticClientHello("ipv6.aether.local", "h2", true, []uint16{0x1301, 0x1302, 0x1303}, []uint16{0x000a})
	var frame2 bytes.Buffer
	frame2.Write(make([]byte, 12))
	binary.Write(&frame2, binary.BigEndian, uint16(EtherTypeIPv6))
	frame2.Write(buildIPv6TCPPacket("2001:db8::1", "2001:db8::2", 60000, 443, 200, 0, TCPFlagPSH|TCPFlagACK, tlsPayload2, true))

	binary.Write(&pcapBuf, binary.BigEndian, uint32(1700000001))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(250000))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(frame2.Len()))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(frame2.Len()))
	pcapBuf.Write(frame2.Bytes())

	reader, err := NewPCAPReader(&pcapBuf)
	if err != nil {
		t.Fatalf("NewPCAPReader failed: %v", err)
	}
	if reader.Format != CaptureFormatPCAP {
		t.Errorf("expected format pcap, got %s", reader.Format)
	}

	pkt1, err := reader.NextPacket()
	if err != nil {
		t.Fatalf("NextPacket 1 failed: %v", err)
	}
	if len(pkt1.Payload) != len(tlsPayload1) {
		t.Errorf("expected Ethernet padding to be stripped: got payload len %d, want %d", len(pkt1.Payload), len(tlsPayload1))
	}

	pkt2, err := reader.NextPacket()
	if err != nil {
		t.Fatalf("NextPacket 2 (IPv6) failed: %v", err)
	}
	if pkt2.SrcIP.String() != "2001:db8::1" || pkt2.DstIP.String() != "2001:db8::2" {
		t.Errorf("unexpected IPv6 addresses: %s -> %s", pkt2.SrcIP, pkt2.DstIP)
	}

	// Ensure reading pkt2 did not overwrite pkt1's slices.
	if pkt1.SrcIP.String() != "192.168.1.50" {
		t.Errorf("packet buffer aliasing detected: pkt1 SrcIP became %s", pkt1.SrcIP)
	}

	engine := NewForensicsEngine("deep")
	flow1, isCH1 := engine.ProcessPacket(pkt1)
	if !isCH1 || flow1.SNI != "telemetry.aether.local" || flow1.ALPN != "http/1.1" || flow1.JA4 == "" {
		t.Fatalf("unexpected flow1: isCH=%v flow=%+v", isCH1, flow1)
	}
	flow2, isCH2 := engine.ProcessPacket(pkt2)
	if !isCH2 || flow2.SNI != "ipv6.aether.local" || flow2.TLSVersion != "TLS 1.3" {
		t.Fatalf("unexpected flow2: isCH=%v flow=%+v", isCH2, flow2)
	}
}

func TestPCAPNGReaderMultiInterface(t *testing.T) {
	order := binary.LittleEndian
	var buf bytes.Buffer

	// SHB + 3 interfaces (Ethernet us, RawIP ns, Loopback binary 2^-10)
	buf.Write(buildPCAPNGSHB(order))
	buf.Write(buildPCAPNGIDB(order, LinkTypeEthernet, 65535, "eth0", 6))
	buf.Write(buildPCAPNGIDB(order, LinkTypeRawIPAlt, 65535, "tun0", 9))
	buf.Write(buildPCAPNGIDB(order, LinkTypeNull, 65535, "lo0", 0x80|10))

	// Insert an Interface Statistics Block (should be skipped cleanly).
	var isb bytes.Buffer
	binary.Write(&isb, order, uint32(0))
	binary.Write(&isb, order, uint64(0))
	writePCAPNGBlock(&buf, order, PCAPNGBlockISB, isb.Bytes())

	// EPB 0 on eth0 (microseconds: 1700000000.123456)
	ch1 := buildSyntheticClientHello("eth0.sard.test", "h2", true, []uint16{0x1301, 0x1302, 0x1303}, []uint16{0x000a})
	frame0 := buildEthIPv4TCPFrame("10.0.0.10", "10.0.0.20", 40001, 443, 1, 0, TCPFlagPSH|TCPFlagACK, ch1)
	buf.Write(buildPCAPNGEPB(order, 0, 1700000000_123456, frame0))

	// EPB 1 on tun0 (nanoseconds: 1700000001.000000789)
	ch2 := buildSyntheticClientHello("tun0.sard.test", "h2", true, []uint16{0x1301, 0x1302, 0x1303}, []uint16{0x000a})
	frame1 := buildIPv4TCPPacket("10.1.0.10", "10.1.0.20", 40002, 443, 1, 0, TCPFlagPSH|TCPFlagACK, ch2)
	buf.Write(buildPCAPNGEPB(order, 1, 1700000001_000000789, frame1))

	// EPB 2 on lo0 (BSD loopback AF_INET=2, binary 2^-10 s => 1700000002.5 s)
	ch3 := buildSyntheticClientHello("lo0.sard.test", "h2", true, []uint16{0x1301, 0x1302, 0x1303}, []uint16{0x000a})
	var frame2 bytes.Buffer
	binary.Write(&frame2, binary.LittleEndian, uint32(2)) // AF_INET
	frame2.Write(buildIPv4TCPPacket("127.0.0.1", "127.0.0.1", 40003, 8443, 1, 0, TCPFlagPSH|TCPFlagACK, ch3))
	rawBinaryTS := (uint64(1700000002) << 10) | 512 // +0.5s
	buf.Write(buildPCAPNGEPB(order, 2, rawBinaryTS, frame2.Bytes()))

	reader, err := NewPCAPReader(&buf)
	if err != nil {
		t.Fatalf("NewPCAPReader PCAP-NG failed: %v", err)
	}
	if reader.Format != CaptureFormatPCAPNG {
		t.Errorf("expected pcapng format, got %s", reader.Format)
	}

	p0, err := reader.NextPacket()
	if err != nil {
		t.Fatalf("p0 failed: %v", err)
	}
	if p0.InterfaceID != 0 || p0.Timestamp.Unix() != 1700000000 || p0.Timestamp.Nanosecond() != 123456000 {
		t.Errorf("unexpected p0 metadata: iface=%d ts=%v", p0.InterfaceID, p0.Timestamp)
	}

	p1, err := reader.NextPacket()
	if err != nil {
		t.Fatalf("p1 failed: %v", err)
	}
	if p1.InterfaceID != 1 || p1.Timestamp.Unix() != 1700000001 || p1.Timestamp.Nanosecond() != 789 {
		t.Errorf("unexpected p1 metadata: iface=%d ts=%v", p1.InterfaceID, p1.Timestamp)
	}

	p2, err := reader.NextPacket()
	if err != nil {
		t.Fatalf("p2 failed: %v", err)
	}
	if p2.InterfaceID != 2 || p2.Timestamp.Unix() != 1700000002 || p2.Timestamp.Nanosecond() != 500000000 {
		t.Errorf("unexpected p2 metadata: iface=%d ts=%v", p2.InterfaceID, p2.Timestamp)
	}

	if _, err := reader.NextPacket(); err != io.EOF {
		t.Errorf("expected io.EOF at end of PCAP-NG, got %v", err)
	}

	ifaces := reader.Interfaces()
	if len(ifaces) != 3 || ifaces[0].Name != "eth0" || ifaces[1].Name != "tun0" || ifaces[2].Name != "lo0" {
		t.Errorf("unexpected PCAP-NG interfaces: %+v", ifaces)
	}
}

func TestMultiStreamTCPReassemblyAndCoalescedRecords(t *testing.T) {
	engine := NewForensicsEngine("deep")
	t0 := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	clientIP := net.ParseIP("10.10.1.5").To4()
	serverIP := net.ParseIP("198.51.100.42").To4()

	// 1. SYN packet establishing sequence base 1000 -> nextSeq 1001.
	engine.ProcessPacketEvent(&Packet{
		Timestamp: t0,
		SrcIP:     clientIP,
		DstIP:     serverIP,
		SrcPort:   50000,
		DstPort:   443,
		Protocol:  IPProtoTCP,
		TCPFlags:  TCPFlagSYN,
		SeqNum:    1000,
	})

	// 2. Fragment ClientHello across 3 TCP segments and deliver out of order: seg1, seg3, seg2 (retransmit seg2).
	chBytes := buildSyntheticClientHello("reassembled.aether.io", "h2", true, []uint16{0x1301, 0x1302, 0x1303}, []uint16{0x000a, 0x000b})
	cut1 := 20
	cut2 := 55
	seg1 := chBytes[:cut1]
	seg2 := chBytes[cut1:cut2]
	seg3 := chBytes[cut2:]

	// Send seg1 (seq=1001)
	_, evs := engine.ProcessPacketEvent(&Packet{
		Timestamp: t0.Add(1 * time.Millisecond),
		SrcIP:     clientIP,
		DstIP:     serverIP,
		SrcPort:   50000,
		DstPort:   443,
		Protocol:  IPProtoTCP,
		TCPFlags:  TCPFlagACK,
		SeqNum:    1001,
		Payload:   seg1,
	})
	if len(evs) != 0 {
		t.Fatalf("expected 0 events after partial seg1, got %d", len(evs))
	}

	// Send seg3 out of order (seq=1001+cut2)
	_, evs = engine.ProcessPacketEvent(&Packet{
		Timestamp: t0.Add(2 * time.Millisecond),
		SrcIP:     clientIP,
		DstIP:     serverIP,
		SrcPort:   50000,
		DstPort:   443,
		Protocol:  IPProtoTCP,
		TCPFlags:  TCPFlagPSH | TCPFlagACK,
		SeqNum:    uint32(1001 + cut2),
		Payload:   seg3,
	})
	if len(evs) != 0 {
		t.Fatalf("expected 0 events while gap remains, got %d", len(evs))
	}

	// Send missing seg2 (seq=1001+cut1) -> completes entire ClientHello!
	flow, evs := engine.ProcessPacketEvent(&Packet{
		Timestamp: t0.Add(3 * time.Millisecond),
		SrcIP:     clientIP,
		DstIP:     serverIP,
		SrcPort:   50000,
		DstPort:   443,
		Protocol:  IPProtoTCP,
		TCPFlags:  TCPFlagACK,
		SeqNum:    uint32(1001 + cut1),
		Payload:   seg2,
	})
	if len(evs) != 1 || evs[0].Type != EventClientHello {
		t.Fatalf("expected 1 reassembled ClientHello event, got %+v", evs)
	}
	if flow.SNI != "reassembled.aether.io" || flow.JA4 == "" {
		t.Errorf("unexpected reassembled ClientHello flow: %+v", flow)
	}

	// Duplicate retransmission of seg2 must NOT re-emit ClientHello.
	_, dupEvs := engine.ProcessPacketEvent(&Packet{
		Timestamp: t0.Add(4 * time.Millisecond),
		SrcIP:     clientIP,
		DstIP:     serverIP,
		SrcPort:   50000,
		DstPort:   443,
		Protocol:  IPProtoTCP,
		TCPFlags:  TCPFlagACK,
		SeqNum:    uint32(1001 + cut1),
		Payload:   seg2,
	})
	if len(dupEvs) != 0 {
		t.Errorf("retransmission should not emit duplicate events, got %d", len(dupEvs))
	}

	// 3. Server sends ServerHello + Certificate coalesced into one stream split across 2 TCP segments.
	shBytes := buildSyntheticServerHello(0x0303, 0x0303, 0xc02f, "h2", []uint16{ExtALPN}, false)
	certDER := generateTestCertDER(t, "reassembled.aether.io", "", nil, false, t0.Add(-time.Hour), t0.Add(time.Hour))
	certBytes := buildSyntheticCertificateRecord(certDER)
	serverStream := append(append([]byte(nil), shBytes...), certBytes...)
	mid := len(shBytes) + 15 // Split mid-Certificate!

	_, srvEvs1 := engine.ProcessPacketEvent(&Packet{
		Timestamp: t0.Add(28 * time.Millisecond), // RTT = 25ms after ClientHello completed at t0+3ms
		SrcIP:     serverIP,
		DstIP:     clientIP,
		SrcPort:   443,
		DstPort:   50000,
		Protocol:  IPProtoTCP,
		TCPFlags:  TCPFlagACK,
		SeqNum:    5000,
		Payload:   serverStream[:mid],
	})
	if len(srvEvs1) != 1 || srvEvs1[0].Type != EventServerHello {
		t.Fatalf("expected 1 ServerHello event from first server segment, got %+v", srvEvs1)
	}

	_, srvEvs2 := engine.ProcessPacketEvent(&Packet{
		Timestamp: t0.Add(29 * time.Millisecond),
		SrcIP:     serverIP,
		DstIP:     clientIP,
		SrcPort:   443,
		DstPort:   50000,
		Protocol:  IPProtoTCP,
		TCPFlags:  TCPFlagPSH | TCPFlagACK | TCPFlagFIN,
		SeqNum:    uint32(5000 + mid),
		Payload:   serverStream[mid:],
	})
	if len(srvEvs2) != 1 || srvEvs2[0].Type != EventCertificate {
		t.Fatalf("expected 1 Certificate event from second server segment, got %+v", srvEvs2)
	}

	// Verify bidirectional SessionRecord correlation.
	sessions := engine.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 correlated session, got %d", len(sessions))
	}
	sess := sessions[0]
	if sess.JA4 == "" || sess.JA4S == "" || sess.JA4X != "7022c563de38_7022c563de38_000000000000" {
		t.Errorf("incomplete correlated fingerprints: JA4=%q JA4S=%q JA4X=%q", sess.JA4, sess.JA4S, sess.JA4X)
	}
	if math.Abs(sess.HandshakeRTTMs-25.0) > 0.1 {
		t.Errorf("expected HandshakeRTTMs ~25.0, got %.3f", sess.HandshakeRTTMs)
	}
	if !sess.CertSelfSigned || sess.ThreatScore == 0 {
		t.Errorf("expected self-signed public cert + minimal JA4X threat score > 0, got score=%d reasons=%v", sess.ThreatScore, sess.ThreatReasons)
	}
}

func TestSignatureDBAndCustomJSON(t *testing.T) {
	db := DefaultSignatureDB()
	if db.Count() < 15 {
		t.Errorf("expected curated default signature DB, got count %d", db.Count())
	}

	// Built-in exact JA4 match
	m, ok := db.MatchJA4("t13d1516h2_8daaf6152771_e5627efa2ab1")
	if !ok || !m.Exact || m.Signature.Category != CategoryBenign {
		t.Errorf("expected exact Chrome benign match, got ok=%v match=%+v", ok, m)
	}

	// Built-in wildcard JA4 match
	m2, ok := db.MatchJA4("ts3i020000_abcdef012345_000000000000")
	if !ok || m2.Exact || m2.Signature.Category != CategorySuspicious {
		t.Errorf("expected wildcard SSL 3.0 match, got ok=%v match=%+v", ok, m2)
	}

	// Load custom JSON signatures (both Sard native and FoxIO JA4DB-style fields).
	customJSON := `{
		"signatures": [
			{
				"id": "custom-c2-wildcard",
				"type": "ja4",
				"pattern": "t12d02*",
				"name": "Custom Wildcard Probe",
				"category": "suspicious",
				"risk_score": 25
			},
			{
				"id": "custom-c2-specific",
				"type": "ja4",
				"pattern": "t12d0204h2_*",
				"name": "Custom Specific Malware",
				"category": "malicious",
				"risk_score": 80
			},
			{
				"application": "Internal Telemetry Agent",
				"ja4_fingerprint": "t13d0305h2_aaaaaaaaaaaa_bbbbbbbbbbbb",
				"ja4s_fingerprint": "t130200_1301_cccccccccccc",
				"category": "tool"
			}
		]
	}`
	n, err := db.LoadJSON(strings.NewReader(customJSON))
	if err != nil {
		t.Fatalf("LoadJSON failed: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 signatures loaded (2 native + 2 JA4DB fields), got %d", n)
	}

	// Specificity test: more specific wildcard should win over broader wildcard.
	mSpec, ok := db.MatchJA4("t12d0204h2_111111111111_222222222222")
	if !ok || mSpec.Signature.ID != "custom-c2-specific" || mSpec.Signature.RiskScore != 80 {
		t.Errorf("expected more specific wildcard to win, got ok=%v match=%+v", ok, mSpec)
	}

	mJA4DB, ok := db.MatchJA4S("t130200_1301_cccccccccccc")
	if !ok || mJA4DB.Signature.Name != "Internal Telemetry Agent" {
		t.Errorf("expected JA4DB-format JA4S signature match, got ok=%v match=%+v", ok, mJA4DB)
	}
}

func TestThreatHeuristicsBeaconAndReport(t *testing.T) {
	engine := NewForensicsEngine("deep")
	base := time.Date(2026, 11, 20, 15, 0, 0, 0, time.UTC)

	// Flow 1: Suspicious direct-IP TLS 1.0 barebones scanner + periodic beacon packets every 2.0s.
	scannerCH := buildSyntheticClientHelloFull("", nil, false, 0x0301, []uint16{0x002f}, nil, nil)
	src := net.ParseIP("192.168.10.5").To4()
	dst := net.ParseIP("203.0.113.99").To4()

	flow, isCH := engine.ProcessPacket(&Packet{
		Timestamp: base,
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   41234,
		DstPort:   443,
		Protocol:  IPProtoTCP,
		Payload:   scannerCH,
	})
	if !isCH {
		t.Fatalf("expected scanner ClientHello detection")
	}
	if flow.ThreatScore < 90 { // direct IP (30) + low ciphers (20) + deprecated TLS 1.0 (25) + scanner sig (40)
		t.Errorf("expected high threat score for barebones TLS 1.0 scanner, got %d (%v)", flow.ThreatScore, flow.ThreatReasons)
	}

	// Emit 10 evenly spaced follow-up packets (2.0s interval) to trigger periodic low-jitter beacon heuristic.
	for i := 1; i <= 10; i++ {
		flow, _ = engine.ProcessPacket(&Packet{
			Timestamp: base.Add(time.Duration(i*2) * time.Second),
			SrcIP:     src,
			DstIP:     dst,
			SrcPort:   41234,
			DstPort:   443,
			Protocol:  IPProtoTCP,
			Payload:   []byte("heartbeat"),
		})
	}
	foundBeacon := false
	for _, r := range flow.ThreatReasons {
		if strings.Contains(r, "beacon") {
			foundBeacon = true
		}
	}
	if !foundBeacon {
		t.Errorf("expected periodic beacon threat reason, got %v (avg=%.2f jitter=%.4f count=%d)",
			flow.ThreatReasons, flow.InterArrivalAvg, flow.Jitter, flow.InterArrivalCount)
	}

	// Flow 2: High-entropy DGA SNI.
	dgaCH := buildSyntheticClientHello("xk9q2m8v7z4p1w6r3t5y.evil.example", "h2", true, []uint16{0x1301, 0x1302, 0x1303}, []uint16{0x000a})
	dgaFlow, _ := engine.ProcessPacket(&Packet{
		Timestamp: base.Add(1 * time.Second),
		SrcIP:     src,
		DstIP:     net.ParseIP("198.51.100.55").To4(),
		SrcPort:   41235,
		DstPort:   443,
		Protocol:  IPProtoTCP,
		Payload:   dgaCH,
	})
	if dgaFlow.ThreatScore < 25 {
		t.Errorf("expected DGA SNI threat score >= 25, got %d (%v)", dgaFlow.ThreatScore, dgaFlow.ThreatReasons)
	}

	report := engine.GenerateReport(CaptureFormatPCAPNG, 15*time.Millisecond)
	if report.TotalSessions != 2 || report.ThreatSessions != 2 || report.ClientHelloCount != 2 {
		t.Errorf("unexpected report totals: %+v", report)
	}
	if len(report.Alerts) != 2 || report.Alerts[0].ThreatScore < report.Alerts[1].ThreatScore {
		t.Errorf("expected alerts sorted by descending threat score")
	}
}

func TestForensicsEngineConcurrentRace(t *testing.T) {
	engine := NewForensicsEngine("deep")
	chRaw := buildSyntheticClientHello("race.aether.io", "h2", true, []uint16{0x1301, 0x1302, 0x1303}, []uint16{0x000a})
	shRaw := buildSyntheticServerHello(0x0303, 0x0304, 0x1301, "", []uint16{ExtSupportedVersions, ExtKeyShare}, false)

	var wg sync.WaitGroup
	base := time.Now().UTC()

	// 12 concurrent writer goroutines feeding interleaved bidirectional streams.
	for w := 0; w < 12; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			cIP := net.IPv4(10, 0, byte(workerID), 1)
			sIP := net.IPv4(198, 51, 100, byte(workerID+1))
			for i := 0; i < 25; i++ {
				port := uint16(30000 + workerID*100 + i)
				ts := base.Add(time.Duration(i) * time.Millisecond)
				engine.ProcessPacketEvent(&Packet{
					Timestamp: ts,
					SrcIP:     cIP,
					DstIP:     sIP,
					SrcPort:   port,
					DstPort:   443,
					Protocol:  IPProtoTCP,
					SeqNum:    100,
					Payload:   chRaw,
				})
				engine.ProcessPacketEvent(&Packet{
					Timestamp: ts.Add(5 * time.Millisecond),
					SrcIP:     sIP,
					DstIP:     cIP,
					SrcPort:   443,
					DstPort:   port,
					Protocol:  IPProtoTCP,
					SeqNum:    200,
					Payload:   shRaw,
				})
			}
		}(w)
	}

	// 4 concurrent reader goroutines inspecting snapshots, sessions, reports, and signatures.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = engine.ActiveFlows()
				_ = engine.Sessions()
				_ = engine.GenerateReport(CaptureFormatPCAP, time.Millisecond)
				_, _ = engine.Signatures().MatchJA4S("t130200_1301_a56c5b993250")
			}
		}()
	}

	wg.Wait()

	report := engine.GenerateReport(CaptureFormatPCAP, time.Millisecond)
	if report.ClientHelloCount != 300 || report.ServerHelloCount != 300 {
		t.Errorf("expected 300 CH and 300 SH under concurrency, got CH=%d SH=%d",
			report.ClientHelloCount, report.ServerHelloCount)
	}
	if report.TotalSessions != 300 {
		t.Errorf("expected 300 correlated sessions, got %d", report.TotalSessions)
	}
}

func BenchmarkParseClientHello(b *testing.B) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f}
	exts := []uint16{0x000b, 0x000a, 0x0023, 0x0017}
	raw := buildSyntheticClientHello("bench.security.aether", "h2", true, ciphers, exts)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := ParseClientHello(raw)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJA4Fingerprint(b *testing.B) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f}
	exts := []uint16{0x000b, 0x000a, 0x0023, 0x0017}
	raw := buildSyntheticClientHello("bench.security.aether", "h2", true, ciphers, exts)
	ch, _ := ParseClientHello(raw)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ch.ComputeJA4()
	}
}

func BenchmarkParseServerHelloJA4S(b *testing.B) {
	raw := buildSyntheticServerHello(0x0303, 0x0304, 0x1301, "", []uint16{ExtSupportedVersions, ExtKeyShare}, false)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sh, err := ParseServerHello(raw)
		if err != nil {
			b.Fatal(err)
		}
		_ = sh.ComputeJA4S()
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	data := []byte("telemetry.aether-research-lab.internal.example.org")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ComputeShannonEntropy(data)
	}
}
