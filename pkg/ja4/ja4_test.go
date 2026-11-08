package ja4

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// Helper to construct a synthetic TLS ClientHello
func buildSyntheticClientHello(sni string, alpn string, tls13 bool, ciphers []uint16, exts []uint16) []byte {
	var chBody bytes.Buffer

	// Version: 0x0303 (TLS 1.2 in record/handshake, TLS 1.3 in supported_versions)
	chBody.Write([]byte{0x03, 0x03})
	// Random: 32 bytes
	chBody.Write(make([]byte, 32))
	// Session ID len: 0
	chBody.WriteByte(0x00)

	// Cipher Suites
	binary.Write(&chBody, binary.BigEndian, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		binary.Write(&chBody, binary.BigEndian, c)
	}

	// Compression Methods: 1 byte len, 0x00 null
	chBody.Write([]byte{0x01, 0x00})

	// Extensions
	var extsBuf bytes.Buffer

	// 1. SNI extension
	if sni != "" {
		binary.Write(&extsBuf, binary.BigEndian, uint16(ExtServerName))
		sniData := []byte(sni)
		serverNameListLen := uint16(len(sniData) + 3)
		extLen := serverNameListLen + 2

		binary.Write(&extsBuf, binary.BigEndian, extLen)
		binary.Write(&extsBuf, binary.BigEndian, serverNameListLen)
		extsBuf.WriteByte(0x00) // host_name
		binary.Write(&extsBuf, binary.BigEndian, uint16(len(sniData)))
		extsBuf.Write(sniData)
	}

	// 2. ALPN extension
	if alpn != "" {
		binary.Write(&extsBuf, binary.BigEndian, uint16(ExtALPN))
		alpnData := []byte(alpn)
		listLen := uint16(len(alpnData) + 1)
		binary.Write(&extsBuf, binary.BigEndian, uint16(listLen+2))
		binary.Write(&extsBuf, binary.BigEndian, listLen)
		extsBuf.WriteByte(byte(len(alpnData)))
		extsBuf.Write(alpnData)
	}

	// 3. Supported Versions (TLS 1.3)
	if tls13 {
		binary.Write(&extsBuf, binary.BigEndian, uint16(ExtSupportedVersions))
		binary.Write(&extsBuf, binary.BigEndian, uint16(3)) // 1 len + 2 version
		extsBuf.WriteByte(0x02)                             // list len
		binary.Write(&extsBuf, binary.BigEndian, uint16(0x0304))
	}

	// Other extensions
	for _, ext := range exts {
		binary.Write(&extsBuf, binary.BigEndian, ext)
		binary.Write(&extsBuf, binary.BigEndian, uint16(0)) // 0 length dummy
	}

	binary.Write(&chBody, binary.BigEndian, uint16(extsBuf.Len()))
	chBody.Write(extsBuf.Bytes())

	// Handshake Frame
	var hsBuf bytes.Buffer
	hsBuf.WriteByte(HandshakeTypeClientHello)
	hsLen := chBody.Len()
	hsBuf.WriteByte(byte(hsLen >> 16))
	hsBuf.WriteByte(byte(hsLen >> 8))
	hsBuf.WriteByte(byte(hsLen))
	hsBuf.Write(chBody.Bytes())

	// TLS Record Frame
	var recBuf bytes.Buffer
	recBuf.WriteByte(RecordTypeHandshake)
	binary.Write(&recBuf, binary.BigEndian, uint16(0x0301))
	binary.Write(&recBuf, binary.BigEndian, uint16(hsBuf.Len()))
	recBuf.Write(hsBuf.Bytes())

	return recBuf.Bytes()
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

	nonGrease := []uint16{0x0000, 0x002f, 0x1301, 0x1302, 0xc02b, 0x000a}
	for _, ng := range nonGrease {
		if IsGREASE(ng) {
			t.Errorf("expected 0x%04x NOT to be GREASE", ng)
		}
	}
}

func TestParseClientHelloAndJA4(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0x0a0a} // 0x0a0a is GREASE
	exts := []uint16{0x000b, 0x000a, 0x1a1a}             // 0x1a1a is GREASE

	raw := buildSyntheticClientHello("api.example.com", "h2", true, ciphers, exts)

	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if ch.SNI != "api.example.com" {
		t.Errorf("expected SNI 'api.example.com', got '%s'", ch.SNI)
	}
	if !ch.IsDomainSNI {
		t.Errorf("expected domain SNI")
	}
	if ch.ALPN != "h2" {
		t.Errorf("expected ALPN 'h2', got '%s'", ch.ALPN)
	}
	if ch.EffectiveVersion != 0x0304 {
		t.Errorf("expected TLS 1.3 (0x0304), got 0x%04x", ch.EffectiveVersion)
	}
	if len(ch.FilteredCiphers) != 3 {
		t.Errorf("expected 3 non-GREASE ciphers, got %d", len(ch.FilteredCiphers))
	}

	ja4 := ch.ComputeJA4()
	if len(ja4) != 36 { // 10 + 1 + 12 + 1 + 12
		t.Errorf("invalid JA4 length: %s (len %d)", ja4, len(ja4))
	}

	// Part A verification: t13d0303h2 (3 ciphers, 3 extensions excluding SNI/ALPN: 0x002b, 0x000b, 0x000a)
	if ja4[:10] != "t13d0303h2" {
		t.Errorf("unexpected JA4 part A: got %s, want t13d0303h2", ja4[:10])
	}
}

func TestShannonEntropy(t *testing.T) {
	// Uniform repeated byte: entropy = 0.0
	zeros := make([]byte, 100)
	if ent := ComputeShannonEntropy(zeros); ent != 0.0 {
		t.Errorf("expected 0 entropy for uniform data, got %f", ent)
	}

	// All 256 byte values equally distributed: entropy = 8.0
	fullByteRange := make([]byte, 256)
	for i := 0; i < 256; i++ {
		fullByteRange[i] = byte(i)
	}
	if ent := ComputeShannonEntropy(fullByteRange); ent < 7.99 || ent > 8.01 {
		t.Errorf("expected 8.0 entropy for complete byte spectrum, got %f", ent)
	}
}

func TestPCAPReader(t *testing.T) {
	var pcapBuf bytes.Buffer

	// Write Global Header (24 bytes)
	binary.Write(&pcapBuf, binary.BigEndian, PCAPMagicSameEndian)
	binary.Write(&pcapBuf, binary.BigEndian, uint16(2)) // ver major
	binary.Write(&pcapBuf, binary.BigEndian, uint16(4)) // ver minor
	binary.Write(&pcapBuf, binary.BigEndian, int32(0))  // thiszone
	binary.Write(&pcapBuf, binary.BigEndian, uint32(0)) // sigfigs
	binary.Write(&pcapBuf, binary.BigEndian, uint32(65535))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(LinkTypeEthernet))

	// Synthetic Ethernet + IPv4 + TCP + ClientHello packet
	tlsPayload := buildSyntheticClientHello("telemetry.aether.local", "http/1.1", false, []uint16{0xc02b, 0xc02f}, nil)

	var frame bytes.Buffer
	// Ethernet header (14 bytes)
	frame.Write(make([]byte, 12)) // src/dst MAC
	binary.Write(&frame, binary.BigEndian, uint16(EtherTypeIPv4))

	// IPv4 header (20 bytes)
	ipLen := uint16(20 + 20 + len(tlsPayload))
	frame.WriteByte(0x45) // ver 4, ihl 5 (20 bytes)
	frame.WriteByte(0x00) // tos
	binary.Write(&frame, binary.BigEndian, ipLen)
	binary.Write(&frame, binary.BigEndian, uint16(0x1234)) // id
	binary.Write(&frame, binary.BigEndian, uint16(0))      // flags
	frame.WriteByte(64)                                    // ttl
	frame.WriteByte(IPProtoTCP)                            // proto
	binary.Write(&frame, binary.BigEndian, uint16(0))      // csum
	frame.Write(net.ParseIP("192.168.1.50").To4())
	frame.Write(net.ParseIP("10.0.0.1").To4())

	// TCP Header (20 bytes)
	binary.Write(&frame, binary.BigEndian, uint16(54321)) // src port
	binary.Write(&frame, binary.BigEndian, uint16(443))   // dst port
	binary.Write(&frame, binary.BigEndian, uint32(100))   // seq
	binary.Write(&frame, binary.BigEndian, uint32(0))     // ack
	frame.WriteByte(0x50)                                 // data offset 5 (20 bytes)
	frame.WriteByte(0x18)                                 // PSH, ACK
	binary.Write(&frame, binary.BigEndian, uint16(65535)) // window
	binary.Write(&frame, binary.BigEndian, uint16(0))     // csum
	binary.Write(&frame, binary.BigEndian, uint16(0))     // urgent

	frame.Write(tlsPayload)

	// Packet Header (16 bytes)
	binary.Write(&pcapBuf, binary.BigEndian, uint32(1700000000))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(500000))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(frame.Len()))
	binary.Write(&pcapBuf, binary.BigEndian, uint32(frame.Len()))
	pcapBuf.Write(frame.Bytes())

	reader, err := NewPCAPReader(&pcapBuf)
	if err != nil {
		t.Fatalf("failed to create PCAP reader: %v", err)
	}

	pkt, err := reader.NextPacket()
	if err != nil {
		t.Fatalf("NextPacket failed: %v", err)
	}

	if pkt.SrcPort != 54321 || pkt.DstPort != 443 {
		t.Errorf("unexpected ports: src=%d, dst=%d", pkt.SrcPort, pkt.DstPort)
	}

	engine := NewForensicsEngine("deep")
	flow, isCH := engine.ProcessPacket(pkt)
	if !isCH {
		t.Fatalf("expected packet to be recognized as ClientHello")
	}

	if flow.SNI != "telemetry.aether.local" {
		t.Errorf("unexpected flow SNI: %s", flow.SNI)
	}
	if flow.ALPN != "http/1.1" {
		t.Errorf("unexpected flow ALPN: %s", flow.ALPN)
	}
	if flow.JA4 == "" {
		t.Errorf("expected populated JA4 string")
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
