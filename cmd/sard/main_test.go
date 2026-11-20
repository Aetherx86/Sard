package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Aetherx86/Sard/pkg/ja4"
)

func buildTestTLSClientHello(sni, alpn string, tls13 bool, ciphers []uint16) []byte {
	var body bytes.Buffer
	binary.Write(&body, binary.BigEndian, uint16(0x0303))
	body.Write(make([]byte, 32))
	body.WriteByte(0x00)
	binary.Write(&body, binary.BigEndian, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		binary.Write(&body, binary.BigEndian, c)
	}
	body.Write([]byte{0x01, 0x00})

	var exts bytes.Buffer
	if sni != "" {
		binary.Write(&exts, binary.BigEndian, uint16(ja4.ExtServerName))
		listLen := uint16(len(sni) + 3)
		binary.Write(&exts, binary.BigEndian, listLen+2)
		binary.Write(&exts, binary.BigEndian, listLen)
		exts.WriteByte(0x00)
		binary.Write(&exts, binary.BigEndian, uint16(len(sni)))
		exts.WriteString(sni)
	}
	if alpn != "" {
		binary.Write(&exts, binary.BigEndian, uint16(ja4.ExtALPN))
		listLen := uint16(len(alpn) + 1)
		binary.Write(&exts, binary.BigEndian, listLen+2)
		binary.Write(&exts, binary.BigEndian, listLen)
		exts.WriteByte(byte(len(alpn)))
		exts.WriteString(alpn)
	}
	if tls13 {
		binary.Write(&exts, binary.BigEndian, uint16(ja4.ExtSupportedVersions))
		binary.Write(&exts, binary.BigEndian, uint16(3))
		exts.WriteByte(0x02)
		binary.Write(&exts, binary.BigEndian, uint16(0x0304))
	}
	binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	body.Write(exts.Bytes())

	return wrapHandshake(ja4.HandshakeTypeClientHello, 0x0301, body.Bytes())
}

func buildTestTLSServerHello(cipher uint16) []byte {
	var body bytes.Buffer
	binary.Write(&body, binary.BigEndian, uint16(0x0303))
	body.Write(make([]byte, 32))
	body.WriteByte(0x00)
	binary.Write(&body, binary.BigEndian, cipher)
	body.WriteByte(0x00)

	var exts bytes.Buffer
	// supported_versions (0x002b) -> TLS 1.3
	binary.Write(&exts, binary.BigEndian, uint16(ja4.ExtSupportedVersions))
	binary.Write(&exts, binary.BigEndian, uint16(2))
	binary.Write(&exts, binary.BigEndian, uint16(0x0304))
	// key_share (0x0033)
	binary.Write(&exts, binary.BigEndian, uint16(ja4.ExtKeyShare))
	binary.Write(&exts, binary.BigEndian, uint16(4))
	binary.Write(&exts, binary.BigEndian, uint16(0x001d))
	binary.Write(&exts, binary.BigEndian, uint16(0))

	binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	body.Write(exts.Bytes())
	return wrapHandshake(ja4.HandshakeTypeServerHello, 0x0303, body.Bytes())
}

func buildTestTLSCertificate(t *testing.T, cn string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	var list bytes.Buffer
	n := len(der)
	list.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)})
	list.Write(der)

	var body bytes.Buffer
	tot := list.Len()
	body.Write([]byte{byte(tot >> 16), byte(tot >> 8), byte(tot)})
	body.Write(list.Bytes())
	return wrapHandshake(ja4.HandshakeTypeCertificate, 0x0303, body.Bytes())
}

func wrapHandshake(hsType uint8, recVer uint16, body []byte) []byte {
	var hs bytes.Buffer
	hs.WriteByte(hsType)
	n := len(body)
	hs.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)})
	hs.Write(body)

	var rec bytes.Buffer
	rec.WriteByte(ja4.RecordTypeHandshake)
	binary.Write(&rec, binary.BigEndian, recVer)
	binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func makeEthFrame(srcIP, dstIP string, srcPort, dstPort uint16, seq uint32, payload []byte) []byte {
	var f bytes.Buffer
	f.Write(make([]byte, 12))
	binary.Write(&f, binary.BigEndian, uint16(ja4.EtherTypeIPv4))
	ipLen := uint16(20 + 20 + len(payload))
	f.WriteByte(0x45)
	f.WriteByte(0x00)
	binary.Write(&f, binary.BigEndian, ipLen)
	binary.Write(&f, binary.BigEndian, uint16(1))
	binary.Write(&f, binary.BigEndian, uint16(0))
	f.WriteByte(64)
	f.WriteByte(ja4.IPProtoTCP)
	binary.Write(&f, binary.BigEndian, uint16(0))
	f.Write(net.ParseIP(srcIP).To4())
	f.Write(net.ParseIP(dstIP).To4())

	binary.Write(&f, binary.BigEndian, srcPort)
	binary.Write(&f, binary.BigEndian, dstPort)
	binary.Write(&f, binary.BigEndian, seq)
	binary.Write(&f, binary.BigEndian, uint32(0))
	f.WriteByte(0x50)
	f.WriteByte(ja4.TCPFlagPSH | ja4.TCPFlagACK)
	binary.Write(&f, binary.BigEndian, uint16(65535))
	binary.Write(&f, binary.BigEndian, uint16(0))
	binary.Write(&f, binary.BigEndian, uint16(0))
	f.Write(payload)
	return f.Bytes()
}

func buildTestPCAPNGCapture(t *testing.T) []byte {
	t.Helper()
	order := binary.LittleEndian
	var out bytes.Buffer

	writeBlock := func(blockType uint32, body []byte) {
		pad := (4 - (len(body) % 4)) % 4
		total := uint32(12 + len(body) + pad)
		binary.Write(&out, order, blockType)
		binary.Write(&out, order, total)
		out.Write(body)
		for i := 0; i < pad; i++ {
			out.WriteByte(0)
		}
		binary.Write(&out, order, total)
	}

	// SHB
	var shb bytes.Buffer
	binary.Write(&shb, order, ja4.PCAPNGByteOrderMagic)
	binary.Write(&shb, order, uint16(1))
	binary.Write(&shb, order, uint16(0))
	binary.Write(&shb, order, int64(-1))
	writeBlock(ja4.PCAPNGBlockSHB, shb.Bytes())

	// IDB (Ethernet, default 10^-6 s)
	var idb bytes.Buffer
	binary.Write(&idb, order, uint16(ja4.LinkTypeEthernet))
	binary.Write(&idb, order, uint16(0))
	binary.Write(&idb, order, uint32(65535))
	writeBlock(ja4.PCAPNGBlockIDB, idb.Bytes())

	writeEPB := func(tsMicro uint64, frame []byte) {
		var epb bytes.Buffer
		binary.Write(&epb, order, uint32(0))
		binary.Write(&epb, order, uint32(tsMicro>>32))
		binary.Write(&epb, order, uint32(tsMicro&0xffffffff))
		binary.Write(&epb, order, uint32(len(frame)))
		binary.Write(&epb, order, uint32(len(frame)))
		epb.Write(frame)
		writeBlock(ja4.PCAPNGBlockEPB, epb.Bytes())
	}

	// Session 1: ClientHello -> ServerHello + Certificate on public server IP
	ch := buildTestTLSClientHello("app.aether.io", "h2", true, []uint16{0x1301, 0x1302, 0x1303})
	sh := buildTestTLSServerHello(0x1301)
	cert := buildTestTLSCertificate(t, "app.aether.io")
	serverCombined := append(append([]byte(nil), sh...), cert...)

	writeEPB(1700000000_000000, makeEthFrame("10.0.0.5", "198.51.100.10", 51000, 443, 100, ch))
	writeEPB(1700000000_020000, makeEthFrame("198.51.100.10", "10.0.0.5", 443, 51000, 200, serverCombined))

	// Session 2: Direct-IP ClientHello with no SNI
	ch2 := buildTestTLSClientHello("", "", false, []uint16{0xc02f})
	writeEPB(1700000001_000000, makeEthFrame("10.0.0.9", "203.0.113.44", 52000, 443, 300, ch2))

	return out.Bytes()
}

func TestCLIVersionAndErrors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("expected exit 0 for --version, got %d", code)
	}
	if !strings.Contains(stdout.String(), version) {
		t.Errorf("expected version %s in stdout, got %q", version, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"--mode=invalid", "-r", "-"}, bytes.NewReader(nil), &stdout, &stderr); code == 0 {
		t.Errorf("expected non-zero exit for invalid mode")
	}
}

func TestCLINDJSONAndReportJSONWithPCAPNG(t *testing.T) {
	capture := buildTestPCAPNGCapture(t)
	tmpDir := t.TempDir()
	capFile := filepath.Join(tmpDir, "session.pcapng")
	if err := os.WriteFile(capFile, capture, 0o600); err != nil {
		t.Fatal(err)
	}

	// Custom signature JSON matching Session 1's ClientHello prefix.
	sigFile := filepath.Join(tmpDir, "sigs.json")
	sigContent := `[{"id":"test-app","type":"ja4","pattern":"t13d0303h2_*","name":"Aether CLI Test Client","category":"tool"}]`
	if err := os.WriteFile(sigFile, []byte(sigContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. NDJSON streaming via stdin ('-') with custom signatures.
	var stdout, stderr bytes.Buffer
	code := run([]string{"--mode=deep", "--json", "--sigs", sigFile, "-r", "-"}, bytes.NewReader(capture), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("NDJSON run failed (code=%d): %s", code, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 4 { // CH1, SH1, CERT1, CH2
		t.Fatalf("expected 4 NDJSON events (CH1, SH1, CERT1, CH2), got %d:\n%s", len(lines), stdout.String())
	}

	var events []JSONEvent
	for _, line := range lines {
		var ev JSONEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("invalid NDJSON line %q: %v", line, err)
		}
		events = append(events, ev)
	}
	if events[0].EventType != "client_hello" || events[0].AppName != "Aether CLI Test Client" {
		t.Errorf("unexpected first event: %+v", events[0])
	}
	if events[1].EventType != "server_hello" || events[1].JA4S != "t130200_1301_a56c5b993250" {
		t.Errorf("unexpected ServerHello event: %+v", events[1])
	}
	if events[2].EventType != "certificate" || events[2].JA4X != "7022c563de38_7022c563de38_000000000000" {
		t.Errorf("unexpected Certificate event: %+v", events[2])
	}

	// 2. Comprehensive --report-json from file.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--mode=deep", "--report-json", "--sigs", sigFile, "-r", capFile}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("report-json run failed (code=%d): %s", code, stderr.String())
	}

	var report ja4.ForensicReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed unmarshaling forensic report JSON: %v\n%s", err, stdout.String())
	}
	if report.CaptureFormat != "pcapng" || report.TotalSessions != 2 || report.ClientHelloCount != 2 || report.ServerHelloCount != 1 || report.CertificateCount != 1 {
		t.Errorf("unexpected report counts: %+v", report)
	}
	if report.ThreatSessions != 2 {
		t.Errorf("expected 2 sessions with threats (self-signed minimal cert + direct-IP no-SNI), got %d", report.ThreatSessions)
	}

	// 3. Filter test: -filter-ja4s + --json.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--json", "-filter-ja4s=t130200_1301", "-r", capFile}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("filter-ja4s run failed: %s", stderr.String())
	}
	filteredLines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(filteredLines) != 2 { // SH1 and CERT1 (both carry correlated JA4S on session)
		t.Errorf("expected 2 events matching -filter-ja4s, got %d:\n%s", len(filteredLines), stdout.String())
	}

	// 4. Tabular human output with --alert.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--mode=deep", "--alert", "-r", capFile}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("tabular alert run failed: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "PCAPNG format") || !strings.Contains(stdout.String(), "ALERT(") {
		t.Errorf("unexpected tabular output:\n%s", stdout.String())
	}
}
