package ja4

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// FlowKey represents a 5-tuple identifying a directional network flow.
type FlowKey struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
	Proto   uint8  `json:"proto"`
}

func MakeFlowKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) FlowKey {
	return FlowKey{
		SrcIP:   srcIP.String(),
		DstIP:   dstIP.String(),
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   proto,
	}
}

// SessionKey uniquely identifies a bidirectional TCP/UDP conversation regardless of direction.
type SessionKey struct {
	EndpointA string
	PortA     uint16
	EndpointB string
	PortB     uint16
	Proto     uint8
}

// MakeSessionKey returns the canonical unordered conversation key for two endpoints.
func MakeSessionKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) SessionKey {
	sIP := srcIP.String()
	dIP := dstIP.String()
	if sIP < dIP || (sIP == dIP && srcPort <= dstPort) {
		return SessionKey{
			EndpointA: sIP,
			PortA:     srcPort,
			EndpointB: dIP,
			PortB:     dstPort,
			Proto:     proto,
		}
	}
	return SessionKey{
		EndpointA: dIP,
		PortA:     dstPort,
		EndpointB: sIP,
		PortB:     srcPort,
		Proto:     proto,
	}
}

// FlowRecord maintains stateful directional session telemetry for network forensics.
type FlowRecord struct {
	Key               FlowKey           `json:"key"`
	FirstSeen         time.Time         `json:"first_seen"`
	LastSeen          time.Time         `json:"last_seen"`
	PacketCount       uint64            `json:"packet_count"`
	ByteCount         uint64            `json:"byte_count"`
	JA4               string            `json:"ja4,omitempty"`
	JA4Raw            string            `json:"ja4_raw,omitempty"`
	JA4Original       string            `json:"ja4_original,omitempty"`
	JA4S              string            `json:"ja4s,omitempty"`
	JA4SRaw           string            `json:"ja4s_raw,omitempty"`
	JA4X              string            `json:"ja4x,omitempty"`
	JA4XRaw           string            `json:"ja4x_raw,omitempty"`
	SNI               string            `json:"sni,omitempty"`
	ALPN              string            `json:"alpn,omitempty"`
	TLSVersion        string            `json:"tls_version,omitempty"`
	SelectedCipher    string            `json:"selected_cipher,omitempty"`
	CertSubjectCN     string            `json:"cert_subject_cn,omitempty"`
	CertIssuerCN      string            `json:"cert_issuer_cn,omitempty"`
	CertSelfSigned    bool              `json:"cert_self_signed,omitempty"`
	CertExpired       bool              `json:"cert_expired,omitempty"`
	ThreatScore       int               `json:"threat_score,omitempty"`
	ThreatReasons     []string          `json:"threat_reasons,omitempty"`
	MatchedSignatures []SignatureMatch  `json:"matched_signatures,omitempty"`
	AppName           string            `json:"app_name,omitempty"`
	Category          SignatureCategory `json:"category,omitempty"`
	ShannonEntropy    float64           `json:"entropy,omitempty"`
	PayloadSampled    int               `json:"payload_sampled,omitempty"`
	InterArrivalAvg   float64           `json:"inter_arrival_avg,omitempty"`
	InterArrivalCount uint64            `json:"inter_arrival_count,omitempty"`
	Jitter            float64           `json:"jitter,omitempty"`
	HandshakeRTTMs    float64           `json:"handshake_rtt_ms,omitempty"`
	LastPacketTime    time.Time         `json:"last_packet_time,omitempty"`

	reasonKeys map[string]struct{}
}

func (f *FlowRecord) clone() *FlowRecord {
	if f == nil {
		return nil
	}
	cp := *f
	cp.reasonKeys = nil
	if len(f.ThreatReasons) > 0 {
		cp.ThreatReasons = append([]string(nil), f.ThreatReasons...)
	}
	if len(f.MatchedSignatures) > 0 {
		cp.MatchedSignatures = append([]SignatureMatch(nil), f.MatchedSignatures...)
	}
	return &cp
}

func (f *FlowRecord) addThreat(ruleKey string, score int, reason string) {
	if f.reasonKeys == nil {
		f.reasonKeys = make(map[string]struct{})
	}
	if _, exists := f.reasonKeys[ruleKey]; exists {
		return
	}
	f.reasonKeys[ruleKey] = struct{}{}
	f.ThreatScore += score
	f.ThreatReasons = append(f.ThreatReasons, reason)
}

func (f *FlowRecord) addSignatureMatch(m SignatureMatch) {
	for _, existing := range f.MatchedSignatures {
		if existing.Signature.ID == m.Signature.ID && existing.MatchedValue == m.MatchedValue {
			return
		}
	}
	f.MatchedSignatures = append(f.MatchedSignatures, m)
	if f.Category == "" || categorySeverity(m.Signature.Category) >= categorySeverity(f.Category) {
		f.Category = m.Signature.Category
		if m.Signature.Name != "" {
			f.AppName = m.Signature.Name
		}
	}
}

// SessionRecord correlates both directions of a TLS conversation (ClientHello + ServerHello + Certificate).
type SessionRecord struct {
	Client            string            `json:"client"`
	Server            string            `json:"server"`
	Protocol          string            `json:"protocol"`
	FirstSeen         time.Time         `json:"first_seen"`
	LastSeen          time.Time         `json:"last_seen"`
	ClientPackets     uint64            `json:"client_packets"`
	ServerPackets     uint64            `json:"server_packets"`
	TotalBytes        uint64            `json:"total_bytes"`
	SNI               string            `json:"sni,omitempty"`
	ALPN              string            `json:"alpn,omitempty"`
	TLSVersion        string            `json:"tls_version,omitempty"`
	SelectedCipher    string            `json:"selected_cipher,omitempty"`
	JA4               string            `json:"ja4,omitempty"`
	JA4Raw            string            `json:"ja4_raw,omitempty"`
	JA4S              string            `json:"ja4s,omitempty"`
	JA4X              string            `json:"ja4x,omitempty"`
	CertSubjectCN     string            `json:"cert_subject_cn,omitempty"`
	CertIssuerCN      string            `json:"cert_issuer_cn,omitempty"`
	CertSelfSigned    bool              `json:"cert_self_signed,omitempty"`
	CertExpired       bool              `json:"cert_expired,omitempty"`
	CertChainLength   int               `json:"cert_chain_length,omitempty"`
	HelloRetryRequest bool              `json:"hello_retry_request,omitempty"`
	HandshakeRTTMs    float64           `json:"handshake_rtt_ms,omitempty"`
	AppName           string            `json:"app_name,omitempty"`
	Category          SignatureCategory `json:"category,omitempty"`
	MatchedSignatures []SignatureMatch  `json:"matched_signatures,omitempty"`
	ThreatScore       int               `json:"threat_score,omitempty"`
	ThreatReasons     []string          `json:"threat_reasons,omitempty"`

	clientHelloTime time.Time
	clientKey       FlowKey
	reasonKeys      map[string]struct{}
}

func (s *SessionRecord) clone() *SessionRecord {
	if s == nil {
		return nil
	}
	cp := *s
	cp.reasonKeys = nil
	if len(s.ThreatReasons) > 0 {
		cp.ThreatReasons = append([]string(nil), s.ThreatReasons...)
	}
	if len(s.MatchedSignatures) > 0 {
		cp.MatchedSignatures = append([]SignatureMatch(nil), s.MatchedSignatures...)
	}
	return &cp
}

func (s *SessionRecord) addThreat(ruleKey string, score int, reason string) {
	if s.reasonKeys == nil {
		s.reasonKeys = make(map[string]struct{})
	}
	if _, exists := s.reasonKeys[ruleKey]; exists {
		return
	}
	s.reasonKeys[ruleKey] = struct{}{}
	s.ThreatScore += score
	s.ThreatReasons = append(s.ThreatReasons, reason)
}

func (s *SessionRecord) addSignatureMatch(m SignatureMatch) {
	for _, existing := range s.MatchedSignatures {
		if existing.Signature.ID == m.Signature.ID && existing.MatchedValue == m.MatchedValue {
			return
		}
	}
	s.MatchedSignatures = append(s.MatchedSignatures, m)
	if s.Category == "" || categorySeverity(m.Signature.Category) >= categorySeverity(s.Category) {
		s.Category = m.Signature.Category
		if m.Signature.Name != "" {
			s.AppName = m.Signature.Name
		}
	}
}

// ForensicEventType identifies the TLS handshake artifact that triggered an event.
type ForensicEventType string

const (
	EventClientHello ForensicEventType = "client_hello"
	EventServerHello ForensicEventType = "server_hello"
	EventCertificate ForensicEventType = "certificate"
)

// ForensicEvent represents a single parsed TLS handshake observation.
type ForensicEvent struct {
	Type              ForensicEventType `json:"event_type"`
	Timestamp         time.Time         `json:"timestamp"`
	Src               string            `json:"src"`
	Dst               string            `json:"dst"`
	Protocol          string            `json:"protocol"`
	SNI               string            `json:"sni,omitempty"`
	ALPN              string            `json:"alpn,omitempty"`
	TLSVersion        string            `json:"tls_version,omitempty"`
	SelectedCipher    string            `json:"selected_cipher,omitempty"`
	JA4               string            `json:"ja4,omitempty"`
	JA4Raw            string            `json:"ja4_raw,omitempty"`
	JA4S              string            `json:"ja4s,omitempty"`
	JA4X              string            `json:"ja4x,omitempty"`
	CertSubjectCN     string            `json:"cert_subject_cn,omitempty"`
	CertSelfSigned    bool              `json:"cert_self_signed,omitempty"`
	HandshakeRTTMs    float64           `json:"handshake_rtt_ms,omitempty"`
	AppName           string            `json:"app_name,omitempty"`
	Category          SignatureCategory `json:"category,omitempty"`
	MatchedSignatures []SignatureMatch  `json:"matched_signatures,omitempty"`
	ThreatScore       int               `json:"threat_score,omitempty"`
	ThreatReasons     []string          `json:"threat_reasons,omitempty"`
	ShannonEntropy    float64           `json:"entropy,omitempty"`
	Jitter            float64           `json:"jitter,omitempty"`
}

// FingerprintCount tracks occurrence counts of an observed fingerprint.
type FingerprintCount struct {
	Fingerprint string `json:"fingerprint"`
	Count       int    `json:"count"`
	AppName     string `json:"app_name,omitempty"`
	Category    string `json:"category,omitempty"`
}

// ForensicReport summarizes an entire capture analysis run in structured JSON form.
type ForensicReport struct {
	CaptureFormat    string             `json:"capture_format"`
	Mode             string             `json:"mode"`
	DurationMs       float64            `json:"duration_ms"`
	TotalPackets     uint64             `json:"total_packets"`
	TotalBytes       uint64             `json:"total_bytes"`
	ActiveFlows      int                `json:"active_flows"`
	TotalSessions    int                `json:"total_sessions"`
	ClientHelloCount uint64             `json:"client_hello_count"`
	ServerHelloCount uint64             `json:"server_hello_count"`
	CertificateCount uint64             `json:"certificate_count"`
	ThreatSessions   int                `json:"threat_sessions"`
	TopJA4           []FingerprintCount `json:"top_ja4,omitempty"`
	TopJA4S          []FingerprintCount `json:"top_ja4s,omitempty"`
	TopJA4X          []FingerprintCount `json:"top_ja4x,omitempty"`
	SignatureHits    map[string]int     `json:"signature_hits,omitempty"`
	Alerts           []*SessionRecord   `json:"alerts,omitempty"`
	Sessions         []*SessionRecord   `json:"sessions,omitempty"`
}

// ComputeShannonEntropy calculates the Shannon entropy in bits per byte [0.0 - 8.0].
func ComputeShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	total := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// ForensicsEngine manages thread-safe stateful session analysis, TCP stream reassembly,
// JA4/JA4S/JA4X signature matching, and threat scoring.
type ForensicsEngine struct {
	mu               sync.RWMutex
	flows            map[FlowKey]*FlowRecord
	sessions         map[SessionKey]*SessionRecord
	reassembler      *StreamReassembler
	signatures       *SignatureDB
	mode             string // "fast" or "deep"
	totalPackets     uint64
	totalBytes       uint64
	clientHelloCount uint64
	serverHelloCount uint64
	certificateCount uint64
}

// NewForensicsEngine instantiates an analysis engine with the built-in signature database.
func NewForensicsEngine(mode string) *ForensicsEngine {
	return NewForensicsEngineWithSignatures(mode, DefaultSignatureDB())
}

// NewForensicsEngineWithSignatures instantiates an analysis engine with a custom SignatureDB.
func NewForensicsEngineWithSignatures(mode string, db *SignatureDB) *ForensicsEngine {
	if mode == "" {
		mode = "fast"
	}
	if db == nil {
		db = DefaultSignatureDB()
	}
	return &ForensicsEngine{
		flows:       make(map[FlowKey]*FlowRecord),
		sessions:    make(map[SessionKey]*SessionRecord),
		reassembler: NewStreamReassembler(defaultMaxStreams, defaultMaxStreamBytes),
		signatures:  db,
		mode:        mode,
	}
}

// Signatures returns the engine's active SignatureDB.
func (fe *ForensicsEngine) Signatures() *SignatureDB {
	return fe.signatures
}

// ProcessPacket evaluates a network packet and updates directional flow and bidirectional
// session telemetry. It returns a thread-safe snapshot of the flow record and true if
// a TLS ClientHello was extracted from this packet (or completed via reassembly).
func (fe *ForensicsEngine) ProcessPacket(pkt *Packet) (*FlowRecord, bool) {
	flow, events := fe.ProcessPacketEvent(pkt)
	for _, ev := range events {
		if ev.Type == EventClientHello {
			return flow, true
		}
	}
	return flow, false
}

// ProcessPacketEvent evaluates a network packet, performs multi-stream TCP handshake
// reassembly, and returns the updated flow snapshot along with any newly observed
// ClientHello, ServerHello, or Certificate forensic events.
func (fe *ForensicsEngine) ProcessPacketEvent(pkt *Packet) (*FlowRecord, []ForensicEvent) {
	if pkt == nil {
		return nil, nil
	}

	fe.mu.Lock()
	defer fe.mu.Unlock()

	fe.totalPackets++
	fe.totalBytes += uint64(len(pkt.Payload))

	key := MakeFlowKey(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Protocol)
	flow, exists := fe.flows[key]

	if !exists {
		flow = &FlowRecord{
			Key:            key,
			FirstSeen:      pkt.Timestamp,
			LastSeen:       pkt.Timestamp,
			LastPacketTime: pkt.Timestamp,
		}
		fe.flows[key] = flow
	} else {
		if fe.mode == "deep" && !flow.LastPacketTime.IsZero() && !pkt.Timestamp.IsZero() {
			delta := pkt.Timestamp.Sub(flow.LastPacketTime).Seconds()
			if delta > 0 {
				flow.InterArrivalCount++
				if flow.InterArrivalAvg == 0 {
					flow.InterArrivalAvg = delta
				} else {
					diff := math.Abs(delta - flow.InterArrivalAvg)
					if flow.InterArrivalCount == 2 {
						flow.Jitter = diff
					} else {
						flow.Jitter += (diff - flow.Jitter) / 16.0
					}
					flow.InterArrivalAvg = (flow.InterArrivalAvg * 0.8) + (delta * 0.2)
				}
			}
		}
		if !pkt.Timestamp.IsZero() {
			flow.LastSeen = pkt.Timestamp
			flow.LastPacketTime = pkt.Timestamp
		}
	}

	flow.PacketCount++
	flow.ByteCount += uint64(len(pkt.Payload))

	sessKey := MakeSessionKey(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Protocol)
	sess := fe.getOrCreateSession(sessKey, pkt)
	if !pkt.Timestamp.IsZero() {
		if sess.FirstSeen.IsZero() || pkt.Timestamp.Before(sess.FirstSeen) {
			sess.FirstSeen = pkt.Timestamp
		}
		if pkt.Timestamp.After(sess.LastSeen) {
			sess.LastSeen = pkt.Timestamp
		}
	}
	sess.TotalBytes += uint64(len(pkt.Payload))
	srcAddr := fmt.Sprintf("%s:%d", pkt.SrcIP.String(), pkt.SrcPort)
	dstAddr := fmt.Sprintf("%s:%d", pkt.DstIP.String(), pkt.DstPort)
	if srcAddr == sess.Client {
		sess.ClientPackets++
	} else {
		sess.ServerPackets++
	}

	// Reassemble TCP stream and extract any newly completed TLS handshake messages.
	hsMsgs := fe.reassembler.Feed(key, pkt)

	var events []ForensicEvent
	for _, msg := range hsMsgs {
		switch msg.Type {
		case HandshakeTypeClientHello:
			ch, err := ParseClientHelloBody(msg.Body, msg.RecordVersion, 't')
			if err != nil {
				continue
			}
			fe.clientHelloCount++
			ja4FP := ch.ComputeJA4()
			ja4Raw := ch.ComputeJA4Raw()
			ja4Orig := ch.ComputeJA4Original()
			tlsVer := TLSVersionName(ch.EffectiveVersion)

			flow.JA4 = ja4FP
			flow.JA4Raw = ja4Raw
			flow.JA4Original = ja4Orig
			flow.SNI = ch.SNI
			flow.ALPN = ch.ALPN
			flow.TLSVersion = tlsVer

			sess.Client = srcAddr
			sess.Server = dstAddr
			sess.clientKey = key
			sess.clientHelloTime = pkt.Timestamp
			sess.JA4 = ja4FP
			sess.JA4Raw = ja4Raw
			sess.SNI = ch.SNI
			sess.ALPN = ch.ALPN
			if sess.TLSVersion == "" {
				sess.TLSVersion = tlsVer
			}

			fe.evaluateClientHelloThreats(flow, sess, ch, ja4FP)

			events = append(events, ForensicEvent{
				Type:              EventClientHello,
				Timestamp:         pkt.Timestamp,
				Src:               srcAddr,
				Dst:               dstAddr,
				Protocol:          protoName(pkt.Protocol),
				SNI:               flow.SNI,
				ALPN:              flow.ALPN,
				TLSVersion:        flow.TLSVersion,
				JA4:               flow.JA4,
				JA4Raw:            flow.JA4Raw,
				AppName:           flow.AppName,
				Category:          flow.Category,
				MatchedSignatures: append([]SignatureMatch(nil), flow.MatchedSignatures...),
				ThreatScore:       flow.ThreatScore,
				ThreatReasons:     append([]string(nil), flow.ThreatReasons...),
				ShannonEntropy:    flow.ShannonEntropy,
				Jitter:            flow.Jitter,
			})

		case HandshakeTypeServerHello:
			sh, err := ParseServerHelloBody(msg.Body, msg.RecordVersion, 't')
			if err != nil {
				continue
			}
			fe.serverHelloCount++
			ja4sFP := sh.ComputeJA4S()
			ja4sRaw := sh.ComputeJA4SRaw()
			tlsVer := TLSVersionName(sh.EffectiveVersion)
			cipherHex := fmt.Sprintf("0x%04x", sh.CipherSuite)

			flow.JA4S = ja4sFP
			flow.JA4SRaw = ja4sRaw
			flow.TLSVersion = tlsVer
			flow.SelectedCipher = cipherHex
			if sh.ALPN != "" {
				flow.ALPN = sh.ALPN
			}

			// ServerHello flows from server -> client.
			if sess.JA4 == "" {
				sess.Server = srcAddr
				sess.Client = dstAddr
			}
			sess.JA4S = ja4sFP
			sess.TLSVersion = tlsVer
			sess.SelectedCipher = cipherHex
			sess.HelloRetryRequest = sh.IsHelloRetryRequest
			if sh.ALPN != "" {
				sess.ALPN = sh.ALPN
			}
			if !sess.clientHelloTime.IsZero() && !pkt.Timestamp.IsZero() {
				rtt := pkt.Timestamp.Sub(sess.clientHelloTime).Seconds() * 1000.0
				if rtt >= 0 {
					sess.HandshakeRTTMs = rtt
					flow.HandshakeRTTMs = rtt
					if clientFlow, ok := fe.flows[sess.clientKey]; ok {
						clientFlow.HandshakeRTTMs = rtt
					}
				}
			}

			fe.evaluateServerHelloThreats(flow, sess, sh, ja4sFP)

			events = append(events, ForensicEvent{
				Type:              EventServerHello,
				Timestamp:         pkt.Timestamp,
				Src:               srcAddr,
				Dst:               dstAddr,
				Protocol:          protoName(pkt.Protocol),
				SNI:               sess.SNI,
				ALPN:              flow.ALPN,
				TLSVersion:        flow.TLSVersion,
				SelectedCipher:    cipherHex,
				JA4:               sess.JA4,
				JA4S:              flow.JA4S,
				HandshakeRTTMs:    flow.HandshakeRTTMs,
				AppName:           flow.AppName,
				Category:          flow.Category,
				MatchedSignatures: append([]SignatureMatch(nil), flow.MatchedSignatures...),
				ThreatScore:       flow.ThreatScore,
				ThreatReasons:     append([]string(nil), flow.ThreatReasons...),
			})

		case HandshakeTypeCertificate:
			cert, err := ParseCertificateBody(msg.Body)
			if err != nil {
				continue
			}
			fe.certificateCount++
			ja4xFP := cert.ComputeJA4X()
			ja4xRaw := cert.ComputeJA4XRaw()
			expired := cert.IsExpiredAt(pkt.Timestamp)

			flow.JA4X = ja4xFP
			flow.JA4XRaw = ja4xRaw
			flow.CertSubjectCN = cert.SubjectCN
			flow.CertIssuerCN = cert.IssuerCN
			flow.CertSelfSigned = cert.IsSelfSigned
			flow.CertExpired = expired

			sess.JA4X = ja4xFP
			sess.CertSubjectCN = cert.SubjectCN
			sess.CertIssuerCN = cert.IssuerCN
			sess.CertSelfSigned = cert.IsSelfSigned
			sess.CertExpired = expired
			sess.CertChainLength = cert.ChainLength

			fe.evaluateCertificateThreats(flow, sess, cert, ja4xFP, pkt.SrcIP, expired)

			events = append(events, ForensicEvent{
				Type:              EventCertificate,
				Timestamp:         pkt.Timestamp,
				Src:               srcAddr,
				Dst:               dstAddr,
				Protocol:          protoName(pkt.Protocol),
				SNI:               sess.SNI,
				TLSVersion:        sess.TLSVersion,
				JA4:               sess.JA4,
				JA4S:              sess.JA4S,
				JA4X:              flow.JA4X,
				CertSubjectCN:     cert.SubjectCN,
				CertSelfSigned:    cert.IsSelfSigned,
				AppName:           flow.AppName,
				Category:          flow.Category,
				MatchedSignatures: append([]SignatureMatch(nil), flow.MatchedSignatures...),
				ThreatScore:       flow.ThreatScore,
				ThreatReasons:     append([]string(nil), flow.ThreatReasons...),
			})
		}
	}

	if fe.mode == "deep" {
		if len(pkt.Payload) > 0 && flow.PayloadSampled < 4096 {
			flow.ShannonEntropy = ComputeShannonEntropy(pkt.Payload)
			flow.PayloadSampled += len(pkt.Payload)
			if flow.ShannonEntropy > 7.7 && flow.JA4 == "" && flow.JA4S == "" && sess.JA4 == "" {
				reason := fmt.Sprintf("High payload entropy without TLS handshake (%.2f bits/byte)", flow.ShannonEntropy)
				flow.addThreat("high_payload_entropy", 20, reason)
				sess.addThreat("high_payload_entropy", 20, reason)
			}
		}

		// Periodic C2 beacon detection: consistent interval >= 1.0s with < 5% jitter.
		if flow.InterArrivalCount >= 8 && flow.InterArrivalAvg >= 1.0 {
			cv := flow.Jitter / flow.InterArrivalAvg
			if cv < 0.05 {
				reason := fmt.Sprintf("Periodic low-jitter traffic beacon candidate (interval=%.2fs, jitter=%.4fs)", flow.InterArrivalAvg, flow.Jitter)
				flow.addThreat("periodic_beacon", 20, reason)
				sess.addThreat("periodic_beacon", 20, reason)
			}
		}
	}

	// Reflect latest flow entropy/jitter into emitted ClientHello events if deep mode sampled it.
	if len(events) > 0 {
		for i := range events {
			if events[i].Type == EventClientHello {
				events[i].ShannonEntropy = flow.ShannonEntropy
				events[i].Jitter = flow.Jitter
			}
		}
	}

	return flow.clone(), events
}

func (fe *ForensicsEngine) getOrCreateSession(sessKey SessionKey, pkt *Packet) *SessionRecord {
	sess, exists := fe.sessions[sessKey]
	if exists {
		return sess
	}
	sess = &SessionRecord{
		Client:    fmt.Sprintf("%s:%d", pkt.SrcIP.String(), pkt.SrcPort),
		Server:    fmt.Sprintf("%s:%d", pkt.DstIP.String(), pkt.DstPort),
		Protocol:  protoName(pkt.Protocol),
		FirstSeen: pkt.Timestamp,
		LastSeen:  pkt.Timestamp,
	}
	fe.sessions[sessKey] = sess
	return sess
}

func (fe *ForensicsEngine) evaluateClientHelloThreats(flow *FlowRecord, sess *SessionRecord, ch *ClientHelloSummary, ja4FP string) {
	// 1. Missing SNI on public Internet IP.
	if !ch.HasSNI && !isPrivateIP(net.ParseIP(flow.Key.DstIP)) {
		reason := "Direct IP TLS connection without SNI"
		flow.addThreat("direct_ip_no_sni", 30, reason)
		sess.addThreat("direct_ip_no_sni", 30, reason)
	}

	// 2. High-entropy / DGA SNI indicator.
	if ch.HasSNI {
		sniEntropy := ComputeShannonEntropy([]byte(ch.SNI))
		if sniEntropy > 3.8 && len(ch.SNI) > 20 {
			reason := fmt.Sprintf("High-entropy SNI indicator (%.2f bits/byte)", sniEntropy)
			flow.addThreat("dga_sni", 25, reason)
			sess.addThreat("dga_sni", 25, reason)
		} else if dot := strings.IndexByte(ch.SNI, '.'); dot >= 14 {
			labelEnt := ComputeShannonEntropy([]byte(ch.SNI[:dot]))
			if labelEnt > 3.6 {
				reason := fmt.Sprintf("High-entropy SNI subdomain label (%.2f bits/byte)", labelEnt)
				flow.addThreat("dga_sni", 25, reason)
				sess.addThreat("dga_sni", 25, reason)
			}
		}
	}

	// 3. Abnormally low cipher suite count.
	if len(ch.FilteredCiphers) <= 2 {
		reason := fmt.Sprintf("Abnormally low cipher suite count (%d)", len(ch.FilteredCiphers))
		flow.addThreat("low_cipher_count", 20, reason)
		sess.addThreat("low_cipher_count", 20, reason)
	}

	// 4. Deprecated TLS protocol version.
	if IsDeprecatedTLSVersion(ch.EffectiveVersion) {
		reason := fmt.Sprintf("Deprecated TLS protocol version advertised (%s)", TLSVersionName(ch.EffectiveVersion))
		flow.addThreat("deprecated_tls_client", 25, reason)
		sess.addThreat("deprecated_tls_client", 25, reason)
	}

	// 5. Known JA4 signature database lookup.
	if match, ok := fe.signatures.MatchJA4(ja4FP); ok {
		flow.addSignatureMatch(match)
		sess.addSignatureMatch(match)
		if match.Signature.RiskScore > 0 {
			reason := fmt.Sprintf("Matched JA4 signature [%s]: %s", match.Signature.Category, match.Signature.Name)
			ruleKey := "sig_ja4_" + match.Signature.ID
			flow.addThreat(ruleKey, match.Signature.RiskScore, reason)
			sess.addThreat(ruleKey, match.Signature.RiskScore, reason)
		}
	}
}

func (fe *ForensicsEngine) evaluateServerHelloThreats(flow *FlowRecord, sess *SessionRecord, sh *ServerHelloSummary, ja4sFP string) {
	if IsDeprecatedTLSVersion(sh.EffectiveVersion) {
		reason := fmt.Sprintf("Server negotiated deprecated protocol (%s)", TLSVersionName(sh.EffectiveVersion))
		flow.addThreat("deprecated_tls_server", 25, reason)
		sess.addThreat("deprecated_tls_server", 25, reason)
	}

	if IsWeakCipherSuite(sh.CipherSuite) {
		reason := fmt.Sprintf("Server negotiated weak/broken cipher suite (0x%04x)", sh.CipherSuite)
		flow.addThreat("weak_cipher_suite", 35, reason)
		sess.addThreat("weak_cipher_suite", 35, reason)
	}

	if match, ok := fe.signatures.MatchJA4S(ja4sFP); ok {
		flow.addSignatureMatch(match)
		sess.addSignatureMatch(match)
		if match.Signature.RiskScore > 0 {
			reason := fmt.Sprintf("Matched JA4S signature [%s]: %s", match.Signature.Category, match.Signature.Name)
			ruleKey := "sig_ja4s_" + match.Signature.ID
			flow.addThreat(ruleKey, match.Signature.RiskScore, reason)
			sess.addThreat(ruleKey, match.Signature.RiskScore, reason)
		}
	}
}

func (fe *ForensicsEngine) evaluateCertificateThreats(flow *FlowRecord, sess *SessionRecord, cert *CertificateSummary, ja4xFP string, serverIP net.IP, expired bool) {
	if cert.IsSelfSigned && !isPrivateIP(serverIP) {
		reason := fmt.Sprintf("Self-signed X.509 certificate on public server (CN=%q)", cert.SubjectCN)
		flow.addThreat("self_signed_public_cert", 25, reason)
		sess.addThreat("self_signed_public_cert", 25, reason)
	}

	if expired {
		reason := fmt.Sprintf("Expired or not-yet-valid X.509 certificate (CN=%q)", cert.SubjectCN)
		flow.addThreat("expired_cert", 20, reason)
		sess.addThreat("expired_cert", 20, reason)
	}

	if match, ok := fe.signatures.MatchJA4X(ja4xFP); ok {
		flow.addSignatureMatch(match)
		sess.addSignatureMatch(match)
		if match.Signature.RiskScore > 0 {
			reason := fmt.Sprintf("Matched JA4X signature [%s]: %s", match.Signature.Category, match.Signature.Name)
			ruleKey := "sig_ja4x_" + match.Signature.ID
			flow.addThreat(ruleKey, match.Signature.RiskScore, reason)
			sess.addThreat(ruleKey, match.Signature.RiskScore, reason)
		}
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func protoName(proto uint8) string {
	switch proto {
	case IPProtoTCP:
		return "TCP"
	case IPProtoUDP:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO(%d)", proto)
	}
}

func categorySeverity(c SignatureCategory) int {
	switch c {
	case CategoryMalicious:
		return 4
	case CategorySuspicious:
		return 3
	case CategoryScanner:
		return 2
	case CategoryTool:
		return 1
	case CategoryBenign:
		return 0
	default:
		return -1
	}
}

// ActiveFlows returns a thread-safe snapshot of all active directional flows.
func (fe *ForensicsEngine) ActiveFlows() []*FlowRecord {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	list := make([]*FlowRecord, 0, len(fe.flows))
	for _, f := range fe.flows {
		list = append(list, f.clone())
	}
	return list
}

// Sessions returns a thread-safe, deterministically ordered snapshot of correlated sessions.
func (fe *ForensicsEngine) Sessions() []*SessionRecord {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	list := make([]*SessionRecord, 0, len(fe.sessions))
	for _, s := range fe.sessions {
		list = append(list, s.clone())
	}
	sortSessionsDeterministic(list)
	return list
}

// GenerateReport produces a comprehensive forensic summary of all observed traffic.
func (fe *ForensicsEngine) GenerateReport(captureFormat string, elapsed time.Duration) *ForensicReport {
	fe.mu.RLock()
	defer fe.mu.RUnlock()

	sessions := make([]*SessionRecord, 0, len(fe.sessions))
	var alerts []*SessionRecord

	ja4Counts := make(map[string]int)
	ja4sCounts := make(map[string]int)
	ja4xCounts := make(map[string]int)
	sigHits := make(map[string]int)

	for _, s := range fe.sessions {
		cp := s.clone()
		sessions = append(sessions, cp)
		if cp.ThreatScore > 0 {
			alerts = append(alerts, cp)
		}
		if cp.JA4 != "" {
			ja4Counts[cp.JA4]++
		}
		if cp.JA4S != "" {
			ja4sCounts[cp.JA4S]++
		}
		if cp.JA4X != "" {
			ja4xCounts[cp.JA4X]++
		}
		for _, m := range cp.MatchedSignatures {
			sigHits[m.Signature.Name]++
		}
	}

	sortSessionsDeterministic(sessions)
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].ThreatScore != alerts[j].ThreatScore {
			return alerts[i].ThreatScore > alerts[j].ThreatScore
		}
		return alerts[i].FirstSeen.Before(alerts[j].FirstSeen)
	})

	if len(sigHits) == 0 {
		sigHits = nil
	}

	return &ForensicReport{
		CaptureFormat:    captureFormat,
		Mode:             fe.mode,
		DurationMs:       float64(elapsed.Microseconds()) / 1000.0,
		TotalPackets:     fe.totalPackets,
		TotalBytes:       fe.totalBytes,
		ActiveFlows:      len(fe.flows),
		TotalSessions:    len(sessions),
		ClientHelloCount: fe.clientHelloCount,
		ServerHelloCount: fe.serverHelloCount,
		CertificateCount: fe.certificateCount,
		ThreatSessions:   len(alerts),
		TopJA4:           fe.rankFingerprints("ja4", ja4Counts, 10),
		TopJA4S:          fe.rankFingerprints("ja4s", ja4sCounts, 10),
		TopJA4X:          fe.rankFingerprints("ja4x", ja4xCounts, 10),
		SignatureHits:    sigHits,
		Alerts:           alerts,
		Sessions:         sessions,
	}
}

func (fe *ForensicsEngine) rankFingerprints(sigType string, counts map[string]int, limit int) []FingerprintCount {
	if len(counts) == 0 {
		return nil
	}
	list := make([]FingerprintCount, 0, len(counts))
	for fp, c := range counts {
		fc := FingerprintCount{Fingerprint: fp, Count: c}
		if m, ok := fe.signatures.match(sigType, fp); ok {
			fc.AppName = m.Signature.Name
			fc.Category = string(m.Signature.Category)
		}
		list = append(list, fc)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count != list[j].Count {
			return list[i].Count > list[j].Count
		}
		return list[i].Fingerprint < list[j].Fingerprint
	})
	if len(list) > limit {
		list = list[:limit]
	}
	return list
}

func sortSessionsDeterministic(list []*SessionRecord) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].FirstSeen.Equal(list[j].FirstSeen) {
			return list[i].FirstSeen.Before(list[j].FirstSeen)
		}
		if list[i].Client != list[j].Client {
			return list[i].Client < list[j].Client
		}
		return list[i].Server < list[j].Server
	})
}
