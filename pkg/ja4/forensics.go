package ja4

import (
	"fmt"
	"math"
	"net"
	"time"
)

// FlowKey represents a 5-tuple identifying a directional network flow.
type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   uint8
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

// FlowRecord maintains stateful session telemetry for network forensics.
type FlowRecord struct {
	Key             FlowKey
	FirstSeen       time.Time
	LastSeen        time.Time
	PacketCount     uint64
	ByteCount       uint64
	JA4             string
	SNI             string
	ALPN            string
	ThreatScore     int
	ThreatReasons   []string
	ShannonEntropy  float64
	PayloadSampled  int
	InterArrivalAvg float64
	LastPacketTime  time.Time
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

// ForensicsEngine manages stateful session analysis and threat scoring.
type ForensicsEngine struct {
	flows map[FlowKey]*FlowRecord
	mode  string // "fast" or "deep"
}

// NewForensicsEngine instantiates an analysis engine.
func NewForensicsEngine(mode string) *ForensicsEngine {
	if mode == "" {
		mode = "fast"
	}
	return &ForensicsEngine{
		flows: make(map[FlowKey]*FlowRecord),
		mode:  mode,
	}
}

// ProcessPacket evaluates a network packet and updates session telemetry.
func (fe *ForensicsEngine) ProcessPacket(pkt *Packet) (*FlowRecord, bool) {
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
		if fe.mode == "deep" && !flow.LastPacketTime.IsZero() {
			delta := pkt.Timestamp.Sub(flow.LastPacketTime).Seconds()
			if delta > 0 {
				if flow.InterArrivalAvg == 0 {
					flow.InterArrivalAvg = delta
				} else {
					flow.InterArrivalAvg = (flow.InterArrivalAvg * 0.8) + (delta * 0.2)
				}
			}
		}
		flow.LastSeen = pkt.Timestamp
		flow.LastPacketTime = pkt.Timestamp
	}

	flow.PacketCount++
	flow.ByteCount += uint64(len(pkt.Payload))

	var isNewClientHello bool

	// Check for TLS ClientHello
	if len(pkt.Payload) >= 5 && pkt.Payload[0] == RecordTypeHandshake {
		ch, err := ParseClientHello(pkt.Payload)
		if err == nil {
			flow.JA4 = ch.ComputeJA4()
			flow.SNI = ch.SNI
			flow.ALPN = ch.ALPN
			isNewClientHello = true

			// Run Threat Heuristics
			fe.evaluateThreats(flow, ch, pkt.Payload)
		}
	}

	if fe.mode == "deep" && len(pkt.Payload) > 0 && flow.PayloadSampled < 4096 {
		flow.ShannonEntropy = ComputeShannonEntropy(pkt.Payload)
		flow.PayloadSampled += len(pkt.Payload)
		if flow.ShannonEntropy > 7.7 && flow.JA4 == "" {
			flow.ThreatScore += 20
			flow.ThreatReasons = append(flow.ThreatReasons, fmt.Sprintf("High payload entropy (%.2f bits/byte)", flow.ShannonEntropy))
		}
	}

	return flow, isNewClientHello
}

func (fe *ForensicsEngine) evaluateThreats(flow *FlowRecord, ch *ClientHelloSummary, payload []byte) {
	// 1. Missing SNI on public Internet IP
	if !ch.HasSNI && !isPrivateIP(net.ParseIP(flow.Key.DstIP)) {
		flow.ThreatScore += 30
		flow.ThreatReasons = append(flow.ThreatReasons, "Direct IP TLS connection without SNI")
	}

	// 2. High entropy or suspicious DGA in SNI
	if ch.HasSNI {
		sniEntropy := ComputeShannonEntropy([]byte(ch.SNI))
		if sniEntropy > 3.8 && len(ch.SNI) > 20 {
			flow.ThreatScore += 25
			flow.ThreatReasons = append(flow.ThreatReasons, fmt.Sprintf("High-entropy SNI indicator (%.2f bits/byte)", sniEntropy))
		}
	}

	// 3. Rare or stripped cipher count
	if len(ch.FilteredCiphers) <= 2 {
		flow.ThreatScore += 20
		flow.ThreatReasons = append(flow.ThreatReasons, fmt.Sprintf("Abnormally low cipher suite count (%d)", len(ch.FilteredCiphers)))
	}

	// 4. Known anomalous / malware signature matches
	// E.g., Cobalt Strike default Malleable C2 profiles or Go/Python automated scrapers
	if ch.ComputeJA4() == "t10i010000_000000000000_000000000000" {
		flow.ThreatScore += 50
		flow.ThreatReasons = append(flow.ThreatReasons, "Known barebones scanner / probe TLS signature")
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// ActiveFlows returns a snapshot of all active flows.
func (fe *ForensicsEngine) ActiveFlows() []*FlowRecord {
	list := make([]*FlowRecord, 0, len(fe.flows))
	for _, f := range fe.flows {
		list = append(list, f)
	}
	return list
}
