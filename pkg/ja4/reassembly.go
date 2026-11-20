package ja4

import (
	"encoding/binary"
	"sort"
)

const (
	defaultMaxStreamBytes = 65536
	defaultMaxStreams     = 10000
	defaultMaxOOOSegments = 32
	maxUnanchoredSegments = 4
)

type tcpSegment struct {
	seq  uint32
	data []byte
}

type tcpStream struct {
	hasSeq        bool
	nextSeq       uint32
	done          bool
	seenBytes     int
	recordVersion uint16
	rawBuf        []byte
	hsBuf         []byte
	ooo           []tcpSegment
	unanchored    []tcpSegment
}

// StreamReassembler performs bounded, sequence-ordered TCP stream reassembly
// specifically targeting TLS handshake records (ClientHello, ServerHello, Certificate).
type StreamReassembler struct {
	streams        map[FlowKey]*tcpStream
	order          []FlowKey
	maxStreamBytes int
	maxStreams     int
}

// NewStreamReassembler creates a bounded TCP handshake stream reassembler.
func NewStreamReassembler(maxStreams, maxStreamBytes int) *StreamReassembler {
	if maxStreams <= 0 {
		maxStreams = defaultMaxStreams
	}
	if maxStreamBytes <= 0 {
		maxStreamBytes = defaultMaxStreamBytes
	}
	return &StreamReassembler{
		streams:        make(map[FlowKey]*tcpStream),
		maxStreamBytes: maxStreamBytes,
		maxStreams:     maxStreams,
	}
}

// ActiveStreams returns the number of currently tracked TCP streams.
func (sr *StreamReassembler) ActiveStreams() int {
	return len(sr.streams)
}

// Feed ingests a TCP packet for flow key and returns any newly completed TLS
// handshake messages reassembled from the stream.
func (sr *StreamReassembler) Feed(key FlowKey, pkt *Packet) []HandshakeMessage {
	if pkt == nil {
		return nil
	}

	isSYN := pkt.TCPFlags&TCPFlagSYN != 0
	isFIN := pkt.TCPFlags&TCPFlagFIN != 0
	isRST := pkt.TCPFlags&TCPFlagRST != 0

	if isRST && len(pkt.Payload) == 0 {
		delete(sr.streams, key)
		return nil
	}

	stream, exists := sr.streams[key]

	// Fast path for stateless synthetic packets (SeqNum == 0, no prior stream state,
	// complete TLS handshake record(s) in a single packet).
	if !exists && pkt.SeqNum == 0 && !isSYN && len(pkt.Payload) > 0 {
		if pkt.Payload[0] != RecordTypeHandshake {
			return nil
		}
		msgs, consumed, err := ExtractHandshakeMessages(pkt.Payload)
		if err == nil && len(msgs) > 0 && consumed == len(pkt.Payload) {
			return msgs
		}
		// Partial record on a synthetic stream: fall through to create a sequential buffer.
	}

	if !exists {
		if len(pkt.Payload) == 0 && !isSYN {
			return nil
		}
		sr.evictIfNeeded()
		stream = &tcpStream{}
		sr.streams[key] = stream
		sr.order = append(sr.order, key)
	}

	if isSYN {
		// SYN consumes 1 sequence number before the first payload byte.
		if !stream.hasSeq {
			stream.hasSeq = true
			stream.nextSeq = pkt.SeqNum + 1
		}
	}

	var msgs []HandshakeMessage
	if !stream.done && len(pkt.Payload) > 0 {
		sr.ingestPayload(stream, pkt.SeqNum, pkt.Payload)
		msgs = sr.drainTLS(stream)
	}

	if isFIN || isRST {
		delete(sr.streams, key)
	}

	return msgs
}

func (sr *StreamReassembler) evictIfNeeded() {
	if len(sr.streams) < sr.maxStreams {
		return
	}
	// Evict oldest tracked stream(s) to enforce memory ceiling.
	for len(sr.order) > 0 && len(sr.streams) >= sr.maxStreams {
		oldest := sr.order[0]
		sr.order = sr.order[1:]
		delete(sr.streams, oldest)
	}
}

func (sr *StreamReassembler) ingestPayload(s *tcpStream, seq uint32, payload []byte) {
	if len(payload) == 0 || s.done {
		return
	}

	// Sequential mode for synthetic packets that leave SeqNum == 0.
	if seq == 0 && !s.hasSeq {
		if s.seenBytes+len(payload) > sr.maxStreamBytes {
			s.markDone()
			return
		}
		s.rawBuf = append(s.rawBuf, payload...)
		s.seenBytes += len(payload)
		return
	}

	if !s.hasSeq {
		if looksLikeTLSHandshakeRecord(payload) {
			s.hasSeq = true
			s.nextSeq = seq
			s.appendInOrder(payload, sr.maxStreamBytes)
			// Promote any previously held unanchored segments that follow this sequence number.
			if len(s.unanchored) > 0 {
				pending := s.unanchored
				s.unanchored = nil
				for _, seg := range pending {
					s.insertSequenced(seg.seq, seg.data, sr.maxStreamBytes)
				}
			}
			return
		}

		// Hold a small window of out-of-order segments in case segment 1 arrives late
		// in a mid-stream capture without a SYN packet.
		if len(s.unanchored) < maxUnanchoredSegments && len(payload) <= sr.maxStreamBytes {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			s.unanchored = append(s.unanchored, tcpSegment{seq: seq, data: cp})
		} else {
			s.markDone()
		}
		return
	}

	s.insertSequenced(seq, payload, sr.maxStreamBytes)
}

func (s *tcpStream) insertSequenced(seq uint32, payload []byte, maxBytes int) {
	if s.done || len(payload) == 0 {
		return
	}

	diff := int32(seq - s.nextSeq)
	if diff < 0 {
		// Retransmission or overlapping segment.
		overlap := int(-diff)
		if overlap >= len(payload) {
			return
		}
		payload = payload[overlap:]
		seq = s.nextSeq
		diff = 0
	}

	if diff == 0 {
		s.appendInOrder(payload, maxBytes)
		s.flushOOO(maxBytes)
		return
	}

	// Future out-of-order segment.
	if int(diff) > maxBytes || len(s.ooo) >= defaultMaxOOOSegments {
		return
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	s.ooo = append(s.ooo, tcpSegment{seq: seq, data: cp})
	sort.Slice(s.ooo, func(i, j int) bool {
		return int32(s.ooo[i].seq-s.ooo[j].seq) < 0
	})
}

func (s *tcpStream) appendInOrder(payload []byte, maxBytes int) {
	remaining := maxBytes - s.seenBytes
	if remaining <= 0 {
		s.markDone()
		return
	}
	if len(payload) > remaining {
		payload = payload[:remaining]
	}
	s.rawBuf = append(s.rawBuf, payload...)
	s.seenBytes += len(payload)
	s.nextSeq += uint32(len(payload))
}

func (s *tcpStream) flushOOO(maxBytes int) {
	for len(s.ooo) > 0 && !s.done {
		seg := s.ooo[0]
		diff := int32(seg.seq - s.nextSeq)
		if diff > 0 {
			break
		}
		s.ooo = s.ooo[1:]
		data := seg.data
		if diff < 0 {
			overlap := int(-diff)
			if overlap >= len(data) {
				continue
			}
			data = data[overlap:]
		}
		s.appendInOrder(data, maxBytes)
	}
}

func (sr *StreamReassembler) drainTLS(s *tcpStream) []HandshakeMessage {
	// Layer 1: Drain complete TLS Handshake (0x16) records from rawBuf into hsBuf.
	for len(s.rawBuf) >= 5 {
		recType := s.rawBuf[0]
		if recType != RecordTypeHandshake {
			if recType == RecordTypeChangeCipherSpec || recType == RecordTypeAlert || recType == RecordTypeApplicationData {
				// Plaintext handshake phase has concluded; drain any remaining handshake messages
				// already buffered in hsBuf, then stop tracking this stream.
				msgs := drainHandshakeMessages(s)
				s.markDone()
				return msgs
			}
			s.markDone()
			return nil
		}

		recVer := binary.BigEndian.Uint16(s.rawBuf[1:3])
		recLen := int(binary.BigEndian.Uint16(s.rawBuf[3:5]))
		if !isPlausibleTLSRecordVersion(recVer) || recLen == 0 || recLen > 18432 {
			s.markDone()
			return nil
		}

		totalRec := 5 + recLen
		if len(s.rawBuf) < totalRec {
			// Wait for more TCP bytes to complete this TLS record.
			break
		}

		if s.recordVersion == 0 {
			s.recordVersion = recVer
		}
		s.hsBuf = append(s.hsBuf, s.rawBuf[5:totalRec]...)
		if totalRec == len(s.rawBuf) {
			s.rawBuf = s.rawBuf[:0]
		} else {
			copy(s.rawBuf, s.rawBuf[totalRec:])
			s.rawBuf = s.rawBuf[:len(s.rawBuf)-totalRec]
		}
	}

	// Layer 2: Drain complete Handshake Messages from hsBuf.
	msgs := drainHandshakeMessages(s)
	if s.seenBytes >= sr.maxStreamBytes && len(s.rawBuf) == 0 && len(s.hsBuf) == 0 {
		s.markDone()
	}
	return msgs
}

func drainHandshakeMessages(s *tcpStream) []HandshakeMessage {
	var msgs []HandshakeMessage
	for len(s.hsBuf) >= 4 {
		msgType := s.hsBuf[0]
		msgLen := int(s.hsBuf[1])<<16 | int(s.hsBuf[2])<<8 | int(s.hsBuf[3])
		if msgLen > 131072 {
			s.markDone()
			return msgs
		}
		totalMsg := 4 + msgLen
		if len(s.hsBuf) < totalMsg {
			break
		}
		body := make([]byte, msgLen)
		copy(body, s.hsBuf[4:totalMsg])
		msgs = append(msgs, HandshakeMessage{
			Type:          msgType,
			RecordVersion: s.recordVersion,
			Body:          body,
		})
		if totalMsg == len(s.hsBuf) {
			s.hsBuf = s.hsBuf[:0]
		} else {
			copy(s.hsBuf, s.hsBuf[totalMsg:])
			s.hsBuf = s.hsBuf[:len(s.hsBuf)-totalMsg]
		}
	}
	return msgs
}

func (s *tcpStream) markDone() {
	s.done = true
	s.rawBuf = nil
	s.hsBuf = nil
	s.ooo = nil
	s.unanchored = nil
}

func looksLikeTLSHandshakeRecord(payload []byte) bool {
	if len(payload) < 5 || payload[0] != RecordTypeHandshake {
		return false
	}
	ver := binary.BigEndian.Uint16(payload[1:3])
	recLen := binary.BigEndian.Uint16(payload[3:5])
	return isPlausibleTLSRecordVersion(ver) && recLen > 0 && recLen <= 18432
}

func isPlausibleTLSRecordVersion(ver uint16) bool {
	return (ver>>8) == 0x03 || ver == 0xfeff || ver == 0xfefd || ver == 0xfefc
}
