package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Aetherx86/Sard/pkg/ja4"
)

const version = "0.1.0"

type JSONEvent struct {
	Timestamp      string   `json:"timestamp"`
	Src            string   `json:"src"`
	Dst            string   `json:"dst"`
	Protocol       string   `json:"protocol"`
	SNI            string   `json:"sni,omitempty"`
	ALPN           string   `json:"alpn,omitempty"`
	JA4            string   `json:"ja4,omitempty"`
	ThreatScore    int      `json:"threat_score,omitempty"`
	ThreatReasons  []string `json:"threat_reasons,omitempty"`
	ShannonEntropy float64  `json:"entropy,omitempty"`
}

func main() {
	pcapPath := flag.String("r", "", "Path to PCAP file (use '-' for stdin)")
	mode := flag.String("mode", "fast", "Analysis procedure: 'fast' (wire-speed streaming) or 'deep' (stateful forensics & entropy)")
	jsonOutput := flag.Bool("json", false, "Output events as structured JSON Lines (NDJSON)")
	alertOnly := flag.Bool("alert", false, "Only emit flows with positive threat detections")
	filterSNI := flag.String("filter-sni", "", "Filter output by SNI string")
	filterJA4 := flag.String("filter-ja4", "", "Filter output by JA4 fingerprint prefix")
	showVersion := flag.Bool("version", false, "Print engine version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Sard v%s - Zero-Allocation TLS ClientHello & Network Forensics Engine\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: sard [options] -r <capture.pcap>\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDual Procedures:\n")
		fmt.Fprintf(os.Stderr, "  --mode=fast   Zero-copy packet streaming for high-throughput wire processing (>5M pkt/s).\n")
		fmt.Fprintf(os.Stderr, "  --mode=deep   Stateful session reassembly, packet jitter calculation, and Shannon entropy analysis.\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("Sard %s (Aether Systems & Research Lab)\n", version)
		os.Exit(0)
	}

	if *pcapPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	var reader io.Reader
	if *pcapPath == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(*pcapPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening PCAP file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	}

	pcapReader, err := ja4.NewPCAPReader(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing PCAP stream: %v\n", err)
		os.Exit(1)
	}

	engine := ja4.NewForensicsEngine(*mode)
	start := time.Now()

	var packetCount uint64
	var chCount uint64
	var threatCount uint64

	if !*jsonOutput {
		fmt.Printf("Sard v%s starting [%s mode] on %s\n", version, *mode, *pcapPath)
		fmt.Printf("%-20s %-22s %-22s %-25s %-36s %s\n",
			"TIMESTAMP", "SOURCE", "DESTINATION", "SNI", "JA4 FINGERPRINT", "STATUS")
		fmt.Println(strings.Repeat("-", 145))
	}

	for {
		pkt, err := pcapReader.NextPacket()
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			// Non-fatal frame error
			continue
		}

		packetCount++
		flow, isCH := engine.ProcessPacket(pkt)

		if isCH {
			chCount++

			if *filterSNI != "" && !strings.Contains(strings.ToLower(flow.SNI), strings.ToLower(*filterSNI)) {
				continue
			}
			if *filterJA4 != "" && !strings.HasPrefix(strings.ToLower(flow.JA4), strings.ToLower(*filterJA4)) {
				continue
			}
			if *alertOnly && flow.ThreatScore == 0 {
				continue
			}

			if flow.ThreatScore > 0 {
				threatCount++
			}

			if *jsonOutput {
				evt := JSONEvent{
					Timestamp:      pkt.Timestamp.UTC().Format(time.RFC3339Nano),
					Src:            fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort),
					Dst:            fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort),
					Protocol:       "TCP",
					SNI:            flow.SNI,
					ALPN:           flow.ALPN,
					JA4:            flow.JA4,
					ThreatScore:    flow.ThreatScore,
					ThreatReasons:  flow.ThreatReasons,
					ShannonEntropy: flow.ShannonEntropy,
				}
				line, _ := json.Marshal(evt)
				fmt.Println(string(line))
			} else {
				status := "CLEAN"
				if flow.ThreatScore > 0 {
					status = fmt.Sprintf("ALERT(%d: %s)", flow.ThreatScore, strings.Join(flow.ThreatReasons, "; "))
				}

				sniDisplay := flow.SNI
				if sniDisplay == "" {
					sniDisplay = "<none>"
				}
				if len(sniDisplay) > 24 {
					sniDisplay = sniDisplay[:21] + "..."
				}

				srcStr := fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.SrcPort)
				dstStr := fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)

				fmt.Printf("%-20s %-22s %-22s %-25s %-36s %s\n",
					pkt.Timestamp.Format("15:04:05.000000"),
					srcStr,
					dstStr,
					sniDisplay,
					flow.JA4,
					status,
				)
			}
		}
	}

	elapsed := time.Since(start)

	if !*jsonOutput {
		fmt.Println(strings.Repeat("-", 145))
		rate := float64(packetCount) / elapsed.Seconds()
		if elapsed.Seconds() == 0 {
			rate = float64(packetCount)
		}
		fmt.Printf("Analysis complete in %s: %d packets processed (%.1f pkt/s), %d ClientHellos, %d threats flagged\n",
			elapsed.Round(time.Millisecond), packetCount, rate, chCount, threatCount)
	}
}
