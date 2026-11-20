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

const version = "0.2.0"

type JSONEvent struct {
	EventType      string                `json:"event_type"`
	Timestamp      string                `json:"timestamp"`
	Src            string                `json:"src"`
	Dst            string                `json:"dst"`
	Protocol       string                `json:"protocol"`
	SNI            string                `json:"sni,omitempty"`
	ALPN           string                `json:"alpn,omitempty"`
	TLSVersion     string                `json:"tls_version,omitempty"`
	SelectedCipher string                `json:"selected_cipher,omitempty"`
	JA4            string                `json:"ja4,omitempty"`
	JA4S           string                `json:"ja4s,omitempty"`
	JA4X           string                `json:"ja4x,omitempty"`
	CertSubjectCN  string                `json:"cert_subject_cn,omitempty"`
	CertSelfSigned bool                  `json:"cert_self_signed,omitempty"`
	HandshakeRTTMs float64               `json:"handshake_rtt_ms,omitempty"`
	AppName        string                `json:"app_name,omitempty"`
	Category       ja4.SignatureCategory `json:"category,omitempty"`
	ThreatScore    int                   `json:"threat_score,omitempty"`
	ThreatReasons  []string              `json:"threat_reasons,omitempty"`
	ShannonEntropy float64               `json:"entropy,omitempty"`
	Jitter         float64               `json:"jitter,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sard", flag.ContinueOnError)
	fs.SetOutput(stderr)

	pcapPath := fs.String("r", "", "Path to PCAP or PCAP-NG capture file (use '-' for stdin)")
	mode := fs.String("mode", "fast", "Analysis procedure: 'fast' (wire-speed streaming) or 'deep' (stateful forensics, jitter & entropy)")
	jsonOutput := fs.Bool("json", false, "Output TLS handshake events as structured JSON Lines (NDJSON)")
	reportJSON := fs.Bool("report-json", false, "Output a single structured JSON forensic summary report")
	alertOnly := fs.Bool("alert", false, "Only emit events/sessions with positive threat detections")
	sigsPath := fs.String("sigs", "", "Path to custom JSON JA4/JA4S/JA4X signature database")
	filterSNI := fs.String("filter-sni", "", "Filter output by SNI substring")
	filterJA4 := fs.String("filter-ja4", "", "Filter output by JA4 fingerprint prefix")
	filterJA4S := fs.String("filter-ja4s", "", "Filter output by JA4S fingerprint prefix")
	filterCategory := fs.String("filter-category", "", "Filter output by matched signature category (benign, tool, scanner, suspicious, malicious)")
	showVersion := fs.Bool("version", false, "Print engine version and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Sard v%s - Zero-Dependency TLS JA4/JA4S/JA4X & PCAP/PCAP-NG Forensics Engine\n\n", version)
		fmt.Fprintf(stderr, "Usage: sard [options] -r <capture.pcap|capture.pcapng>\n\n")
		fmt.Fprintf(stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nDual Procedures:\n")
		fmt.Fprintf(stderr, "  --mode=fast   Streaming TLS dissection, TCP handshake reassembly, and signature matching.\n")
		fmt.Fprintf(stderr, "  --mode=deep   Full stateful forensics with jitter, beacon detection, and Shannon entropy.\n")
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "Sard %s (Aether Systems & Research Lab)\n", version)
		return 0
	}

	if *mode != "fast" && *mode != "deep" {
		fmt.Fprintf(stderr, "Error: invalid --mode %q (expected 'fast' or 'deep')\n", *mode)
		return 1
	}

	if *pcapPath == "" {
		fs.Usage()
		return 1
	}

	sigDB := ja4.DefaultSignatureDB()
	if *sigsPath != "" {
		if _, err := sigDB.LoadJSONFile(*sigsPath); err != nil {
			fmt.Fprintf(stderr, "Error loading signature database %s: %v\n", *sigsPath, err)
			return 1
		}
	}

	var reader io.Reader
	if *pcapPath == "-" {
		reader = stdin
	} else {
		f, err := os.Open(*pcapPath)
		if err != nil {
			fmt.Fprintf(stderr, "Error opening capture file: %v\n", err)
			return 1
		}
		defer f.Close()
		reader = f
	}

	pcapReader, err := ja4.NewPCAPReader(reader)
	if err != nil {
		fmt.Fprintf(stderr, "Error parsing capture stream: %v\n", err)
		return 1
	}

	engine := ja4.NewForensicsEngineWithSignatures(*mode, sigDB)
	start := time.Now()

	var packetCount uint64
	var chCount uint64
	var shCount uint64
	var certCount uint64
	var threatCount uint64

	tabular := !*jsonOutput && !*reportJSON
	if tabular {
		fmt.Fprintf(stdout, "Sard v%s starting [%s mode, %s format, %d signatures] on %s\n",
			version, *mode, strings.ToUpper(pcapReader.Format), sigDB.Count(), *pcapPath)
		fmt.Fprintf(stdout, "%-16s %-5s %-22s %-22s %-24s %-36s %s\n",
			"TIMESTAMP", "TYPE", "SOURCE", "DESTINATION", "SNI / CN", "FINGERPRINT", "STATUS")
		fmt.Fprintln(stdout, strings.Repeat("-", 155))
	}

	for {
		pkt, err := pcapReader.NextPacket()
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			continue
		}

		packetCount++
		_, events := engine.ProcessPacketEvent(pkt)

		for _, ev := range events {
			switch ev.Type {
			case ja4.EventClientHello:
				chCount++
			case ja4.EventServerHello:
				shCount++
			case ja4.EventCertificate:
				certCount++
			}

			if !matchesFilters(ev, *filterSNI, *filterJA4, *filterJA4S, *filterCategory, *alertOnly) {
				continue
			}

			if ev.ThreatScore > 0 {
				threatCount++
			}

			if *reportJSON {
				continue
			}

			if *jsonOutput {
				outEvt := JSONEvent{
					EventType:      string(ev.Type),
					Timestamp:      formatEventTimeRFC3339(ev.Timestamp),
					Src:            ev.Src,
					Dst:            ev.Dst,
					Protocol:       ev.Protocol,
					SNI:            ev.SNI,
					ALPN:           ev.ALPN,
					TLSVersion:     ev.TLSVersion,
					SelectedCipher: ev.SelectedCipher,
					JA4:            ev.JA4,
					JA4S:           ev.JA4S,
					JA4X:           ev.JA4X,
					CertSubjectCN:  ev.CertSubjectCN,
					CertSelfSigned: ev.CertSelfSigned,
					HandshakeRTTMs: ev.HandshakeRTTMs,
					AppName:        ev.AppName,
					Category:       ev.Category,
					ThreatScore:    ev.ThreatScore,
					ThreatReasons:  ev.ThreatReasons,
					ShannonEntropy: ev.ShannonEntropy,
					Jitter:         ev.Jitter,
				}
				line, _ := json.Marshal(outEvt)
				fmt.Fprintln(stdout, string(line))
			} else {
				printTabularEvent(stdout, ev)
			}
		}
	}

	elapsed := time.Since(start)

	if *reportJSON {
		report := engine.GenerateReport(pcapReader.Format, elapsed)
		filterReport(report, *filterSNI, *filterJA4, *filterJA4S, *filterCategory, *alertOnly)
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "Error encoding JSON report: %v\n", err)
			return 1
		}
		return 0
	}

	if tabular {
		fmt.Fprintln(stdout, strings.Repeat("-", 155))
		rate := float64(packetCount) / elapsed.Seconds()
		if elapsed.Seconds() == 0 {
			rate = float64(packetCount)
		}
		fmt.Fprintf(stdout, "Analysis complete in %s: %d packets (%.1f pkt/s), %d ClientHellos, %d ServerHellos, %d Certificates, %d threat events\n",
			elapsed.Round(time.Millisecond), packetCount, rate, chCount, shCount, certCount, threatCount)
	}

	return 0
}

func matchesFilters(ev ja4.ForensicEvent, sniFilter, ja4Filter, ja4sFilter, catFilter string, alertOnly bool) bool {
	if sniFilter != "" && !strings.Contains(strings.ToLower(ev.SNI), strings.ToLower(sniFilter)) {
		return false
	}
	if ja4Filter != "" && !strings.HasPrefix(strings.ToLower(ev.JA4), strings.ToLower(ja4Filter)) {
		return false
	}
	if ja4sFilter != "" && !strings.HasPrefix(strings.ToLower(ev.JA4S), strings.ToLower(ja4sFilter)) {
		return false
	}
	if catFilter != "" && !strings.EqualFold(string(ev.Category), catFilter) {
		return false
	}
	if alertOnly && ev.ThreatScore == 0 {
		return false
	}
	return true
}

func filterReport(r *ja4.ForensicReport, sniFilter, ja4Filter, ja4sFilter, catFilter string, alertOnly bool) {
	if sniFilter == "" && ja4Filter == "" && ja4sFilter == "" && catFilter == "" && !alertOnly {
		return
	}
	matchSess := func(s *ja4.SessionRecord) bool {
		if sniFilter != "" && !strings.Contains(strings.ToLower(s.SNI), strings.ToLower(sniFilter)) {
			return false
		}
		if ja4Filter != "" && !strings.HasPrefix(strings.ToLower(s.JA4), strings.ToLower(ja4Filter)) {
			return false
		}
		if ja4sFilter != "" && !strings.HasPrefix(strings.ToLower(s.JA4S), strings.ToLower(ja4sFilter)) {
			return false
		}
		if catFilter != "" && !strings.EqualFold(string(s.Category), catFilter) {
			return false
		}
		if alertOnly && s.ThreatScore == 0 {
			return false
		}
		return true
	}

	var filteredSessions []*ja4.SessionRecord
	for _, s := range r.Sessions {
		if matchSess(s) {
			filteredSessions = append(filteredSessions, s)
		}
	}
	var filteredAlerts []*ja4.SessionRecord
	for _, a := range r.Alerts {
		if matchSess(a) {
			filteredAlerts = append(filteredAlerts, a)
		}
	}
	r.Sessions = filteredSessions
	r.Alerts = filteredAlerts
	r.TotalSessions = len(filteredSessions)
	r.ThreatSessions = len(filteredAlerts)
}

func formatEventTimeRFC3339(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339Nano)
}

func printTabularEvent(w io.Writer, ev ja4.ForensicEvent) {
	typeTag := "CH"
	fp := ev.JA4
	label := ev.SNI
	switch ev.Type {
	case ja4.EventServerHello:
		typeTag = "SH"
		fp = ev.JA4S
		if label == "" {
			label = ev.SelectedCipher
		}
	case ja4.EventCertificate:
		typeTag = "CERT"
		fp = ev.JA4X
		if ev.CertSubjectCN != "" {
			label = ev.CertSubjectCN
		}
	}

	if label == "" {
		label = "<none>"
	}
	if len(label) > 23 {
		label = label[:20] + "..."
	}

	status := "CLEAN"
	if ev.AppName != "" && ev.ThreatScore == 0 {
		status = fmt.Sprintf("MATCH(%s: %s)", ev.Category, ev.AppName)
	}
	if ev.ThreatScore > 0 {
		status = fmt.Sprintf("ALERT(%d: %s)", ev.ThreatScore, strings.Join(ev.ThreatReasons, "; "))
	}

	tsStr := "00:00:00.000000"
	if !ev.Timestamp.IsZero() {
		tsStr = ev.Timestamp.UTC().Format("15:04:05.000000")
	}

	fmt.Fprintf(w, "%-16s %-5s %-22s %-22s %-24s %-36s %s\n",
		tsStr, typeTag, ev.Src, ev.Dst, label, fp, status)
}
