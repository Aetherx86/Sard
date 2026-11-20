package ja4

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// SignatureCategory classifies a matched TLS fingerprint.
type SignatureCategory string

const (
	CategoryBenign     SignatureCategory = "benign"
	CategoryTool       SignatureCategory = "tool"
	CategoryScanner    SignatureCategory = "scanner"
	CategorySuspicious SignatureCategory = "suspicious"
	CategoryMalicious  SignatureCategory = "malicious"
)

// Signature describes a known JA4, JA4S, or JA4X fingerprint rule.
type Signature struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"` // "ja4", "ja4s", "ja4x"
	Pattern     string            `json:"pattern"`
	Name        string            `json:"name"`
	Category    SignatureCategory `json:"category"`
	RiskScore   int               `json:"risk_score,omitempty"`
	Description string            `json:"description,omitempty"`
	Reference   string            `json:"reference,omitempty"`
}

// SignatureMatch captures a positive lookup against a SignatureDB.
type SignatureMatch struct {
	Signature    Signature `json:"signature"`
	MatchedValue string    `json:"matched_value"`
	Exact        bool      `json:"exact"`
}

// SignatureDB stores indexed JA4, JA4S, and JA4X signatures for thread-safe lookup.
type SignatureDB struct {
	mu           sync.RWMutex
	exactJA4     map[string]Signature
	exactJA4S    map[string]Signature
	exactJA4X    map[string]Signature
	wildcardJA4  []Signature
	wildcardJA4S []Signature
	wildcardJA4X []Signature
}

// NewSignatureDB returns an empty SignatureDB.
func NewSignatureDB() *SignatureDB {
	return &SignatureDB{
		exactJA4:  make(map[string]Signature),
		exactJA4S: make(map[string]Signature),
		exactJA4X: make(map[string]Signature),
	}
}

// DefaultSignatureDB returns a SignatureDB pre-populated with curated JA4, JA4S,
// and JA4X signatures covering modern browsers, runtimes, servers, scanners, and C2 profiles.
func DefaultSignatureDB() *SignatureDB {
	db := NewSignatureDB()
	for _, sig := range builtinSignatures {
		_ = db.Add(sig)
	}
	return db
}

// Add inserts or updates a signature in the database.
func (db *SignatureDB) Add(sig Signature) error {
	sig.Type = strings.ToLower(strings.TrimSpace(sig.Type))
	sig.Pattern = strings.ToLower(strings.TrimSpace(sig.Pattern))
	if sig.Pattern == "" {
		return errors.New("signature pattern cannot be empty")
	}
	if sig.Type != "ja4" && sig.Type != "ja4s" && sig.Type != "ja4x" {
		return fmt.Errorf("unsupported signature type %q (expected ja4, ja4s, or ja4x)", sig.Type)
	}
	if sig.Category == "" {
		sig.Category = CategorySuspicious
	}
	if sig.Name == "" {
		sig.Name = sig.ID
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	isWild := strings.ContainsRune(sig.Pattern, '*')
	switch sig.Type {
	case "ja4":
		if isWild {
			db.wildcardJA4 = upsertWildcard(db.wildcardJA4, sig)
		} else {
			db.exactJA4[sig.Pattern] = sig
		}
	case "ja4s":
		if isWild {
			db.wildcardJA4S = upsertWildcard(db.wildcardJA4S, sig)
		} else {
			db.exactJA4S[sig.Pattern] = sig
		}
	case "ja4x":
		if isWild {
			db.wildcardJA4X = upsertWildcard(db.wildcardJA4X, sig)
		} else {
			db.exactJA4X[sig.Pattern] = sig
		}
	}
	return nil
}

func upsertWildcard(list []Signature, sig Signature) []Signature {
	for i := range list {
		if list[i].Pattern == sig.Pattern {
			list[i] = sig
			return list
		}
	}
	return append(list, sig)
}

// Count returns the total number of registered signatures across all fingerprint types.
func (db *SignatureDB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.exactJA4) + len(db.exactJA4S) + len(db.exactJA4X) +
		len(db.wildcardJA4) + len(db.wildcardJA4S) + len(db.wildcardJA4X)
}

// MatchJA4 looks up a JA4 ClientHello fingerprint.
func (db *SignatureDB) MatchJA4(fp string) (SignatureMatch, bool) {
	return db.match("ja4", fp)
}

// MatchJA4S looks up a JA4S ServerHello fingerprint.
func (db *SignatureDB) MatchJA4S(fp string) (SignatureMatch, bool) {
	return db.match("ja4s", fp)
}

// MatchJA4X looks up a JA4X X.509 certificate fingerprint.
func (db *SignatureDB) MatchJA4X(fp string) (SignatureMatch, bool) {
	return db.match("ja4x", fp)
}

func (db *SignatureDB) match(sigType, fp string) (SignatureMatch, bool) {
	if db == nil || fp == "" {
		return SignatureMatch{}, false
	}
	norm := strings.ToLower(strings.TrimSpace(fp))

	db.mu.RLock()
	defer db.mu.RUnlock()

	var exactMap map[string]Signature
	var wildcards []Signature
	switch sigType {
	case "ja4":
		exactMap = db.exactJA4
		wildcards = db.wildcardJA4
	case "ja4s":
		exactMap = db.exactJA4S
		wildcards = db.wildcardJA4S
	case "ja4x":
		exactMap = db.exactJA4X
		wildcards = db.wildcardJA4X
	default:
		return SignatureMatch{}, false
	}

	if sig, ok := exactMap[norm]; ok {
		return SignatureMatch{
			Signature:    sig,
			MatchedValue: norm,
			Exact:        true,
		}, true
	}

	var best Signature
	bestSpec := -1
	matched := false
	for _, sig := range wildcards {
		if wildcardMatch(sig.Pattern, norm) {
			spec := patternSpecificity(sig.Pattern)
			if !matched || spec > bestSpec || (spec == bestSpec && sig.RiskScore > best.RiskScore) {
				best = sig
				bestSpec = spec
				matched = true
			}
		}
	}
	if matched {
		return SignatureMatch{
			Signature:    best,
			MatchedValue: norm,
			Exact:        false,
		}, true
	}
	return SignatureMatch{}, false
}

// LoadJSON parses signature rules from r and registers them in the database.
// It supports both Sard native format (JSON array or {"signatures": [...]}) and
// FoxIO JA4DB-style entries (ja4_fingerprint / ja4s_fingerprint / ja4x_fingerprint).
func (db *SignatureDB) LoadJSON(r io.Reader) (int, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("failed reading signature JSON: %w", err)
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return 0, nil
	}

	type rawSigEntry struct {
		ID              string            `json:"id"`
		Type            string            `json:"type"`
		Pattern         string            `json:"pattern"`
		Name            string            `json:"name"`
		Category        SignatureCategory `json:"category"`
		RiskScore       int               `json:"risk_score"`
		Description     string            `json:"description"`
		Reference       string            `json:"reference"`
		Application     string            `json:"application"`
		Notes           string            `json:"notes"`
		JA4Fingerprint  string            `json:"ja4_fingerprint"`
		JA4SFingerprint string            `json:"ja4s_fingerprint"`
		JA4XFingerprint string            `json:"ja4x_fingerprint"`
	}

	var entries []rawSigEntry
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return 0, fmt.Errorf("invalid signature array JSON: %w", err)
		}
	} else {
		var wrapper struct {
			Signatures []rawSigEntry `json:"signatures"`
		}
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return 0, fmt.Errorf("invalid signature object JSON: %w", err)
		}
		entries = wrapper.Signatures
	}

	loaded := 0
	for i, e := range entries {
		name := e.Name
		if name == "" {
			name = e.Application
		}
		desc := e.Description
		if desc == "" {
			desc = e.Notes
		}
		cat := e.Category
		if cat == "" {
			if e.RiskScore > 0 {
				cat = CategorySuspicious
			} else {
				cat = CategoryBenign
			}
		}

		addOne := func(sigType, pattern string) error {
			if pattern == "" {
				return nil
			}
			id := e.ID
			if id == "" {
				id = fmt.Sprintf("custom-%s-%d", sigType, i+1)
			}
			if err := db.Add(Signature{
				ID:          id,
				Type:        sigType,
				Pattern:     pattern,
				Name:        name,
				Category:    cat,
				RiskScore:   e.RiskScore,
				Description: desc,
				Reference:   e.Reference,
			}); err != nil {
				return err
			}
			loaded++
			return nil
		}

		if e.Type != "" && e.Pattern != "" {
			if err := addOne(e.Type, e.Pattern); err != nil {
				return loaded, err
			}
			continue
		}
		// JA4DB-compatible fallback fields.
		if err := addOne("ja4", e.JA4Fingerprint); err != nil {
			return loaded, err
		}
		if err := addOne("ja4s", e.JA4SFingerprint); err != nil {
			return loaded, err
		}
		if err := addOne("ja4x", e.JA4XFingerprint); err != nil {
			return loaded, err
		}
	}

	return loaded, nil
}

// LoadJSONFile opens path and loads JSON signature definitions into the database.
func (db *SignatureDB) LoadJSONFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return db.LoadJSON(f)
}

func patternSpecificity(p string) int {
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] != '*' {
			n++
		}
	}
	return n
}

// wildcardMatch matches s against pattern where '*' matches zero or more characters.
func wildcardMatch(pattern, s string) bool {
	pi, si := 0, 0
	starIdx, matchIdx := -1, 0

	for si < len(s) {
		if pi < len(pattern) && pattern[pi] == s[si] {
			pi++
			si++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = si
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			si = matchIdx
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

var builtinSignatures = []Signature{
	// Benign browsers & standard clients (JA4)
	{
		ID:          "ja4-chrome-120-h2",
		Type:        "ja4",
		Pattern:     "t13d1516h2_8daaf6152771_e5627efa2ab1",
		Name:        "Chromium / Google Chrome (TLS 1.3 H2)",
		Category:    CategoryBenign,
		Description: "Standard BoringSSL TLS 1.3 ClientHello with HTTP/2 ALPN and GREASE.",
	},
	{
		ID:          "ja4-chrome-125-h2",
		Type:        "ja4",
		Pattern:     "t13d1516h2_8daaf6152771_02713d6af862",
		Name:        "Chromium / Google Chrome (Post-Quantum KeyShare)",
		Category:    CategoryBenign,
		Description: "Modern Chrome TLS 1.3 ClientHello with X25519Kyber768/MLKEM768.",
	},
	{
		ID:          "ja4-firefox-tls13-h2",
		Type:        "ja4",
		Pattern:     "t13d1715h2_5b57614c22b0_3d5424432f57",
		Name:        "Mozilla Firefox (NSS TLS 1.3 H2)",
		Category:    CategoryBenign,
		Description: "Standard Firefox NSS TLS 1.3 ClientHello.",
	},
	{
		ID:          "ja4-safari-tls13-h2",
		Type:        "ja4",
		Pattern:     "t13d2014h2_a09f3c656075_14788d8d241b",
		Name:        "Apple Safari / WebKit (TLS 1.3 H2)",
		Category:    CategoryBenign,
		Description: "Apple Network.framework / BoringSSL TLS 1.3 ClientHello.",
	},
	{
		ID:          "ja4-go-stdlib-http",
		Type:        "ja4",
		Pattern:     "t13d190900_9dc949149365_97f8aa674fd9",
		Name:        "Go crypto/tls HTTP/1.1 Client",
		Category:    CategoryTool,
		Description: "Go standard library TLS 1.3 client without ALPN.",
	},
	{
		ID:          "ja4-go-stdlib-h2",
		Type:        "ja4",
		Pattern:     "t13d1910h2_9dc949149365_97f8aa674fd9",
		Name:        "Go net/http TLS 1.3 Client",
		Category:    CategoryTool,
		Description: "Go standard library net/http TLS 1.3 client with HTTP/2 ALPN.",
	},
	{
		ID:          "ja4-curl-openssl-h2",
		Type:        "ja4",
		Pattern:     "t13d3112h2_e8f1e7e78f70_4d7a28d6f226",
		Name:        "curl / OpenSSL 3.x (TLS 1.3 H2)",
		Category:    CategoryTool,
		Description: "curl linked against OpenSSL 3.x negotiating HTTP/2.",
	},
	{
		ID:          "ja4-python-urllib3",
		Type:        "ja4",
		Pattern:     "t13d311100_e8f1e7e78f70_b186095e22b6",
		Name:        "Python urllib3 / requests (OpenSSL 3.x)",
		Category:    CategoryTool,
		Description: "Python standard TLS client without ALPN.",
	},

	// Scanners, probes & C2 profiles (JA4)
	{
		ID:          "ja4-barebones-tls10-probe",
		Type:        "ja4",
		Pattern:     "t10i010000_000000000000_000000000000",
		Name:        "Barebones TLS 1.0 Probe",
		Category:    CategoryScanner,
		RiskScore:   50,
		Description: "Minimal TLS 1.0 direct-IP probe with no extensions.",
	},
	{
		ID:          "ja4-barebones-tls10-single",
		Type:        "ja4",
		Pattern:     "t10i010000_*",
		Name:        "Minimal TLS 1.0 Direct-IP Scanner",
		Category:    CategoryScanner,
		RiskScore:   40,
		Description: "Direct-IP TLS 1.0 handshake advertising a single cipher and zero extensions.",
	},
	{
		ID:          "ja4-ssl3-downgrade-probe",
		Type:        "ja4",
		Pattern:     "ts3*",
		Name:        "SSL 3.0 Legacy / POODLE Probe",
		Category:    CategorySuspicious,
		RiskScore:   40,
		Description: "Client attempting deprecated SSL 3.0 handshake.",
	},
	{
		ID:          "ja4-sliver-go-direct-ip",
		Type:        "ja4",
		Pattern:     "t13i190900_9dc949149365_*",
		Name:        "Go Direct-IP TLS 1.3 Implant / Sliver-like Profile",
		Category:    CategorySuspicious,
		RiskScore:   35,
		Description: "Go crypto/tls fingerprint connecting directly to an IP address without SNI or ALPN.",
	},
	{
		ID:          "ja4-cobaltstrike-java-default",
		Type:        "ja4",
		Pattern:     "t12i380800_7d94a0c3853e_9c7d972c4a82",
		Name:        "Cobalt Strike / Java JSSE Direct-IP Beacon",
		Category:    CategoryMalicious,
		RiskScore:   60,
		Description: "Java JSSE TLS 1.2 ClientHello targeting a bare IP without SNI.",
	},

	// Known ServerHello profiles (JA4S)
	{
		ID:          "ja4s-tls13-aes128gcm-std",
		Type:        "ja4s",
		Pattern:     "t130200_1301_a56c5b993250",
		Name:        "TLS 1.3 Server (AES-128-GCM, sv+ks)",
		Category:    CategoryBenign,
		Description: "Standard TLS 1.3 ServerHello selecting TLS_AES_128_GCM_SHA256.",
	},
	{
		ID:          "ja4s-tls13-aes256gcm-std",
		Type:        "ja4s",
		Pattern:     "t130200_1302_a56c5b993250",
		Name:        "TLS 1.3 Server (AES-256-GCM, sv+ks)",
		Category:    CategoryBenign,
		Description: "Standard TLS 1.3 ServerHello selecting TLS_AES_256_GCM_SHA384.",
	},
	{
		ID:          "ja4s-tls13-chacha20-std",
		Type:        "ja4s",
		Pattern:     "t130200_1303_a56c5b993250",
		Name:        "TLS 1.3 Server (ChaCha20-Poly1305, sv+ks)",
		Category:    CategoryBenign,
		Description: "Standard TLS 1.3 ServerHello selecting TLS_CHACHA20_POLY1305_SHA256.",
	},
	{
		ID:          "ja4s-tls13-boringssl-ks-sv",
		Type:        "ja4s",
		Pattern:     "t130200_1301_234ea6891581",
		Name:        "BoringSSL / Go TLS 1.3 Server (ks+sv)",
		Category:    CategoryBenign,
		Description: "TLS 1.3 ServerHello ordering key_share before supported_versions.",
	},
	{
		ID:          "ja4s-tls12-minimal-noext",
		Type:        "ja4s",
		Pattern:     "t120000_*_000000000000",
		Name:        "Minimal TLS 1.2 Server (No Extensions)",
		Category:    CategorySuspicious,
		RiskScore:   20,
		Description: "Legacy or custom TLS 1.2 listener returning zero ServerHello extensions.",
	},

	// Known X.509 certificate profiles (JA4X)
	{
		ID:          "ja4x-minimal-cn-only-noext",
		Type:        "ja4x",
		Pattern:     "7022c563de38_7022c563de38_000000000000",
		Name:        "Minimal CN-Only Certificate Without X.509v3 Extensions",
		Category:    CategorySuspicious,
		RiskScore:   30,
		Description: "Barebones certificate with only CommonName in issuer/subject and no v3 extensions (common in ad-hoc C2 listeners).",
	},
}
