package assessment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	DebianSnapshotSchema = "debian-tracker-normalized-1"
	MaxSnapshotBytes     = 2 << 20
	MaxSnapshotRules     = 10000
)

var ErrSnapshotInvalid = errors.New("advisory_snapshot_invalid")
var ErrSnapshotLimit = errors.New("advisory_snapshot_limit_exceeded")
var safeToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,127}$`)
var allowedJSONKeys = map[string]bool{"schema": true, "synthetic": true, "coveredSources": true, "rules": true, "sourcePackage": true, "advisoryId": true, "release": true, "status": true, "fixedVersion": true, "qualifications": true, "archiveVersions": true, "repository": true, "version": true}
var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

type ArchiveVersion struct {
	Repository string `json:"repository"`
	Version    string `json:"version"`
}
type DebianRule struct {
	SourcePackage  string   `json:"sourcePackage"`
	AdvisoryID     string   `json:"advisoryId"`
	Release        string   `json:"release"`
	Status         string   `json:"status"`
	FixedVersion   string   `json:"fixedVersion"`
	Qualifications []string `json:"qualifications"`
	// ArchiveVersions describe the vendor archive, NEVER the installed endpoint.
	ArchiveVersions []ArchiveVersion `json:"archiveVersions"`
}
type debianDocument struct {
	Schema         string       `json:"schema"`
	Synthetic      bool         `json:"synthetic"`
	CoveredSources []string     `json:"coveredSources"`
	Rules          []DebianRule `json:"rules"`
}

// DebianSnapshot is immutable after strict parsing. This first adapter consumes
// a small normalized interchange format, NOT the live tracker export or OVAL.
// A future official-feed importer must explicitly prove its schema/coverage.
type DebianSnapshot struct {
	source   SourceSnapshot
	document debianDocument
}

func (s *DebianSnapshot) Source() SourceSnapshot {
	if s == nil {
		return SourceSnapshot{}
	}
	return s.source
}

// ParseDebianSnapshot verifies a caller-pinned digest and strict bounded shape.
// It does not fetch data, verify signatures, confer feed redistribution rights,
// or turn a JSON declaration into authenticity. Provenance is an adapter input.
func ParseDebianSnapshot(r io.Reader, provenance SourceSnapshot) (*DebianSnapshot, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSnapshotBytes+1))
	if err != nil {
		return nil, ErrSnapshotInvalid
	}
	if len(data) > MaxSnapshotBytes {
		return nil, ErrSnapshotLimit
	}
	if !utf8.Valid(data) {
		return nil, ErrSnapshotInvalid
	}
	if err := validateJSONShape(data); err != nil {
		return nil, err
	}
	var document debianDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrSnapshotInvalid
	}
	hash := sha256.Sum256(data)
	if provenance.SHA256 != hex.EncodeToString(hash[:]) || provenance.Kind != "advisory" || !safeToken.MatchString(provenance.ID) || len(provenance.Revision) > 128 || provenance.Provider != "debian-security-tracker" || provenance.Synthetic != document.Synthetic {
		return nil, ErrSnapshotInvalid
	}
	if !oneOf(provenance.Trust, "unverified", "local", "https_origin_only", "vendor_signature_verified", "synthetic_fixture") {
		return nil, ErrSnapshotInvalid
	}
	if provenance.Synthetic != (provenance.Trust == "synthetic_fixture") {
		return nil, ErrSnapshotInvalid
	}
	if provenance.PublicURL != "" && provenance.PublicURL != "https://security-tracker.debian.org/tracker/data/json" {
		return nil, ErrSnapshotInvalid
	}
	if document.Schema != DebianSnapshotSchema || len(document.Rules) > MaxSnapshotRules || len(document.CoveredSources) > MaxSnapshotRules || len(document.CoveredSources) == 0 || document.Rules == nil {
		return nil, ErrSnapshotInvalid
	}
	covered := map[string]bool{}
	for _, name := range document.CoveredSources {
		if !packageName.MatchString(name) || covered[name] {
			return nil, ErrSnapshotInvalid
		}
		covered[name] = true
	}
	identities := map[string]bool{}
	for _, rule := range document.Rules {
		if !covered[rule.SourcePackage] || !packageName.MatchString(rule.SourcePackage) || !safeToken.MatchString(rule.AdvisoryID) || !safeToken.MatchString(rule.Release) || !safeToken.MatchString(rule.Status) || len(rule.FixedVersion) > maxIdentityLength || len(rule.Qualifications) > 16 || len(rule.ArchiveVersions) > 32 {
			return nil, ErrSnapshotInvalid
		}
		if rule.FixedVersion != "" && !ValidDebianVersion(rule.FixedVersion) {
			return nil, ErrSnapshotInvalid
		}
		identity := rule.SourcePackage + "\x00" + rule.AdvisoryID + "\x00" + rule.Release
		if identities[identity] {
			return nil, ErrSnapshotInvalid
		}
		identities[identity] = true
		for _, q := range rule.Qualifications {
			if !safeToken.MatchString(q) {
				return nil, ErrSnapshotInvalid
			}
		}
		archives := map[string]bool{}
		for _, archive := range rule.ArchiveVersions {
			if !safeToken.MatchString(archive.Repository) || !ValidDebianVersion(archive.Version) || archives[archive.Repository] {
				return nil, ErrSnapshotInvalid
			}
			archives[archive.Repository] = true
		}
	}
	return &DebianSnapshot{source: provenance, document: document}, nil
}
func validateJSONShape(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	nodes := 0
	var value func(int) error
	value = func(depth int) error {
		nodes++
		if depth > 16 || nodes > 250000 {
			return ErrSnapshotLimit
		}
		token, err := decoder.Token()
		if err != nil {
			return ErrSnapshotInvalid
		}
		switch token := token.(type) {
		case string:
			if len(token) > maxIdentityLength || strings.ContainsAny(token, "\x00\r\n") {
				return ErrSnapshotInvalid
			}
		case json.Delim:
			switch token {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					keyToken, err := decoder.Token()
					if err != nil {
						return ErrSnapshotInvalid
					}
					key, ok := keyToken.(string)
					if !ok || !allowedJSONKeys[key] || len(key) > 128 || seen[key] || len(seen) >= 256 {
						return ErrSnapshotInvalid
					}
					seen[key] = true
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim('}') {
					return ErrSnapshotInvalid
				}
			case '[':
				n := 0
				for decoder.More() {
					n++
					if n > MaxSnapshotRules {
						return ErrSnapshotLimit
					}
					if err := value(depth + 1); err != nil {
						return err
					}
				}
				end, err := decoder.Token()
				if err != nil || end != json.Delim(']') {
					return ErrSnapshotInvalid
				}
			default:
				return ErrSnapshotInvalid
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrSnapshotInvalid
	}
	return nil
}
