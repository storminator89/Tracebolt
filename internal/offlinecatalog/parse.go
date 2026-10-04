package offlinecatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"localrmm/internal/assessment"
)

// Parse copies and validates bounded, normalized JSON. It performs no network,
// filesystem, comparator, signature-verification, or package-manager operation.
// Callers must not mutate raw concurrently with Parse; after return raw is never
// retained and may be overwritten. now must come from the server, not the file.
func Parse(ctx context.Context, raw []byte, now time.Time) (Candidate, error) {
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	if len(raw) > MaxBytes {
		return Candidate{}, ErrTooLarge
	}
	data := bytes.Clone(raw)
	root, err := readRoot(ctx, data)
	if err != nil {
		return Candidate{}, err
	}
	syntheticRaw := bytes.TrimSpace(root["synthetic"])
	if !bytes.Equal(syntheticRaw, []byte("true")) && !bytes.Equal(syntheticRaw, []byte("false")) {
		return Candidate{}, ErrInvalid
	}
	synthetic := bytes.Equal(syntheticRaw, []byte("true"))
	for _, key := range []string{"coveredSources", "rules"} {
		value := bytes.TrimSpace(root[key])
		if len(value) == 0 || value[0] != '[' {
			return Candidate{}, ErrInvalid
		}
	}
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	id := newID("catalog_")
	// The foundation parser requires synthetic_fixture for synthetic input.
	// This is a validation-only marker, NOT vendor provenance. The resulting
	// provenance-bearing snapshot is discarded and is never exposed or matched.
	trust := "unverified"
	if synthetic {
		trust = "synthetic_fixture"
	}
	_, err = assessment.ParseDebianSnapshot(bytes.NewReader(data), assessment.SourceSnapshot{
		ID: id, Provider: "debian-security-tracker", Kind: "advisory", SHA256: digest,
		Trust: trust, Synthetic: synthetic,
		// Publication/fetch/expiry/validation times and URL deliberately absent.
	})
	if canceled := ctx.Err(); canceled != nil {
		return Candidate{}, canceled
	}
	if err != nil {
		if errors.Is(err, assessment.ErrSnapshotLimit) {
			return Candidate{}, ErrTooLarge
		}
		return Candidate{}, ErrInvalid
	}
	// The existing parser has already enforced known fields, duplicate keys,
	// UTF-8, nesting/string/array bounds, and normalized record identities.
	// Decode a private typed document for explicit null/type/release checks and
	// aggregate metadata; no accessor to its mutable slices exists.
	var document normalizedDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return Candidate{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	for _, rule := range document.Rules {
		if err := ctx.Err(); err != nil {
			return Candidate{}, err
		}
		if rule.Release != "trixie" {
			return Candidate{}, ErrUnsupportedRelease
		}
	}
	if err := ctx.Err(); err != nil {
		return Candidate{}, err
	}
	return Candidate{data: &candidateData{document: document, metadata: Metadata{
		ID: id, SHA256: digest, Format: assessment.DebianSnapshotSchema,
		Provider: "debian-security-tracker", DeclaredRelease: "trixie",
		ImportedAt: now.UTC(), PublishedAt: nil, Freshness: "unknown",
		OriginAssurance: "unverified", Synthetic: synthetic, ByteCount: len(data),
		RuleCount: len(document.Rules), CoveredSourceCount: len(document.CoveredSources),
	}}}, nil
}

// readRoot rejects missing, extra and duplicate root keys before typed decoding.
// Each value remains raw here; deeply nested or oversized structure is rejected
// by the fixed foundation parser before any full typed document is allocated.
func readRoot(ctx context.Context, data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalid
	}
	root := make(map[string]json.RawMessage, 4)
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		token, err = decoder.Token()
		if err != nil {
			return nil, ErrInvalid
		}
		key, ok := token.(string)
		if !ok || (key != "schema" && key != "synthetic" && key != "coveredSources" && key != "rules") {
			return nil, ErrInvalid
		}
		if _, duplicate := root[key]; duplicate {
			return nil, ErrInvalid
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, ErrInvalid
		}
		root[key] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(root) != 4 {
		return nil, ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return root, nil
}

type normalizedDocument struct {
	Schema         strictString     `json:"schema"`
	Synthetic      bool             `json:"synthetic"`
	CoveredSources strictStrings    `json:"coveredSources"`
	Rules          []normalizedRule `json:"rules"`
}

type normalizedRule struct {
	SourcePackage   strictString   `json:"sourcePackage"`
	AdvisoryID      strictString   `json:"advisoryId"`
	Release         strictString   `json:"release"`
	Status          strictString   `json:"status"`
	FixedVersion    strictString   `json:"fixedVersion"`
	Qualifications  strictStrings  `json:"qualifications"`
	ArchiveVersions strictArchives `json:"archiveVersions"`
}

type normalizedArchive struct {
	Repository strictString `json:"repository"`
	Version    strictString `json:"version"`
}

// encoding/json normally accepts null for string/bool values and slices. Null
// must not silently become a valid zero value at this upload boundary.
type strictString string

func (s *strictString) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return ErrInvalid
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ErrInvalid
	}
	*s = strictString(value)
	return nil
}

type strictStrings []strictString

func (s *strictStrings) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return ErrInvalid
	}
	var value []strictString
	if err := json.Unmarshal(raw, &value); err != nil {
		return ErrInvalid
	}
	*s = value
	return nil
}

type strictArchives []normalizedArchive

func (s *strictArchives) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return ErrInvalid
	}
	var value []normalizedArchive
	if err := json.Unmarshal(raw, &value); err != nil {
		return ErrInvalid
	}
	*s = value
	return nil
}
