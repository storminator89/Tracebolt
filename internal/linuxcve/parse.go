package linuxcve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"localrmm/internal/assessment"
	"localrmm/internal/linuxpackages"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,255}$`)
var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// Parse accepts a local, operator-supplied envelope, not a URL or fetch request.
// A syntactically valid subset is intentionally represented as imported records
// only. JSON truncation, duplicate keys, trailing bytes, oversized input, empty
// target scope, and invalid timestamps fail without creating a snapshot.
func Parse(ctx context.Context, r io.Reader, now time.Time) (*Snapshot, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCanceled
	}
	if r == nil || !validTime(now) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	data, err := readBounded(ctx, r, MaxBundleBytes)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, ErrInvalid
	}
	if err = validateJSON(ctx, data); err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(data, &members) != nil || len(members) != 4 {
		return nil, ErrInvalid
	}
	for _, key := range []string{"schemaVersion", "provider", "fetchedAt", "payload"} {
		if _, ok := members[key]; !ok {
			return nil, ErrInvalid
		}
	}
	var envelope struct {
		SchemaVersion string          `json:"schemaVersion"`
		Provider      string          `json:"provider"`
		FetchedAt     time.Time       `json:"fetchedAt"`
		Payload       json.RawMessage `json:"payload"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || envelope.SchemaVersion != BundleSchemaVersion || !validTime(envelope.FetchedAt) || envelope.FetchedAt.After(now) || len(envelope.Payload) == 0 {
		return nil, ErrInvalid
	}
	return parseSnapshot(ctx, envelope.Provider, envelope.Payload, envelope.FetchedAt, now)
}

// parseSnapshot receives JSON already checked for encoding, framing and duplicate keys.
func parseSnapshot(ctx context.Context, provider string, payload []byte, fetchedAt, now time.Time) (*Snapshot, error) {
	s := &Snapshot{metadata: FeedMetadata{Provider: provider, FetchedAt: fetchedAt.UTC(), ValidatedAt: now.UTC(), ExpiresAt: fetchedAt.Add(FeedTTL).UTC(), Trust: "operator_imported_unverified", Coverage: "imported_records_only"}, rules: make(map[string][]rule)}
	var err error
	if !validTime(s.metadata.ExpiresAt) {
		return nil, ErrInvalid
	}
	switch provider {
	case DebianProvider:
		s.metadata.Target = linuxpackages.Debian13
		s.metadata.SourceURL = "https://security-tracker.debian.org/tracker/data/json"
		s.metadata.License = "not_verified"
		err = parseDebian(ctx, payload, s)
	case UbuntuProvider:
		s.metadata.Target = linuxpackages.Ubuntu2404
		s.metadata.SourceURL = "https://security-metadata.canonical.com/osv/"
		s.metadata.License = "CC-BY-SA-4.0"
		err = parseUbuntu(ctx, payload, s, fetchedAt)
	default:
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	if s.metadata.RecordCount == 0 || len(s.rules) == 0 {
		return nil, invalidAt(invalidTargetScope, s.metadata.RecordCount, 0)
	}
	for name, rules := range s.rules {
		sort.Slice(rules, func(i, j int) bool { return rules[i].cve < rules[j].cve })
		s.rules[name] = rules
	}
	h := sha256.Sum256(payload)
	s.metadata.SHA256 = hex.EncodeToString(h[:])
	s.metadata.SourceCount = len(s.rules)
	s.metadata.Freshness = freshness(s.metadata.FetchedAt, s.metadata.ExpiresAt, now)
	s.valid = true
	return s, nil
}

// ParseOfficialDebian is exclusively for an ingestion adapter which obtained
// the entire body from the fixed SourceURL over verified HTTPS, or restored that
// adapter's protected cache. The JSON bundle importer cannot grant this trust.
// It proves transport origin only, never a signature or package provenance.
func ParseOfficialDebian(ctx context.Context, r io.Reader, fetchedAt, now time.Time) (*Snapshot, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCanceled
	}
	if r == nil || !validTime(fetchedAt) || !validTime(fetchedAt.UTC()) || !validTime(now) || fetchedAt.UTC().After(now) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := readBounded(ctx, r, officialPayloadLimit(fetchedAt))
	if err != nil {
		return nil, err
	}
	return ParseOfficialDebianBytes(ctx, raw, fetchedAt, now)
}

// ParseOfficialDebianBytes avoids copying an already bounded HTTP/cache body
// into a second envelope. Its contract and trust are identical to the reader
// entry point; the returned immutable snapshot retains no caller-owned bytes.
func ParseOfficialDebianBytes(ctx context.Context, raw []byte, fetchedAt, now time.Time) (*Snapshot, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCanceled
	}
	if !validTime(fetchedAt) || !validTime(fetchedAt.UTC()) || !validTime(now) || fetchedAt.UTC().After(now) {
		return nil, ErrInvalid
	}
	if int64(len(raw)) > officialPayloadLimit(fetchedAt) {
		return nil, ErrLimit
	}
	if !utf8.Valid(raw) {
		return nil, invalidAt(invalidJSONUTF8, 0, 0)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Preserve the former envelope's depth and four fixed header values in the
	// token budget; the optimization must not broaden structural admission.
	if err := validateJSONAt(ctx, raw, 1, 4); err != nil {
		return nil, err
	}
	// Validate before trimming. Non-JSON Unicode whitespace must not be repaired.
	// This matches RawMessage payload hashing, preserving existing cache hashes.
	payload := bytes.Trim(raw, " \t\r\n")
	s, err := parseSnapshot(ctx, DebianProvider, payload, fetchedAt.UTC(), now)
	if err != nil {
		return nil, err
	}
	s.metadata.Trust = "https_origin_only"
	s.metadata.Coverage = "official_feed_records"
	return s, nil
}

func officialPayloadLimit(fetchedAt time.Time) int64 {
	// Preserve the former reader entry point's exact byte budget without ever
	// building its feed-sized envelope. Both callers validate the time first.
	at, _ := json.Marshal(fetchedAt.UTC())
	prefix := `{"schemaVersion":"` + BundleSchemaVersion + `","provider":"` + DebianProvider + `","fetchedAt":`
	return MaxOfficialJSONBytes - int64(len(prefix)+len(at)+len(`,"payload":`)+1)
}

func readBounded(ctx context.Context, r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, r}, limit+1))
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	if err != nil {
		return nil, ErrInvalid
	}
	if int64(len(data)) > limit {
		return nil, ErrLimit
	}
	return data, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, ErrCanceled
	}
	return r.r.Read(p)
}

// Token traversal rejects duplicate keys at every nesting level, including
// ignored provider fields. Unknown provider fields are harmless and preserved
// only by the digest; an unknown envelope member is rejected separately.
func validateJSON(ctx context.Context, data []byte) error {
	return validateJSONAt(ctx, data, 0, 0)
}

func validateJSONAt(ctx context.Context, data []byte, startDepth, initialCount int) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	count := initialCount
	var walk func(int) error
	walk = func(depth int) error {
		count++
		if ctx.Err() != nil {
			return ErrCanceled
		}
		if depth > 32 || count > 16000000 {
			return ErrLimit
		}
		t, err := d.Token()
		if err != nil {
			return invalidAt(invalidJSONToken, count, depth)
		}
		if str, ok := t.(string); ok && len(str) > 1<<20 {
			return ErrLimit
		}
		delimiter, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return invalidAt(invalidJSONKey, count, depth)
				}
				k, ok := key.(string)
				if !ok || len(k) > 512 {
					return invalidAt(invalidJSONKey, count, depth)
				}
				if _, exists := seen[strings.ToLower(k)]; exists {
					return invalidAt(invalidJSONDuplicate, count, depth)
				}
				seen[strings.ToLower(k)] = struct{}{}
				if len(seen) > MaxRecords {
					return ErrLimit
				}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			t, err = d.Token()
			if err != nil || t != json.Delim('}') {
				return invalidAt(invalidJSONClose, count, depth)
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			t, err = d.Token()
			if err != nil || t != json.Delim(']') {
				return invalidAt(invalidJSONClose, count, depth)
			}
		default:
			return invalidAt(invalidJSONClose, count, depth)
		}
		return nil
	}
	if err := walk(startDepth); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return invalidAt(invalidJSONTrailing, count, startDepth)
	}
	return nil
}

func parseDebian(ctx context.Context, raw []byte, s *Snapshot) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return invalidAt(invalidDebianRoot, 0, 0)
	}
	total := 0
	for d.More() {
		if ctx.Err() != nil {
			return ErrCanceled
		}
		t, err = d.Token()
		name, ok := t.(string)
		if err != nil || !ok || !packagePattern.MatchString(name) {
			return invalidAt(invalidDebianSourceName, total, 0)
		}
		var records map[string]json.RawMessage
		if d.Decode(&records) != nil {
			return invalidAt(invalidDebianSourceRecords, total, 0)
		}
		if len(records) == 0 {
			return invalidAt(invalidDebianEmptySource, total, 0)
		}
		for id, record := range records {
			total++
			if total > MaxRecords {
				return ErrLimit
			}
			if ctx.Err() != nil {
				return ErrCanceled
			}
			var issue struct {
				Releases map[string]json.RawMessage `json:"releases"`
			}
			if json.Unmarshal(record, &issue) != nil {
				return invalidAt(invalidDebianIssue, total, 0)
			}
			if issue.Releases == nil {
				return invalidAt(invalidDebianReleases, total, 0)
			}
			if !cvePattern.MatchString(id) {
				continue
			}
			release, found := issue.Releases["trixie"]
			if !found {
				continue
			}
			var v struct {
				Status string `json:"status"`
				Fixed  string `json:"fixed_version"`
			}
			if json.Unmarshal(release, &v) != nil {
				return invalidAt(invalidDebianRelease, total, 0)
			}
			if v.Status == "" {
				return invalidAt(invalidDebianStatus, total, 0)
			}
			rule := rule{cve: id, advisoryURL: "https://security-tracker.debian.org/tracker/" + id}
			if v.Fixed != "" && !assessment.ValidDebianVersion(v.Fixed) {
				return invalidAt(invalidDebianFixedVersion, total, 0)
			}
			switch {
			case v.Status == "resolved" && v.Fixed == "0":
				rule.reason = "vendor_not_affected"
			case v.Status == "resolved" && v.Fixed != "":
				rule.fixed = v.Fixed
			case v.Status == "open" && v.Fixed == "":
				rule.reason = "published_fix_unavailable"
			case v.Status == "undetermined":
				rule.reason = "vendor_status_undetermined"
			default:
				rule.reason = "vendor_record_uninterpretable"
			}
			s.rules[name] = append(s.rules[name], rule)
			s.metadata.RecordCount++
		}
	}
	if _, err := d.Token(); err != nil {
		return ErrInvalid
	}
	return nil
}

type osvRecord struct {
	ID        string        `json:"id"`
	Modified  time.Time     `json:"modified"`
	Published *time.Time    `json:"published"`
	Withdrawn *time.Time    `json:"withdrawn"`
	Affected  []osvAffected `json:"affected"`
}
type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
}

func parseUbuntu(ctx context.Context, raw []byte, s *Snapshot, fetchedAt time.Time) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('[') {
		return ErrInvalid
	}
	records := 0
	ids := map[string]bool{}
	for d.More() {
		if ctx.Err() != nil {
			return ErrCanceled
		}
		records++
		if records > MaxRecords {
			return ErrLimit
		}
		var v osvRecord
		if d.Decode(&v) != nil || v.ID == "" || len(v.ID) > 128 || !validTime(v.Modified) || v.Modified.After(fetchedAt) {
			return ErrInvalid
		}
		if ids[v.ID] {
			return ErrInvalid
		}
		ids[v.ID] = true
		if v.Published != nil && (!validTime(*v.Published) || v.Published.After(v.Modified)) {
			return ErrInvalid
		}
		if v.Withdrawn != nil && (!validTime(*v.Withdrawn) || v.Withdrawn.After(fetchedAt)) {
			return ErrInvalid
		}
		// USNs can reference multiple CVEs without an exact per-CVE version mapping;
		// LSNs describe livepatch. Neither is interpreted as source-package CVE data.
		cve := strings.TrimPrefix(v.ID, "UBUNTU-")
		if !strings.HasPrefix(v.ID, "UBUNTU-") || !cvePattern.MatchString(cve) || v.Withdrawn != nil {
			continue
		}
		if v.Affected == nil {
			return ErrInvalid
		}
		seenSources := map[string]bool{}
		for _, affected := range v.Affected {
			if !packagePattern.MatchString(affected.Package.Name) || affected.Package.Ecosystem == "" {
				return ErrInvalid
			}
			if affected.Package.Ecosystem != "Ubuntu:24.04:LTS" {
				continue
			}
			name := affected.Package.Name
			if seenSources[name] {
				return ErrInvalid
			}
			seenSources[name] = true
			if affected.Package.PURL != "" && !sourcePURL(affected.Package.PURL, name) {
				return ErrInvalid
			}
			rule := rule{cve: cve, advisoryURL: "https://ubuntu.com/security/" + cve}
			if len(affected.Ranges) == 0 {
				rule.reason = "published_fix_unavailable"
			}
			if len(affected.Ranges) > 16 {
				return ErrLimit
			}
			for _, rg := range affected.Ranges {
				if rg.Type != "ECOSYSTEM" {
					rule.reason = "vendor_range_unsupported"
					continue
				}
				if len(rg.Events) == 0 || len(rg.Events) > 32 {
					return ErrInvalid
				}
				introduced := ""
				for _, event := range rg.Events {
					if len(event) != 1 {
						return ErrInvalid
					}
					if start, ok := event["introduced"]; ok {
						if introduced != "" || !assessment.ValidDebianVersion(start) {
							return ErrInvalid
						}
						introduced = start
					} else if fixed, ok := event["fixed"]; ok {
						if introduced == "" || fixed == "0" || !assessment.ValidDebianVersion(fixed) {
							return ErrInvalid
						}
						rule.intervals = append(rule.intervals, interval{introduced, fixed})
						introduced = ""
					} else {
						// last_affected/limit cannot establish a published distribution fix.
						rule.reason = "vendor_range_unsupported"
					}
				}
				if introduced != "" {
					rule.reason = "published_fix_unavailable"
				}
			}
			// A mixed unsupported/open record is conservatively not evaluated, rather
			// than pretending its known fixed range covers every possible version.
			if len(rule.intervals) == 0 && rule.reason == "" {
				rule.reason = "published_fix_unavailable"
			}
			s.rules[name] = append(s.rules[name], rule)
			s.metadata.RecordCount++
			if s.metadata.RecordCount > MaxRecords {
				return ErrLimit
			}
		}
	}
	if _, err := d.Token(); err != nil {
		return ErrInvalid
	}
	return nil
}

func sourcePURL(purl, name string) bool {
	if len(purl) > 2048 || !strings.HasPrefix(purl, "pkg:deb/ubuntu/"+name+"@") {
		return false
	}
	u, err := url.Parse(purl)
	if err != nil || u.Fragment != "" {
		return false
	}
	q, err := url.ParseQuery(u.RawQuery)
	return err == nil && len(q["arch"]) == 1 && q.Get("arch") == "source" && len(q["distro"]) == 1 && q.Get("distro") == "noble"
}

func validTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 }
func freshness(at, expires, now time.Time) string {
	if !validTime(now) || !validTime(at) || !validTime(expires) || at.After(now) || !expires.After(at) {
		return "unknown"
	}
	if !now.Before(expires) {
		return "stale"
	}
	return "fresh"
}
func InventoryFreshness(at, now time.Time) string { return freshness(at, at.Add(InventoryTTL), now) }
