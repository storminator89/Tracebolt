// Package journalpolicy is the pure access policy for a future fixed-purpose
// local journal helper. It does not establish file ownership, peer credentials,
// enrollment authority, or permission to install/run a helper.
package journalpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalview"
)

const Version = "tracebolt.journal-content-policy.v1"
const VersionV2 = "tracebolt.journal-content-policy.v2"
const VersionV3 = "tracebolt.journal-content-policy.v3"
const VersionV4 = "tracebolt.journal-content-policy.v4"
const ScopeV4 = "on-demand-retained-system-service-log-content"
const Scope = "on-demand-allowlisted-system-service-log-content"
const ScopeV3 = "on-demand-system-service-log-content"
const CollectionProfile = "managed-operations-v3"
const MaxPolicyBytes = 8 << 10
const MaxUnits = 32

// ServiceAuthorization is required in v3. Legacy policies always authorize
// only their explicit exact-unit allowlist and cannot carry this field.
type ServiceAuthorization string

const ExactUnits ServiceAuthorization = "exact-units"
const AllSystemServices ServiceAuthorization = "all-system-services"

// IsGenerationPolicy enumerates the supported generation-bound versions.
// An unknown future schema must never inherit generation authority implicitly.
func IsGenerationPolicy(version string) bool {
	return version == VersionV2 || version == VersionV3 || version == VersionV4
}

var ErrPolicy = errors.New("journal content policy is invalid")
var ErrDenied = errors.New("journal content request is not authorized")
var ErrChanged = errors.New("journal content policy changed before delivery")

// Policy is an explicit local administrator declaration. A future loader must
// obtain it from a protected root-owned file, never from manager input. The
// separate helper account must not share the main agent's UID.
type Policy struct {
	SchemaVersion         string               `json:"schemaVersion"`
	Revision              uint64               `json:"revision,string,omitempty"`
	Generation            string               `json:"generation,omitempty"`
	Scope                 string               `json:"scope"`
	BrowsingContract      string               `json:"browsingContract,omitempty"`
	ServiceAuthorization  ServiceAuthorization `json:"serviceAuthorization,omitempty"`
	CollectionProfile     string               `json:"collectionProfile"`
	SenderBinding         string               `json:"senderBinding"`
	ManagerOrigin         string               `json:"managerOrigin"`
	TransportProfile      string               `json:"transportProfile"`
	AgentUID              uint32               `json:"agentUid"`
	HelperUID             uint32               `json:"helperUid"`
	AllowedUnits          []string             `json:"allowedUnits"`
	MaxWindowSeconds      uint32               `json:"maxWindowSeconds"`
	MaxLookbackSeconds    uint32               `json:"maxLookbackSeconds"`
	MaxPriority           int                  `json:"maxPriority"`
	Enabled               bool                 `json:"enabled"`
	ContentAcknowledged   bool                 `json:"contentAcknowledged"`
	PlaintextAcknowledged bool                 `json:"plaintextAcknowledged"`
}

// Context contains facts obtained independently by the future local adapter.
// PeerUID must come from Unix SO_PEERCRED. Other values must come from the
// currently validated enrollment and dedicated-helper identity, never request
// JSON. This struct alone is not proof that the facts are authoritative.
type Context struct {
	SenderBinding     string
	ManagerOrigin     string
	TransportProfile  string
	CollectionProfile string
	AgentUID          uint32
	HelperUID         uint32
	PeerUID           uint32
}

func validUID(id uint32) bool { return id != 0 && id != ^uint32(0) }
func validBinding(s string) bool {
	if len(s) != 64 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s && strings.Trim(s, "0") != ""
}

// Origin is display/binding metadata, never a destination used by this package.
// It must additionally equal the exact origin from the current trusted context.
func validOrigin(raw, profile string) bool {
	if len(raw) == 0 || len(raw) > 512 || strings.ContainsAny(raw, "\\%\r\n\t ") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Host != strings.ToLower(u.Host) || raw != u.Scheme+"://"+u.Host {
		return false
	}
	return profile == "tls" && u.Scheme == "https" || profile == "http-test" && u.Scheme == "http"
}

func Validate(p Policy) error {
	if p.SchemaVersion != Version && !IsGenerationPolicy(p.SchemaVersion) || p.SchemaVersion == Version && (p.Revision != 0 || p.Generation != "") || IsGenerationPolicy(p.SchemaVersion) && (p.Revision == 0 || !journalgeneration.ValidGeneration(p.Generation)) || p.CollectionProfile != CollectionProfile || !validBinding(p.SenderBinding) || !validOrigin(p.ManagerOrigin, p.TransportProfile) || !validUID(p.AgentUID) || !validUID(p.HelperUID) || p.AgentUID == p.HelperUID || !validRangePolicy(p) || p.MaxPriority < 0 || p.MaxPriority > 7 || !p.ContentAcknowledged || p.TransportProfile == "http-test" && !p.PlaintextAcknowledged || p.TransportProfile == "tls" && p.PlaintextAcknowledged {
		return ErrPolicy
	}
	if p.SchemaVersion == VersionV3 || p.SchemaVersion == VersionV4 {
		if (p.SchemaVersion == VersionV3 && p.Scope != ScopeV3 || p.SchemaVersion == VersionV4 && p.Scope != ScopeV4) || p.ServiceAuthorization != ExactUnits && p.ServiceAuthorization != AllSystemServices {
			return ErrPolicy
		}
	} else if p.Scope != Scope || p.ServiceAuthorization != "" {
		return ErrPolicy
	}
	if p.ServiceAuthorization == AllSystemServices {
		// An explicit [] is mandatory. No wildcard, omitted/null allowlist, or
		// legacy empty allowlist can be interpreted as broad authorization.
		if p.AllowedUnits == nil || len(p.AllowedUnits) != 0 {
			return ErrPolicy
		}
	} else if len(p.AllowedUnits) == 0 || len(p.AllowedUnits) > MaxUnits {
		return ErrPolicy
	}
	// Reuse the reader's exact unit grammar; do not create a second permissive
	// interpretation of service names. Only the unit varies in this pure check.
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	for i, unit := range p.AllowedUnits {
		if i > 0 && p.AllowedUnits[i-1] >= unit {
			return ErrPolicy
		}
		if journalview.ValidateQuery(journalview.Query{Unit: unit, Start: now.Add(-time.Minute), End: now, MaxPriority: p.MaxPriority}, now) != nil {
			return ErrPolicy
		}
	}
	return nil
}

func Encode(p Policy) ([]byte, error) {
	if Validate(p) != nil {
		return nil, ErrPolicy
	}
	b, err := json.Marshal(p)
	if err != nil || len(b) > MaxPolicyBytes {
		return nil, ErrPolicy
	}
	return b, nil
}

// Decode requires every member and rejects unknown, duplicate, null, wrongly
// typed and oversized values. No root policy is inferred from an empty file.
func Decode(raw []byte) (Policy, error) {
	bad := func() (Policy, error) { return Policy{}, ErrPolicy }
	if len(raw) == 0 || len(raw) > MaxPolicyBytes || !utf8.Valid(raw) {
		return bad()
	}
	fields := map[string]string{"schemaVersion": "s", "scope": "s", "browsingContract": "s", "serviceAuthorization": "s", "collectionProfile": "s", "senderBinding": "s", "managerOrigin": "s", "transportProfile": "s", "agentUid": "n", "helperUid": "n", "allowedUnits": "a", "maxWindowSeconds": "n", "maxLookbackSeconds": "n", "maxPriority": "n", "enabled": "b", "contentAcknowledged": "b", "plaintextAcknowledged": "b", "revision": "r", "generation": "s"}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return bad()
	}
	seen := map[string]bool{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return bad()
		}
		key, ok := t.(string)
		kind, known := fields[key]
		if !ok || !known || seen[key] {
			return bad()
		}
		seen[key] = true
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return bad()
		}
		v = bytes.TrimSpace(v)
		if len(v) == 0 || bytes.Equal(v, []byte("null")) {
			return bad()
		}
		switch kind {
		case "r":
			var revision string
			if json.Unmarshal(v, &revision) != nil || len(revision) == 0 || len(revision) > 20 || revision[0] < '1' || revision[0] > '9' || !bytes.Equal(v, []byte(`"`+revision+`"`)) {
				return bad()
			}
			for _, c := range revision {
				if c < '0' || c > '9' {
					return bad()
				}
			}
		case "s":
			if v[0] != '"' {
				return bad()
			}
		case "b":
			if !bytes.Equal(v, []byte("true")) && !bytes.Equal(v, []byte("false")) {
				return bad()
			}
		case "a":
			if v[0] != '[' {
				return bad()
			}
		case "n":
			if len(v) > 10 || len(v) > 1 && v[0] == '0' {
				return bad()
			}
			for _, c := range v {
				if c < '0' || c > '9' {
					return bad()
				}
			}
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') {
		return bad()
	}
	if _, err = d.Token(); err != io.EOF {
		return bad()
	}
	var p Policy
	if json.Unmarshal(raw, &p) != nil || Validate(p) != nil {
		return bad()
	}
	for key := range fields {
		if key == "revision" || key == "generation" {
			if seen[key] != IsGenerationPolicy(p.SchemaVersion) {
				return bad()
			}
		} else if key == "serviceAuthorization" {
			if seen[key] != (p.SchemaVersion == VersionV3 || p.SchemaVersion == VersionV4) {
				return bad()
			}
		} else if key == "browsingContract" {
			if seen[key] != (p.SchemaVersion == VersionV4) {
				return bad()
			}
		} else if !seen[key] {
			return bad()
		}
	}
	return p, nil
}

// Permit is a detached, content-free authorization for one exact query. It is
// not a reusable lease: current policy/context must be checked before capture
// and again before releasing any content. It does not authorize remote routing.
type Permit struct {
	query      journalview.Query
	policyHash [32]byte
	generation journalgeneration.Tuple
}

func (p Permit) Query() journalview.Query { return p.query }
func (p Permit) PolicyDigest() string     { return "sha256:" + hex.EncodeToString(p.policyHash[:]) }

// PolicyGeneration computes the full canonical policy binding. Legacy v1 has
// no generation and returns zero; callers must not treat zero as v2/v3 permission.
func PolicyGeneration(p Policy) (journalgeneration.Tuple, error) {
	raw, err := Encode(p)
	if err != nil {
		return journalgeneration.Tuple{}, ErrPolicy
	}
	if p.SchemaVersion == Version {
		return journalgeneration.Tuple{}, nil
	}
	hash := sha256.Sum256(raw)
	return journalgeneration.Tuple{Revision: p.Revision, Generation: p.Generation, PolicyDigest: "sha256:" + hex.EncodeToString(hash[:])}, nil
}

func (p Permit) Generation() journalgeneration.Tuple { return p.generation }

// Authorize preserves the legacy v1-only boundary. A v2/v3 caller must supply its
// exact current generation through AuthorizeBound rather than silently upgrade.
func Authorize(p Policy, c Context, q journalview.Query, now time.Time) (Permit, error) {
	return AuthorizeBound(p, c, q, journalgeneration.Tuple{}, now)
}

func AuthorizeBound(p Policy, c Context, q journalview.Query, generation journalgeneration.Tuple, now time.Time) (Permit, error) {
	expected, err := PolicyGeneration(p)
	if err != nil || expected != generation {
		return Permit{}, ErrDenied
	}
	if Validate(p) != nil || !p.Enabled || c.SenderBinding != p.SenderBinding || c.ManagerOrigin != p.ManagerOrigin || c.TransportProfile != p.TransportProfile || c.CollectionProfile != p.CollectionProfile || c.AgentUID != p.AgentUID || c.HelperUID != p.HelperUID || c.PeerUID != p.AgentUID || journalview.ValidateQuery(q, now) != nil || p.ServiceAuthorization != AllSystemServices && !slices.Contains(p.AllowedUnits, q.Unit) || !rangeAuthorized(p, q, now) || q.MaxPriority > p.MaxPriority {
		return Permit{}, ErrDenied
	}
	raw, err := Encode(p)
	if err != nil {
		return Permit{}, ErrDenied
	}
	return Permit{query: q, policyHash: sha256.Sum256(raw), generation: generation}, nil
}

func (p Permit) Recheck(current Policy, c Context, now time.Time) error {
	next, err := AuthorizeBound(current, c, p.query, p.generation, now)
	if err != nil || next.policyHash != p.policyHash {
		return ErrChanged
	}
	return nil
}

func validRangePolicy(p Policy) bool {
	if p.SchemaVersion == VersionV4 {
		return p.BrowsingContract == journalview.BrowseContract && p.MaxWindowSeconds == 0 && p.MaxLookbackSeconds == 0
	}
	return p.BrowsingContract == "" && p.MaxWindowSeconds > 0 && p.MaxWindowSeconds <= 3600 && p.MaxLookbackSeconds >= p.MaxWindowSeconds && p.MaxLookbackSeconds <= 86400
}
func rangeAuthorized(p Policy, q journalview.Query, now time.Time) bool {
	if q.BrowseMode == journalview.BrowseMode {
		return p.SchemaVersion == VersionV4 && p.BrowsingContract == journalview.BrowseContract
	}
	return q.BrowseMode == "" && (p.SchemaVersion == VersionV4 || q.End.Sub(q.Start) <= time.Duration(p.MaxWindowSeconds)*time.Second && now.Sub(q.Start) <= time.Duration(p.MaxLookbackSeconds)*time.Second)
}
