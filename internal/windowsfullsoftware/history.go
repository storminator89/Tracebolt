package windowsfullsoftware

import (
	"encoding/json"
	"strings"
	"time"
)

const (
	HistoryScope       = "windows-machine-software-history-v1"
	HistoryPageVersion = "tracebolt.windows-software-history-page.v1"
	HistoryRetention   = 7 * 24 * time.Hour
	MaxHistoryRows     = 1024
	MaxHistoryBytes    = 1 << 20
	HistoryHTTPPrivacy = "WARNING: HTTP-test sends history-authorized complete machine-software registration metadata in plaintext. Network observers can read it; signatures do not encrypt it or authenticate manager responses. Production requires HTTPS."
	HistoryPrivacy     = "Separately allow the manager to compare complete caller-visible HKLM machine-software generations captured after this explicit history grant. Retain observed registration additions/removals and observed name/version/publisher differences for up to seven days from the earlier original observation, at most 1024 change rows and 1 MiB per device. Unknown fields are not observed changes. Gaps, missing baselines and quota omissions are explicit. This does not establish installation/uninstallation times, upgrade direction or application identity across reinstalls. Operator-only private search and paging; no additional native collection, privileges, AI, export, health inference or actions. Existing inventory consent alone does not grant history."
)

type HistoryChange struct {
	ID               string    `json:"id"`
	Kind             string    `json:"kind"` // registration_added, registration_removed, metadata_changed
	RegistrationID   string    `json:"registrationId"`
	RegistryView     string    `json:"registryView"`
	BeforeObservedAt time.Time `json:"beforeObservedAt"`
	AfterObservedAt  time.Time `json:"afterObservedAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
	Before           *Row      `json:"before"`
	After            *Row      `json:"after"`
	ChangedFields    []string  `json:"changedFields"`
}

type HistoryComparison struct {
	Status           string     `json:"status"` // baseline, compared, gap
	Reason           string     `json:"reason"` // no_baseline, source_gap, incomparable, resource_limit, or empty
	BeforeObservedAt *time.Time `json:"beforeObservedAt"`
	AfterObservedAt  time.Time  `json:"afterObservedAt"`
	ExpiresAt        time.Time  `json:"expiresAt"`
	ObservedChanges  int        `json:"observedChanges"`
}

type HistoryPage struct {
	SchemaVersion   string             `json:"schemaVersion"`
	DeviceID        string             `json:"deviceId"`
	ServerNow       time.Time          `json:"serverNow"`
	Status          string             `json:"status"` // not_configured, disabled, awaiting, ready
	AuthorityUntil  *time.Time         `json:"authorityUntil"`
	GrantID         *string            `json:"grantId"`
	GrantRevision   *uint64            `json:"grantRevision"`
	HistoryDigest   string             `json:"historyDigest"`
	Comparison      *HistoryComparison `json:"comparison"`
	LatestAttempt   *Attempt           `json:"latestAttempt"`
	GapCount        uint64             `json:"gapCount"`
	OmittedChanges  uint64             `json:"omittedChanges"`
	ExpiredChanges  uint64             `json:"expiredChanges"`
	RetainedCount   int                `json:"retainedCount"`
	Search          string             `json:"search"`
	Limit           int                `json:"limit"`
	Offset          int                `json:"offset"`
	MatchingCount   int                `json:"matchingCount"`
	Rows            []HistoryChange    `json:"rows"`
	NextCursor      string             `json:"nextCursor"`
	CursorExpiresAt *time.Time         `json:"cursorExpiresAt"`
}

// History uses the same private query shape; its only sort is observed-desc.
func ValidateHistoryQuery(q Query) error {
	if q.Sort != "observed-desc" {
		return ErrInvalid
	}
	q.Sort = "name-asc"
	return ValidateQuery(q)
}

// DiffHistory compares exact opaque source-key identities and views, never
// labels. It counts the entire bounded difference but retains no oversized
// prefix; callers expose an explicit gap if the complete difference will not fit.
func DiffHistory(before, after Manifest, oldRows, newRows []Row) ([]HistoryChange, int, error) {
	if ValidateManifest(before) != nil || ValidateManifest(after) != nil || before.DeviceID != after.DeviceID || before.SenderBinding != after.SenderBinding || before.GrantID != after.GrantID || before.GrantRevision != after.GrantRevision || before.Source != after.Source || before.Coverage != after.Coverage || after.Sequence != before.Sequence+1 || after.CaptureStartedAt.Before(before.CaptureFinishedAt) {
		return nil, 0, ErrInvalid
	}
	for _, pair := range []struct {
		m    Manifest
		rows []Row
	}{{before, oldRows}, {after, newRows}} {
		digest, size, err := RowsDigest(pair.rows)
		if err != nil || digest != pair.m.RowsSHA256 || size != pair.m.RowsBytes || len(pair.rows) != pair.m.RowCount {
			return nil, 0, ErrInvalid
		}
	}
	changes := []HistoryChange{}
	total, size := 0, 2
	add := func(kind string, a, b *Row, fields []string) {
		row := a
		if b != nil {
			row = b
		}
		c := HistoryChange{Kind: kind, RegistrationID: row.RegistrationID, RegistryView: row.RegistryView, BeforeObservedAt: before.CaptureFinishedAt, AfterObservedAt: after.CaptureFinishedAt, ExpiresAt: before.CaptureStartedAt.Add(HistoryRetention), Before: a, After: b, ChangedFields: fields}
		c.ID = Hash([]byte("tracebolt.windows-software-history.change.v1\x00" + before.GenerationID + "\x00" + after.GenerationID + "\x00" + row.RegistrationID + "\x00" + row.RegistryView + "\x00" + kind))
		total++
		raw, _ := json.Marshal(c)
		size += len(raw) + 1
		if total <= MaxHistoryRows && size <= MaxHistoryBytes-16384 {
			changes = append(changes, c)
		}
	}
	i, j := 0, 0
	for i < len(oldRows) || j < len(newRows) {
		if i == len(oldRows) {
			add("registration_added", nil, &newRows[j], []string{})
			j++
			continue
		}
		if j == len(newRows) {
			add("registration_removed", &oldRows[i], nil, []string{})
			i++
			continue
		}
		a, b := &oldRows[i], &newRows[j]
		if a.RegistrationID < b.RegistrationID {
			add("registration_removed", a, nil, []string{})
			i++
			continue
		}
		if a.RegistrationID > b.RegistrationID {
			add("registration_added", nil, b, []string{})
			j++
			continue
		}
		if a.RegistryView != b.RegistryView {
			return nil, 0, ErrInvalid
		}
		fields := []string{}
		for _, f := range []struct {
			name string
			a, b *string
		}{{"name", a.Name, b.Name}, {"version", a.Version, b.Version}, {"publisher", a.Publisher, b.Publisher}} {
			if f.a != nil && f.b != nil && *f.a != *f.b {
				fields = append(fields, f.name)
			}
		}
		if len(fields) > 0 {
			add("metadata_changed", a, b, fields)
		}
		i++
		j++
	}
	if len(changes) != total {
		return nil, total, ErrBudget
	}
	return changes, total, nil
}

func HistorySearchText(c HistoryChange) string {
	values := []string{c.Kind, c.RegistryView, c.RegistrationID}
	for _, r := range []*Row{c.Before, c.After} {
		if r != nil {
			for _, v := range []*string{r.Name, r.Version, r.Publisher} {
				if v != nil {
					values = append(values, *v)
				}
			}
		}
	}
	return IdentityKey(strings.Join(values, "\n"))
}
