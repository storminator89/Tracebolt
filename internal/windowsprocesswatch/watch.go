// Package windowsprocesswatch derives exact-name presence from already-consented
// complete Toolhelp snapshots. Presence is not running state or application health.
package windowsprocesswatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsfullprocesses"
)

const (
	StateSchema  = "tracebolt.windows-process-watch-state.v1"
	ViewSchema   = "tracebolt.windows-process-watch-view.v1"
	MaxNames     = 8
	MaxDevices   = 25
	MaxBytes     = 32 << 10
	MaxAge       = 5 * time.Minute
	ViewLifetime = 30 * time.Second
)

var ErrInvalid = errors.New("windows_process_watch_invalid")

type Binding struct {
	GrantID       string `json:"grantId"`
	GrantRevision uint64 `json:"grantRevision"`
}
type Policy struct {
	Enabled  bool     `json:"enabled"`
	Names    []string `json:"names"`
	Revision uint64   `json:"revision"`
	Source   *Binding `json:"source"`
}
type State struct {
	SchemaVersion   string     `json:"schemaVersion"`
	DeviceID        string     `json:"deviceId"`
	InvitationID    string     `json:"invitationId"`
	CertificateHash string     `json:"certificateHash"`
	Policy          Policy     `json:"policy"`
	ChangedAt       *time.Time `json:"changedAt"`
}
type Input struct {
	DeviceID, InvitationID, CertificateHash, CurrentLeaf string
	AuthorityUntil                                       time.Time
	Complete                                             *windowsfullprocesses.Complete
	Counts                                               map[string]int
	UnavailableNames                                     int
}
type Request struct {
	Enabled          bool                           `json:"enabled"`
	Names            []string                       `json:"names"`
	ExpectedRevision uint64                         `json:"expectedRevision"`
	Consent          bool                           `json:"consent"`
	Source           *windowsfullprocesses.Complete `json:"source"`
}
type Check struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Matches *int   `json:"matches"`
}
type View struct {
	SchemaVersion    string                         `json:"schemaVersion"`
	DeviceID         string                         `json:"deviceId"`
	ServerNow        time.Time                      `json:"serverNow"`
	ExpiresAt        time.Time                      `json:"expiresAt"`
	Policy           Policy                         `json:"policy"`
	Status           string                         `json:"status"`
	Checks           []Check                        `json:"checks"`
	Source           *windowsfullprocesses.Complete `json:"source"`
	UnavailableNames *int                           `json:"unavailableNames"`
}

func New() State { return State{SchemaVersion: StateSchema, Policy: Policy{Names: []string{}}} }
func Names(names []string) ([]string, error) {
	if names == nil || len(names) > MaxNames {
		return nil, ErrInvalid
	}
	out := append([]string{}, names...)
	sort.Strings(out)
	for i, n := range out {
		if windowsfullprocesses.ValidateRow(windowsfullprocesses.Row{Name: &n, NameQuality: "observed"}) != nil || i > 0 && out[i-1] == n {
			return nil, ErrInvalid
		}
	}
	return out, nil
}
func Fresh(p *windowsfullprocesses.Complete, now time.Time) bool {
	if p == nil || !windowsfullprocesses.ValidTime(now) {
		return false
	}
	hash, e := windowsfullprocesses.ManifestDigest(p.Manifest)
	return e == nil && hash == p.ManifestSHA256 && windowsfullprocesses.ValidTime(p.ReceivedAt) && !p.ReceivedAt.Before(p.Manifest.CaptureFinishedAt) && !p.ReceivedAt.After(now) && !p.Manifest.CaptureStartedAt.After(now) && now.Sub(p.Manifest.CaptureStartedAt) < MaxAge && now.Sub(p.ReceivedAt) < MaxAge && now.Before(p.Manifest.ExpiresAt)
}
func (in Input) Authorized(now time.Time) bool {
	return enrollmentcrypto.ValidID(in.DeviceID, "agent_") && enrollmentcrypto.ValidID(in.InvitationID, "invite_") && enrollmentcrypto.ValidHash(in.CertificateHash) && enrollmentcrypto.ValidHash(in.CurrentLeaf) && windowsfullprocesses.ValidTime(now) && windowsfullprocesses.ValidTime(in.AuthorityUntil) && now.Before(in.AuthorityUntil)
}
func (s State) Bound(in Input) bool {
	return s.DeviceID == "" || s.DeviceID == in.DeviceID && s.InvitationID == in.InvitationID && s.CertificateHash == in.CertificateHash
}
func (in Input) Sample(now time.Time) bool {
	if !in.Authorized(now) || !Fresh(in.Complete, now) || in.Complete.Manifest.DeviceID != in.DeviceID || in.Counts == nil || len(in.Counts) > MaxNames || in.UnavailableNames < 0 || in.UnavailableNames > in.Complete.Manifest.RowCount {
		return false
	}
	total := in.UnavailableNames
	for name, n := range in.Counts {
		if _, e := Names([]string{name}); e != nil || n < 0 {
			return false
		}
		total += n
	}
	return total <= in.Complete.Manifest.RowCount
}
func (s *State) Configure(in Input, r Request, now time.Time) error {
	names, e := Names(r.Names)
	if e != nil || !in.Authorized(now) || !s.Bound(in) || r.ExpectedRevision != s.Policy.Revision || s.Policy.Revision >= windowsfullprocesses.MaxSequence || s.ChangedAt != nil && now.Before(*s.ChangedAt) {
		return ErrInvalid
	}
	if r.Enabled {
		if !r.Consent || len(names) == 0 || !in.Sample(now) || r.Source == nil || *r.Source != *in.Complete {
			return ErrInvalid
		}
		// A deliberate review must use each exact name that is actually visible now.
		// Missing names can be retained by read-only watches, not newly guessed at save.
		for _, name := range names {
			if in.Counts[name] < 1 {
				return ErrInvalid
			}
		}
	} else if r.Consent || len(names) != 0 || r.Source != nil {
		return ErrInvalid
	}
	s.DeviceID = in.DeviceID
	s.InvitationID = in.InvitationID
	s.CertificateHash = in.CertificateHash
	s.Policy = Policy{Enabled: r.Enabled, Names: names, Revision: s.Policy.Revision + 1}
	if r.Enabled {
		s.Policy.Source = &Binding{in.Complete.Manifest.GrantID, in.Complete.Manifest.GrantRevision}
	}
	at := now.UTC().Round(0)
	s.ChangedAt = &at
	return nil
}
func (s State) View(in Input, now time.Time) (View, error) {
	if !in.Authorized(now) || !s.Bound(in) || s.ChangedAt != nil && now.Before(*s.ChangedAt) {
		return View{}, ErrInvalid
	}
	out := View{SchemaVersion: ViewSchema, DeviceID: in.DeviceID, ServerNow: now, ExpiresAt: now.Add(ViewLifetime), Policy: s.Policy, Status: "disabled", Checks: []Check{}}
	if in.AuthorityUntil.Before(out.ExpiresAt) {
		out.ExpiresAt = in.AuthorityUntil
	}
	if !s.Policy.Enabled {
		return out, nil
	}
	out.Status = "unknown"
	current := in.Sample(now) && s.Policy.Source != nil && *s.Policy.Source == (Binding{in.Complete.Manifest.GrantID, in.Complete.Manifest.GrantRevision})
	if current {
		out.Status = "current"
		out.Source = in.Complete
		n := in.UnavailableNames
		out.UnavailableNames = &n
		for _, until := range []time.Time{in.Complete.Manifest.CaptureStartedAt.Add(MaxAge), in.Complete.ReceivedAt.Add(MaxAge), in.Complete.Manifest.ExpiresAt} {
			if until.Before(out.ExpiresAt) {
				out.ExpiresAt = until
			}
		}
	}
	for _, name := range s.Policy.Names {
		check := Check{Name: name, Status: "unknown"}
		if current {
			if n, ok := in.Counts[name]; ok && n > 0 {
				check.Status = "present"
				check.Matches = &n
			} else if ok && in.UnavailableNames == 0 {
				check.Status = "not_observed"
				check.Matches = &n
			}
		}
		out.Checks = append(out.Checks, check)
	}
	return out, nil
}
func Encode(s State) ([]byte, error) {
	if s.SchemaVersion != StateSchema || !enrollmentcrypto.ValidID(s.DeviceID, "agent_") || !enrollmentcrypto.ValidID(s.InvitationID, "invite_") || !enrollmentcrypto.ValidHash(s.CertificateHash) || !windowsfullprocesses.ValidSequence(s.Policy.Revision) || s.ChangedAt == nil || !windowsfullprocesses.ValidTime(*s.ChangedAt) {
		return nil, ErrInvalid
	}
	names, e := Names(s.Policy.Names)
	if e != nil || len(names) != len(s.Policy.Names) {
		return nil, ErrInvalid
	}
	for i := range names {
		if names[i] != s.Policy.Names[i] {
			return nil, ErrInvalid
		}
	}
	if s.Policy.Enabled {
		if len(names) == 0 || s.Policy.Source == nil || !windowsfullprocesses.ValidHex(s.Policy.Source.GrantID, 32) || !windowsfullprocesses.ValidSequence(s.Policy.Source.GrantRevision) {
			return nil, ErrInvalid
		}
	} else if len(names) != 0 || s.Policy.Source != nil {
		return nil, ErrInvalid
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > MaxBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
func Decode(raw []byte) (State, error) {
	var s State
	if len(raw) == 0 || len(raw) > MaxBytes || json.Unmarshal(raw, &s) != nil {
		return State{}, ErrInvalid
	}
	canonical, e := Encode(s)
	if e != nil || !bytes.Equal(raw, canonical) {
		return State{}, ErrInvalid
	}
	return s, nil
}
