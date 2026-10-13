package enrollmentstore

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/macosinventory"
	"localrmm/internal/macosinventorywire"
)

const (
	MacOSInventoryMaxPageBytes       = 32 * 1024
	MacOSInventoryLookupQueryVersion = "tracebolt.macos-read-inventory-query.v2"
	MacOSInventoryLookupPageVersion  = "tracebolt.macos-read-inventory-page.v2"
	MacOSInventoryMaxSearchBytes     = 256
)

type MacOSInventoryQuery struct {
	Section       string  `json:"section"`
	GenerationID  string  `json:"generationId"`
	Offset        int     `json:"offset"`
	Limit         int     `json:"limit"`
	SchemaVersion string  `json:"schemaVersion,omitempty"`
	Search        *string `json:"search,omitempty"`
}

type MacOSInventorySources struct {
	Hardware  macosinventory.Status `json:"hardware"`
	Receipts  macosinventory.Status `json:"receipts"`
	Processes macosinventory.Status `json:"processes"`
	IPv4      macosinventory.Status `json:"ipv4"`
	IPv6      macosinventory.Status `json:"ipv6"`
}

// Private operator response only. The unexported identity/session guard cannot
// be supplied by JSON or reconstructed from a mutable device identifier.
type MacOSInventoryPage struct {
	SchemaVersion  string                     `json:"schemaVersion"`
	DeviceID       string                     `json:"deviceId"`
	Section        string                     `json:"section"`
	Status         string                     `json:"status"`
	ServerNow      time.Time                  `json:"serverNow"`
	AuthorityUntil time.Time                  `json:"authorityUntil"`
	GenerationID   string                     `json:"generationId"`
	SourceQuality  string                     `json:"sourceQuality"`
	CollectedAt    *time.Time                 `json:"collectedAt"`
	ExpiresAt      *time.Time                 `json:"expiresAt"`
	Sources        *MacOSInventorySources     `json:"sources"`
	Hardware       *macosinventory.Hardware   `json:"hardware"`
	ReceiptIDs     []string                   `json:"receiptIds"`
	Processes      []macosinventory.Process   `json:"processes"`
	Interfaces     []macosinventory.Interface `json:"interfaces"`
	Offset         int                        `json:"offset"`
	Total          int                        `json:"total"`
	NextOffset     *int                       `json:"nextOffset"`
	// Pointers retain the exact v1 bytes while emitting empty/zero v2 values.
	Search        *string `json:"search,omitempty"`
	MatchingCount *int    `json:"matchingCount,omitempty"`
	guard         macOSInventoryReadGuard
}

type macOSInventoryReadGuard struct {
	invitation, certificate, session, grant, generation string
	control                                             uint64
	checked, until                                      time.Time
}
type macOSInventorySessionKey struct{}
type macOSInventorySession struct {
	id     string
	until  time.Time
	active func() bool
}

// Install only at the authenticated operator boundary, never from JSON.
func WithMacOSInventorySession(ctx context.Context, id string, until time.Time, active func() bool) context.Context {
	return context.WithValue(ctx, macOSInventorySessionKey{}, macOSInventorySession{id, until, active})
}
func macOSSession(ctx context.Context, at time.Time) (macOSInventorySession, error) {
	s, ok := ctx.Value(macOSInventorySessionKey{}).(macOSInventorySession)
	if !ok || s.id == "" || s.active == nil || !s.active() || !validStoreTime(s.until) || !at.Before(s.until) {
		return s, enrollmentstate.ErrProof
	}
	return s, nil
}
func ValidateMacOSInventoryQuery(q MacOSInventoryQuery) error {
	if q.SchemaVersion == "" {
		if q.Search != nil {
			return macosinventorywire.ErrInvalid
		}
	} else if q.SchemaVersion != MacOSInventoryLookupQueryVersion || q.Section != "receipts" && q.Section != "processes" || q.Search == nil || !validMacOSInventorySearch(*q.Search) {
		return macosinventorywire.ErrInvalid
	}
	if q.Limit < 1 || q.Limit > 100 || q.Offset < 0 || q.Offset > macosinventory.MaxProcesses {
		return macosinventorywire.ErrInvalid
	}
	switch q.Section {
	case "summary":
		if q.Offset != 0 || q.GenerationID != "" {
			return macosinventorywire.ErrInvalid
		}
	case "hardware", "receipts", "processes", "ipv4", "ipv6":
		if !enrollmentcrypto.ValidID(q.GenerationID, "sample_") || q.Section == "hardware" && q.Offset != 0 {
			return macosinventorywire.ErrInvalid
		}
	default:
		return macosinventorywire.ErrInvalid
	}
	return nil
}

// Search is canonical printable ASCII, not a regular expression or a query
// language. Numeric fields are matched separately, never joined with labels.
func validMacOSInventorySearch(search string) bool {
	if len(search) > MacOSInventoryMaxSearchBytes || strings.Trim(search, " ") != search {
		return false
	}
	for i := 0; i < len(search); i++ {
		if search[i] < ' ' || search[i] > '~' || search[i] >= 'A' && search[i] <= 'Z' {
			return false
		}
	}
	return true
}

func macOSInventoryProcessMatches(row macosinventory.Process, search string) bool {
	return search == "" ||
		row.NameQuality == "observed" && strings.Contains(strings.ToLower(row.AccountingName), search) ||
		strings.Contains(strconv.FormatUint(uint64(row.PID), 10), search) ||
		strings.Contains(strconv.FormatUint(uint64(row.ParentPID), 10), search)
}

func (s *Store) MacOSInventoryPage(ctx context.Context, device string, q MacOSInventoryQuery, now time.Time) (MacOSInventoryPage, error) {
	zero := MacOSInventoryPage{}
	if ValidateMacOSInventoryQuery(q) != nil || !enrollmentcrypto.ValidID(device, "agent_") {
		return zero, macosinventorywire.ErrInvalid
	}
	release, e := s.macOSInventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	var out MacOSInventoryPage
	e = s.transact(ctx, func(t *transaction) error {
		var err error
		now, err = macOSNow(ctx, now)
		if err != nil {
			return err
		}
		owner, err := macOSSession(ctx, now)
		if err != nil {
			return err
		}
		var snap enrollmentstate.Snapshot
		for _, v := range t.engine.Snapshots() {
			if v.Approval.DeviceID == device {
				if snap.InvitationID != "" {
					return ErrStorage
				}
				snap = v
			}
		}
		if snap.InvitationID == "" {
			return enrollmentstate.ErrNotFound
		}
		cert := t.currentCertificateHash(snap)
		if _, err = s.macOSInventoryAuthority(t, snap.InvitationID, cert, now); err != nil {
			return err
		}
		if err = macOSInventoryClock(ctx, t, now); err != nil {
			return err
		}
		r, err := readMacOSInventoryRecord(ctx, t, snap.InvitationID)
		if err != nil {
			return err
		}
		out = MacOSInventoryPage{SchemaVersion: "tracebolt.macos-read-inventory-page.v1", DeviceID: device, Section: q.Section, Status: "not-enabled", ServerNow: now, SourceQuality: "unknown", ReceiptIDs: []string{}, Processes: []macosinventory.Process{}, Interfaces: []macosinventory.Interface{}, Offset: q.Offset}
		if q.SchemaVersion == MacOSInventoryLookupQueryVersion {
			search, matches := *q.Search, 0
			out.SchemaVersion = MacOSInventoryLookupPageVersion
			out.Search, out.MatchingCount = &search, &matches
		}
		out.guard = macOSInventoryReadGuard{invitation: snap.InvitationID, certificate: cert, session: owner.id, checked: now, until: time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()}
		if owner.until.Before(out.guard.until) {
			out.guard.until = owner.until
		}
		if r != nil {
			active, _ := macosinventorywire.DecodeControl(r.EnableRaw)
			out.guard.grant = active.GrantID
			out.guard.control = 1
			out.Status = "unavailable"
			if len(r.DisableRaw) > 0 {
				out.Status = "disabled"
				out.guard.control = 2
			}
			if r.Latest != nil {
				h := r.Latest
				out.GenerationID = h.GenerationID
				out.CollectedAt = &h.CollectedAt
				out.ExpiresAt = &h.ExpiresAt
				out.SourceQuality = h.SourceQuality
				out.Sources = &h.Sources
				out.guard.generation = h.GenerationID
				if len(r.DisableRaw) == 0 {
					if !now.Before(h.ExpiresAt) {
						out.Status = "expired"
					} else if now.Before(h.CollectedAt.Add(macosinventorywire.CaptureInterval)) {
						out.Status = "fresh"
					} else {
						out.Status = "stale"
					}
				}
				if now.Before(h.ExpiresAt) && len(r.DisableRaw) == 0 {
					if h.ExpiresAt.Before(out.guard.until) {
						out.guard.until = h.ExpiresAt
					}
					out.AuthorityUntil = out.guard.until
					if q.Section != "summary" {
						if q.GenerationID != h.GenerationID {
							return macosinventorywire.ErrConflict
						}
						report, err := macosinventorywire.DecodeReport(r.ReportRaw)
						if err != nil {
							return ErrStorage
						}
						switch q.Section {
						case "hardware":
							out.Hardware = &report.Snapshot.Hardware
						case "receipts":
							out.Total = len(report.Snapshot.Receipts.Identifiers)
						case "processes":
							out.Total = len(report.Snapshot.Processes.Rows)
						case "ipv4":
							out.Total = len(report.Snapshot.Network.IPv4.Rows)
						case "ipv6":
							out.Total = len(report.Snapshot.Network.IPv6.Rows)
						}
						pageTotal := out.Total
						if out.Search != nil {
							// Compact only this bounded decoded report in source order. No
							// persistent index, SQL search, collection or source mutation.
							switch q.Section {
							case "receipts":
								rows := report.Snapshot.Receipts.Identifiers
								report.Snapshot.Receipts.Identifiers = rows[:0]
								for _, row := range rows {
									if strings.Contains(strings.ToLower(row), *out.Search) {
										report.Snapshot.Receipts.Identifiers = append(report.Snapshot.Receipts.Identifiers, row)
									}
								}
								pageTotal = len(report.Snapshot.Receipts.Identifiers)
							case "processes":
								rows := report.Snapshot.Processes.Rows
								report.Snapshot.Processes.Rows = rows[:0]
								for _, row := range rows {
									if macOSInventoryProcessMatches(row, *out.Search) {
										report.Snapshot.Processes.Rows = append(report.Snapshot.Processes.Rows, row)
									}
								}
								pageTotal = len(report.Snapshot.Processes.Rows)
							}
							*out.MatchingCount = pageTotal
						}
						if q.Offset > pageTotal && q.Section != "hardware" {
							return macosinventorywire.ErrInvalid
						}
						for i := q.Offset; i < pageTotal && i < q.Offset+q.Limit; i++ {
							switch q.Section {
							case "receipts":
								out.ReceiptIDs = append(out.ReceiptIDs, report.Snapshot.Receipts.Identifiers[i])
							case "processes":
								out.Processes = append(out.Processes, report.Snapshot.Processes.Rows[i])
							case "ipv4":
								out.Interfaces = append(out.Interfaces, report.Snapshot.Network.IPv4.Rows[i])
							case "ipv6":
								out.Interfaces = append(out.Interfaces, report.Snapshot.Network.IPv6.Rows[i])
							}
							next := i + 1
							if next < pageTotal {
								out.NextOffset = &next
							} else {
								out.NextOffset = nil
							}
							raw, err := json.Marshal(out)
							if err != nil {
								return ErrStorage
							}
							if len(raw) > MacOSInventoryMaxPageBytes {
								switch q.Section {
								case "receipts":
									out.ReceiptIDs = out.ReceiptIDs[:len(out.ReceiptIDs)-1]
								case "processes":
									out.Processes = out.Processes[:len(out.Processes)-1]
								default:
									out.Interfaces = out.Interfaces[:len(out.Interfaces)-1]
								}
								next = i
								out.NextOffset = &next
								if i == q.Offset {
									return ErrStorage
								}
								break
							}
						}
					}
				} else if q.Section != "summary" {
					return macosinventorywire.ErrExpired
				}
			} else if q.Section != "summary" {
				return macosinventorywire.ErrConflict
			}
		} else if q.Section != "summary" {
			return macosinventorywire.ErrConflict
		}
		out.AuthorityUntil = out.guard.until
		t.beforeCommit = append(t.beforeCommit, func() error { return s.macOSInventoryReadGuard(ctx, t, out.guard, now) })
		return nil
	})
	if e != nil {
		return zero, e
	}
	if e = s.RecheckMacOSInventoryPage(ctx, out, now); e != nil {
		return zero, e
	}
	return out, nil
}
func (s *Store) macOSInventoryReadGuard(ctx context.Context, t *transaction, g macOSInventoryReadGuard, now time.Time) error {
	at, e := macOSNow(ctx, now)
	if e != nil {
		return e
	}
	if g.invitation == "" || at.Before(g.checked) || !at.Before(g.until) {
		return enrollmentstate.ErrExpired
	}
	if e = macOSInventoryClock(ctx, t, at); e != nil {
		return e
	}
	owner, e := macOSSession(ctx, at)
	if e != nil || owner.id != g.session {
		return enrollmentstate.ErrProof
	}
	if _, e = s.macOSInventoryAuthority(t, g.invitation, g.certificate, at); e != nil {
		return e
	}
	r, e := readMacOSInventoryRecord(ctx, t, g.invitation)
	if e != nil {
		return e
	}
	if r == nil {
		if g.grant != "" {
			return macosinventorywire.ErrConflict
		}
		return nil
	}
	c, _ := macosinventorywire.DecodeControl(r.EnableRaw)
	revision := uint64(1)
	if len(r.DisableRaw) > 0 {
		revision = 2
	}
	generation := ""
	if r.Latest != nil {
		generation = r.Latest.GenerationID
	}
	if c.GrantID != g.grant || revision != g.control || generation != g.generation {
		return macosinventorywire.ErrConflict
	}
	return nil
}
func (s *Store) RecheckMacOSInventoryPage(ctx context.Context, p MacOSInventoryPage, now time.Time) error {
	if s == nil || s.storeState == nil || s.config.Binding.CollectionProfile != macosinventorywire.Profile {
		return enrollmentstate.ErrProof
	}
	return s.transact(ctx, func(t *transaction) error {
		if err := s.macOSInventoryReadGuard(ctx, t, p.guard, now); err != nil {
			return err
		}
		t.beforeCommit = append(t.beforeCommit, func() error { return s.macOSInventoryReadGuard(ctx, t, p.guard, now) })
		return nil
	})
}
