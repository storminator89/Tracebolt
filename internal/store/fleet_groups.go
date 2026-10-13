package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Organizational metadata only. Nothing in this table is collection, policy,
// action, enrollment, AI or notification authority.
const fleetGroupsSchema = `CREATE TABLE IF NOT EXISTS fleet_groups(id TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384 AND json_valid(body)))`
const MaxFleetGroups = 25
const MaxFleetGroupMembers = 50 // bounded Linux and Windows admission, 25 each
const MaxFleetGroupRevision = uint64(1<<53 - 1)

var ErrFleetGroupConflict = errors.New("fleet group revision or admission changed")
var ErrFleetGroupInvalid = errors.New("invalid fleet group")

// Identity is a private hash of manager/profile and original issued identity;
// never a mutable hostname, address or renewed leaf. Do not project it to UI.
type FleetGroupMember struct {
	DeviceID string `json:"deviceId"`
	Identity string `json:"identity"`
}
type FleetGroup struct {
	Version  string             `json:"version"`
	ID       string             `json:"id"`
	Manager  string             `json:"manager"`
	Name     string             `json:"name"`
	Revision uint64             `json:"revision"`
	Members  []FleetGroupMember `json:"members"`
}

func ValidFleetGroupName(name string) bool {
	if name != strings.TrimSpace(name) || len(name) < 1 || len(name) > 80 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func validFleetGroup(g FleetGroup) bool {
	if g.Version != "tracebolt.fleet-group.v1" || !enrollmentcrypto.ValidID(g.ID, "group_") || !enrollmentcrypto.ValidHash(g.Manager) || !ValidFleetGroupName(g.Name) || g.Revision < 1 || g.Revision > MaxFleetGroupRevision || g.Members == nil || len(g.Members) > MaxFleetGroupMembers {
		return false
	}
	for i, m := range g.Members {
		if !enrollmentcrypto.ValidID(m.DeviceID, "agent_") || !enrollmentcrypto.ValidHash(m.Identity) || i > 0 && g.Members[i-1].DeviceID >= m.DeviceID {
			return false
		}
	}
	return true
}
func decodeFleetGroup(id string, raw []byte) (FleetGroup, error) {
	var g FleetGroup
	if len(raw) > 16384 || json.Unmarshal(raw, &g) != nil || g.ID != id || !validFleetGroup(g) {
		return g, ErrFleetGroupInvalid
	}
	canonical, err := json.Marshal(g)
	if err != nil || !bytes.Equal(canonical, raw) {
		return FleetGroup{}, ErrFleetGroupInvalid
	}
	return g, nil
}
func (s *Store) FleetGroups(ctx context.Context, manager string) ([]FleetGroup, error) {
	if !enrollmentcrypto.ValidHash(manager) {
		return nil, ErrFleetGroupInvalid
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,body FROM fleet_groups ORDER BY id LIMIT 26")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetGroup{}
	count := 0
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		count++
		if count > MaxFleetGroups {
			return nil, ErrFleetGroupInvalid
		}
		g, err := decodeFleetGroup(id, raw)
		if err != nil {
			return nil, err
		}
		if g.Manager == manager {
			out = append(out, g)
		}
	}
	return out, rows.Err()
}

// Save uses exact revisions, including zero for a fresh server-generated ID.
// Updating membership replaces the reviewed set; no dynamic matching/inheritance.
func (s *Store) SaveFleetGroup(ctx context.Context, manager, id, name string, members []FleetGroupMember, expected uint64, remove bool, guard func() error) (FleetGroup, error) {
	if expected >= MaxFleetGroupRevision || guard == nil {
		return FleetGroup{}, ErrFleetGroupInvalid
	}
	members = append([]FleetGroupMember{}, members...)
	sort.Slice(members, func(i, j int) bool { return members[i].DeviceID < members[j].DeviceID })
	next := FleetGroup{Version: "tracebolt.fleet-group.v1", ID: id, Manager: manager, Name: name, Revision: expected + 1, Members: members}
	if !validFleetGroup(next) {
		return FleetGroup{}, ErrFleetGroupInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return FleetGroup{}, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM fleet_groups").Scan(&count); err != nil {
		return FleetGroup{}, err
	}
	if count > MaxFleetGroups {
		return FleetGroup{}, ErrFleetGroupInvalid
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT body FROM fleet_groups WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		if expected != 0 || remove {
			return FleetGroup{}, ErrFleetGroupConflict
		}
		if count >= MaxFleetGroups {
			return FleetGroup{}, ErrLimit
		}
	} else if err != nil {
		return FleetGroup{}, err
	} else {
		old, e := decodeFleetGroup(id, raw)
		if e != nil {
			return FleetGroup{}, e
		}
		if old.Manager != manager || old.Revision != expected {
			return FleetGroup{}, ErrFleetGroupConflict
		}
	}
	if err = guard(); err != nil {
		return FleetGroup{}, err
	}
	if remove {
		_, err = tx.ExecContext(ctx, "DELETE FROM fleet_groups WHERE id=?", id)
	} else {
		raw, err = json.Marshal(next)
		if err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO fleet_groups(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", id, raw)
		}
	}
	if err != nil {
		return FleetGroup{}, err
	}
	if err = disarmFleetMonitoring(ctx, tx, next, remove); err != nil {
		return FleetGroup{}, err
	}
	if err = guard(); err != nil {
		return FleetGroup{}, err
	}
	if err = ctx.Err(); err != nil {
		return FleetGroup{}, err
	}
	if err = tx.Commit(); err != nil {
		return FleetGroup{}, err
	}
	return next, nil
}
