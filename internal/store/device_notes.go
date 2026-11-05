package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Manager-only organizational prose. Never collector, policy, AI or export data.
const deviceNotesSchema = `CREATE TABLE IF NOT EXISTS device_notes(manager TEXT NOT NULL, identity TEXT NOT NULL, device_id TEXT NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=524288 AND json_valid(body)), PRIMARY KEY(manager,identity,device_id))`
const MaxDeviceNotes = 25
const MaxDeviceNoteOperations = 250
const MaxDeviceNotebooks = 100
const MaxDeviceNoteTextBytes = 2000
const MaxDeviceNoteRevision = uint64(1<<53 - 1)
const maxDeviceNotesBytes = 512 * 1024
const deviceNotesVersion = "tracebolt.device-notes.v1"

var ErrDeviceNotesInvalid = errors.New("invalid device notes")
var ErrDeviceNotesConflict = errors.New("device notes revision or operation changed")
var ErrDeviceNotesLimit = errors.New("device notes limit reached")

type DeviceNote struct {
	ID        string    `json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"createdAt"`
	Archived  bool      `json:"archived"`
	ChangedAt time.Time `json:"changedAt"`
}
type DeviceNoteOperation struct {
	ID            string `json:"id"`
	Action        string `json:"action"`
	NoteID        string `json:"noteId"`
	Revision      uint64 `json:"revision"`
	RequestDigest string `json:"requestDigest"`
}
type DeviceNotes struct {
	Version    string                `json:"version"`
	Manager    string                `json:"manager"`
	Identity   string                `json:"identity"`
	DeviceID   string                `json:"deviceId"`
	Revision   uint64                `json:"revision"`
	Notes      []DeviceNote          `json:"notes"`
	Operations []DeviceNoteOperation `json:"operations"`
}

func validDeviceNotesBinding(manager, identity, deviceID string) bool {
	return enrollmentcrypto.ValidHash(manager) && enrollmentcrypto.ValidHash(identity) && enrollmentcrypto.ValidID(deviceID, "agent_")
}
func ValidDeviceNoteText(text string) bool {
	if len(text) == 0 || len(text) > MaxDeviceNoteTextBytes || !utf8.ValidString(text) || strings.TrimSpace(text) != text {
		return false
	}
	for _, r := range text {
		if unicode.Is(unicode.Cf, r) || unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}
func emptyDeviceNotes(manager, identity, deviceID string) DeviceNotes {
	return DeviceNotes{Version: deviceNotesVersion, Manager: manager, Identity: identity, DeviceID: deviceID, Notes: []DeviceNote{}, Operations: []DeviceNoteOperation{}}
}
func deviceNoteDigest(manager, identity, deviceID, operationID, action, noteID, text string, expected uint64) string {
	// Typed, length-delimited JSON avoids ambiguous concatenation. Expected revision
	// is part of the immutable intent; a stale request cannot be silently rebased.
	b, _ := json.Marshal(struct {
		Fields   []string
		Expected uint64
	}{[]string{deviceNotesVersion, manager, identity, deviceID, operationID, action, noteID, text}, expected})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validDeviceNoteTime(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.Location() == time.UTC
}
func decodeDeviceNotes(raw []byte, manager, identity, deviceID string) (DeviceNotes, error) {
	var n DeviceNotes
	if len(raw) > maxDeviceNotesBytes || json.Unmarshal(raw, &n) != nil || n.Version != deviceNotesVersion || n.Manager != manager || n.Identity != identity || n.DeviceID != deviceID || !validDeviceNotesBinding(n.Manager, n.Identity, n.DeviceID) || n.Notes == nil || n.Operations == nil || len(n.Notes) > MaxDeviceNotes || len(n.Operations) > MaxDeviceNoteOperations || n.Revision == 0 || n.Revision > MaxDeviceNoteRevision || n.Revision != uint64(len(n.Operations)) {
		return DeviceNotes{}, ErrDeviceNotesInvalid
	}
	byID := map[string]DeviceNote{}
	for _, note := range n.Notes {
		if !enrollmentcrypto.ValidID(note.ID, "note_") || !ValidDeviceNoteText(note.Text) || !validDeviceNoteTime(note.CreatedAt) || !validDeviceNoteTime(note.ChangedAt) || note.ChangedAt.Before(note.CreatedAt) {
			return DeviceNotes{}, ErrDeviceNotesInvalid
		}
		if _, ok := byID[note.ID]; ok {
			return DeviceNotes{}, ErrDeviceNotesInvalid
		}
		byID[note.ID] = note
	}
	seen := map[string]bool{}
	states := map[string]bool{}
	added := 0
	for i, op := range n.Operations {
		note, exists := byID[op.NoteID]
		if !exists || seen[op.ID] || !enrollmentcrypto.ValidID(op.ID, "noteop_") || op.Revision != uint64(i+1) || !enrollmentcrypto.ValidHash(op.RequestDigest) {
			return DeviceNotes{}, ErrDeviceNotesInvalid
		}
		seen[op.ID] = true
		archived, known := states[op.NoteID]
		text := ""
		switch op.Action {
		case "add":
			if known || op.NoteID != "note_"+strings.TrimPrefix(op.ID, "noteop_") || added >= len(n.Notes) || n.Notes[added].ID != op.NoteID {
				return DeviceNotes{}, ErrDeviceNotesInvalid
			}
			states[op.NoteID] = false
			text = note.Text
			added++
		case "archive":
			if !known || archived {
				return DeviceNotes{}, ErrDeviceNotesInvalid
			}
			states[op.NoteID] = true
		case "restore":
			if !known || !archived {
				return DeviceNotes{}, ErrDeviceNotesInvalid
			}
			states[op.NoteID] = false
		default:
			return DeviceNotes{}, ErrDeviceNotesInvalid
		}
		if op.RequestDigest != deviceNoteDigest(manager, identity, deviceID, op.ID, op.Action, op.NoteID, text, op.Revision-1) {
			return DeviceNotes{}, ErrDeviceNotesInvalid
		}
	}
	if added != len(n.Notes) {
		return DeviceNotes{}, ErrDeviceNotesInvalid
	}
	for _, note := range n.Notes {
		if states[note.ID] != note.Archived {
			return DeviceNotes{}, ErrDeviceNotesInvalid
		}
	}
	canonical, err := json.Marshal(n)
	if err != nil || !bytes.Equal(canonical, raw) {
		return DeviceNotes{}, ErrDeviceNotesInvalid
	}
	return n, nil
}

type deviceNotesReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readDeviceNotes(ctx context.Context, q deviceNotesReader, manager, identity, deviceID string) (DeviceNotes, bool, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT body FROM device_notes WHERE manager=? AND identity=? AND device_id=?`, manager, identity, deviceID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return emptyDeviceNotes(manager, identity, deviceID), false, nil
	}
	if err != nil {
		return DeviceNotes{}, false, err
	}
	n, err := decodeDeviceNotes(raw, manager, identity, deviceID)
	return n, true, err
}
func (s *Store) ReadDeviceNotes(ctx context.Context, manager, identity, deviceID string) (DeviceNotes, error) {
	if !validDeviceNotesBinding(manager, identity, deviceID) {
		return DeviceNotes{}, ErrDeviceNotesInvalid
	}
	n, _, err := readDeviceNotes(ctx, s.db, manager, identity, deviceID)
	return n, err
}
func (s *Store) ApplyDeviceNote(ctx context.Context, manager, identity, deviceID, operationID, action, noteID, text string, expected uint64, now time.Time, guard func() error) (DeviceNotes, error) {
	if !validDeviceNotesBinding(manager, identity, deviceID) || !enrollmentcrypto.ValidID(operationID, "noteop_") || !enrollmentcrypto.ValidID(noteID, "note_") || expected >= MaxDeviceNoteRevision || guard == nil || !validDeviceNoteTime(now.UTC()) {
		return DeviceNotes{}, ErrDeviceNotesInvalid
	}
	if action == "add" {
		if !ValidDeviceNoteText(text) || noteID != "note_"+strings.TrimPrefix(operationID, "noteop_") {
			return DeviceNotes{}, ErrDeviceNotesInvalid
		}
	} else if (action != "archive" && action != "restore") || text != "" {
		return DeviceNotes{}, ErrDeviceNotesInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceNotes{}, err
	}
	defer tx.Rollback()
	n, exists, err := readDeviceNotes(ctx, tx, manager, identity, deviceID)
	if err != nil {
		return DeviceNotes{}, err
	}
	digest := deviceNoteDigest(manager, identity, deviceID, operationID, action, noteID, text, expected)
	for _, op := range n.Operations {
		if op.ID == operationID {
			if op.RequestDigest != digest {
				return DeviceNotes{}, ErrDeviceNotesConflict
			}
			if err = ctx.Err(); err != nil {
				return DeviceNotes{}, err
			}
			if err = guard(); err != nil {
				return DeviceNotes{}, err
			}
			return n, nil
		}
	}
	if n.Revision != expected {
		return DeviceNotes{}, ErrDeviceNotesConflict
	}
	// A new request must not move the authored journal behind an already
	// committed timestamp, including after a manager clock rollback or restart.
	for _, note := range n.Notes {
		if now.Before(note.CreatedAt) || now.Before(note.ChangedAt) {
			return DeviceNotes{}, ErrDeviceNotesConflict
		}
	}
	if len(n.Operations) >= MaxDeviceNoteOperations {
		return DeviceNotes{}, ErrDeviceNotesLimit
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM device_notes`).Scan(&count); err != nil {
		return DeviceNotes{}, err
	}
	if count > MaxDeviceNotebooks {
		return DeviceNotes{}, ErrDeviceNotesInvalid
	}
	if !exists && count >= MaxDeviceNotebooks {
		return DeviceNotes{}, ErrDeviceNotesLimit
	}
	now = now.UTC()
	if action == "add" {
		if len(n.Notes) >= MaxDeviceNotes {
			return DeviceNotes{}, ErrDeviceNotesLimit
		}
		n.Notes = append(n.Notes, DeviceNote{ID: noteID, Text: text, CreatedAt: now, ChangedAt: now})
	} else {
		found := false
		for i := range n.Notes {
			note := &n.Notes[i]
			if note.ID != noteID {
				continue
			}
			found = true
			if note.Archived == (action == "archive") || now.Before(note.ChangedAt) {
				return DeviceNotes{}, ErrDeviceNotesConflict
			}
			note.Archived = action == "archive"
			note.ChangedAt = now
			break
		}
		if !found {
			return DeviceNotes{}, ErrDeviceNotesConflict
		}
	}
	n.Revision++
	n.Operations = append(n.Operations, DeviceNoteOperation{ID: operationID, Action: action, NoteID: noteID, Revision: n.Revision, RequestDigest: digest})
	raw, err := json.Marshal(n)
	if err != nil {
		return DeviceNotes{}, err
	}
	if _, err = decodeDeviceNotes(raw, manager, identity, deviceID); err != nil {
		return DeviceNotes{}, err
	}
	if err = ctx.Err(); err != nil {
		return DeviceNotes{}, err
	}
	if err = guard(); err != nil {
		return DeviceNotes{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO device_notes(manager,identity,device_id,body) VALUES(?,?,?,?) ON CONFLICT(manager,identity,device_id) DO UPDATE SET body=excluded.body`, manager, identity, deviceID, raw); err != nil {
		return DeviceNotes{}, err
	}
	if err = guard(); err != nil {
		return DeviceNotes{}, err
	}
	if err = ctx.Err(); err != nil {
		return DeviceNotes{}, err
	}
	if err = tx.Commit(); err != nil {
		return DeviceNotes{}, err
	}
	return n, nil
}
