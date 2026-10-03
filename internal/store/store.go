// Package store persists local demo state with SQLite transactions.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/model"
	_ "modernc.org/sqlite"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

var ErrNotFound = errors.New("not found")
var ErrLimit = errors.New("note limit reached")

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return nil, err
	}
	if fi, e := os.Lstat(absolute); e == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("database path must be a regular file")
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	f, err := os.OpenFile(absolute, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err = os.Chmod(absolute, 0600); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: absolute}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, err = db.Exec(q); err != nil {
			return fail(err)
		}
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version > 1 {
		return fail(fmt.Errorf("unsupported database schema version %d", version))
	}
	tx, err := db.Begin()
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	for _, q := range []string{`CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, body TEXT NOT NULL CHECK(json_valid(body)))`, `CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, body TEXT NOT NULL CHECK(json_valid(body)))`, `PRAGMA user_version=1`} {
		if _, err = tx.Exec(q); err != nil {
			return fail(err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Seed(devices []model.Device, cases []model.Case) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, d := range devices {
		b, e := json.Marshal(d)
		if e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT OR IGNORE INTO devices(id,body) VALUES(?,?)", d.ID, string(b)); e != nil {
			return e
		}
	}
	for _, c := range cases {
		b, e := json.Marshal(c)
		if e != nil {
			return e
		}
		if _, e = tx.Exec("INSERT OR IGNORE INTO cases(id,body) VALUES(?,?)", c.ID, string(b)); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) Devices() ([]model.Device, error) {
	rows, err := s.db.Query("SELECT body FROM devices ORDER BY rowid LIMIT 1000")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Device{}
	for rows.Next() {
		var b string
		var d model.Device
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(b), &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) Cases() ([]model.Case, error) {
	rows, err := s.db.Query("SELECT body FROM cases ORDER BY rowid LIMIT 1000")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Case{}
	for rows.Next() {
		var b string
		var c model.Case
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(b), &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) Case(id string) (model.Case, error) {
	var c model.Case
	var b string
	err := s.db.QueryRow("SELECT body FROM cases WHERE id=?", id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	err = json.Unmarshal([]byte(b), &c)
	return c, err
}
func (s *Store) Mutate(id, kind, value string) (model.Case, error) {
	var c model.Case
	if kind != "note" && kind != "status" {
		return c, errors.New("invalid mutation")
	}
	if kind == "status" && value != "open" && value != "investigating" && value != "resolved" {
		return c, errors.New("invalid status")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	var b string
	if err = tx.QueryRow("SELECT body FROM cases WHERE id=?", id).Scan(&b); errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	} else if err != nil {
		return c, err
	}
	if err = json.Unmarshal([]byte(b), &c); err != nil {
		return c, err
	}
	if kind == "status" && c.Status == value {
		return c, nil
	}
	if len(c.Timeline) >= 500 {
		return c, ErrLimit
	}
	now := time.Now().UTC()
	raw := make([]byte, 12)
	if _, err = rand.Read(raw); err != nil {
		return c, err
	}
	eid := hex.EncodeToString(raw)
	event := model.Activity{ID: eid, Time: now, CaseID: id, DeviceID: c.DeviceID}
	if kind == "note" {
		if len(c.Notes) >= 100 {
			return c, ErrLimit
		}
		c.Notes = append(c.Notes, model.Note{ID: eid, Text: value, CreatedAt: now, Author: "Local operator"})
		event.Type = "note"
		event.Title = "Operator note added"
		event.Detail = "Local case note saved. No endpoint action was executed."
	} else {
		c.Status = value
		event.Type = "status"
		event.Title = "Case marked " + value
		event.Detail = "Operator workflow state changed. This does not assert that endpoint health changed."
	}
	c.Timeline = append(c.Timeline, event)
	c.UpdatedAt = now
	body, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	if _, err = tx.Exec("UPDATE cases SET body=? WHERE id=?", string(body), id); err != nil {
		return c, err
	}
	if err = tx.Commit(); err != nil {
		return c, err
	}
	return c, nil
}
