// Package linuxcveprogress stores bounded, private CVE assessment checkpoints.
// The caller binds each opaque JSON payload to its inventory and feed inputs.
// This package does not collect inventory, evaluate CVEs, or contact a network.
package linuxcveprogress

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	SlotCount        = 4
	MaxPayloadBytes  = 240 << 10
	MaxEnvelopeBytes = 256 << 10
	checkpointSchema = "tracebolt.linux-cve-progress.v1"
)

var (
	ErrInvalid     = errors.New("linux_cve_progress_invalid")
	ErrCorrupt     = errors.New("linux_cve_progress_corrupt")
	ErrIO          = errors.New("linux_cve_progress_io")
	ErrUnsafe      = errors.New("linux_cve_progress_unsafe")
	ErrLocked      = errors.New("linux_cve_progress_locked")
	ErrUnsupported = errors.New("linux_cve_progress_unsupported")
	ErrClosed      = errors.New("linux_cve_progress_closed")
	ErrUncertain   = errors.New("linux_cve_progress_commit_uncertain")
)

var slotNames = [SlotCount]string{"slot-0.json", "slot-1.json", "slot-2.json", "slot-3.json"}

type storage interface {
	read(string) ([]byte, error)
	replace(string, []byte) error
	close() error
}

// Cache holds an exclusive lifetime lock on one dedicated checkpoint directory.
// It must not share that directory with the feed cache or other runtime state.
type Cache struct {
	mu       sync.Mutex
	disk     storage
	closed   bool
	poisoned bool
}

// Open opens a private 0700 directory, creating only the final path component
// beneath an existing private parent. Symlinks anywhere in the path are rejected.
// Existing unsafe permissions or corrupt checkpoints are never repaired.
func Open(path string) (*Cache, error) {
	disk, err := openStorage(path)
	if err != nil {
		return nil, err
	}
	return &Cache{disk: disk}, nil
}

func (c *Cache) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.disk == nil {
		return nil
	}
	return c.disk.close()
}

func (c *Cache) usable() error {
	if c.closed || c.disk == nil {
		return ErrClosed
	}
	if c.poisoned {
		return ErrUncertain
	}
	return nil
}

// Load returns an independent copy of the exact payload bytes for key, or nil
// when that exact binding is absent or has reached its original expiry. Reads
// never extend expiry or update timestamps. Every slot is revalidated first;
// corruption in another slot cannot silently be hidden by a cache hit or miss.
func (c *Cache) Load(key string, now time.Time) ([]byte, error) {
	if c == nil {
		return nil, ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return nil, err
	}
	if !validKey(key) || !validTime(now) {
		return nil, ErrInvalid
	}
	slots, err := c.scan(now)
	if err != nil {
		return nil, err
	}
	for _, e := range slots {
		if e != nil && e.Key == key && now.Before(e.ExpiresAt) {
			return bytes.Clone(e.Data), nil
		}
	}
	return nil, nil
}

// Save durably replaces the checkpoint for exactly key. expiresAt is the
// inventory's original retention deadline, not a new TTL. Existing bindings
// retain their CreatedAt and ExpiresAt; time rollback and expiry extension fail.
// New bindings use the lowest empty slot, then an expired slot, then the oldest
// UpdatedAt slot. Ties use the lowest slot number. Payloads are valid JSON but
// otherwise opaque, and their bytes (including whitespace) are preserved.
// An uncertain commit permanently blocks this instance until Close and reopen.
func (c *Cache) Save(key string, expiresAt, now time.Time, raw []byte) error {
	if c == nil {
		return ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return err
	}
	if !validKey(key) || !validTime(expiresAt) || !validTime(now) || !now.Before(expiresAt) || len(raw) == 0 || len(raw) > MaxPayloadBytes || !utf8.Valid(raw) || !json.Valid(raw) {
		return ErrInvalid
	}
	slots, err := c.scan(now)
	if err != nil {
		return err
	}
	selected := -1
	e := &envelope{Schema: checkpointSchema, Key: key, CreatedAt: now.UTC(), UpdatedAt: now.UTC(), ExpiresAt: expiresAt.UTC(), Data: bytes.Clone(raw)}
	for i, prior := range slots {
		if prior != nil && prior.Key == key {
			if !prior.ExpiresAt.Equal(expiresAt) || now.Before(prior.UpdatedAt) {
				return ErrInvalid
			}
			e.CreatedAt = prior.CreatedAt
			selected = i
			break
		}
	}
	if selected < 0 {
		selected = selectSlot(slots, now)
	}
	encoded, err := encode(e)
	if err != nil {
		return err
	}
	if err = c.disk.replace(slotNames[selected], encoded); errors.Is(err, ErrUncertain) {
		c.poisoned = true
	}
	return err
}

func selectSlot(slots [SlotCount]*envelope, now time.Time) int {
	for i, e := range slots {
		if e == nil {
			return i
		}
	}
	selected := 0
	for i := 1; i < len(slots); i++ {
		expired, selectedExpired := !now.Before(slots[i].ExpiresAt), !now.Before(slots[selected].ExpiresAt)
		if expired && !selectedExpired || expired == selectedExpired && slots[i].UpdatedAt.Before(slots[selected].UpdatedAt) {
			selected = i
		}
	}
	return selected
}

func (c *Cache) scan(now time.Time) ([SlotCount]*envelope, error) {
	var slots [SlotCount]*envelope
	keys := make(map[string]bool, SlotCount)
	for i, name := range slotNames {
		raw, err := c.disk.read(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return slots, err
		}
		e, err := decode(raw, now)
		if err != nil {
			return slots, err
		}
		if keys[e.Key] {
			return slots, ErrCorrupt
		}
		keys[e.Key] = true
		slots[i] = e
	}
	return slots, nil
}

// Metadata uses a canonical JSON prefix, followed by the exact JSON payload.
// This avoids base64 expansion while accepting the full 240 KiB payload budget.
// The digest binds all metadata and payload bytes; it is an integrity check,
// not authentication against another process running as the owning user.
type envelope struct {
	Schema    string          `json:"schema"`
	Key       string          `json:"key"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
	SHA256    string          `json:"sha256"`
	Data      json.RawMessage `json:"data"`
}

type header struct {
	Schema    string    `json:"schema"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	SHA256    string    `json:"sha256"`
}

func prefix(e *envelope, checksum string) ([]byte, error) {
	raw, err := json.Marshal(header{e.Schema, e.Key, e.CreatedAt, e.UpdatedAt, e.ExpiresAt, checksum})
	if err != nil {
		return nil, ErrInvalid
	}
	return append(raw[:len(raw)-1], []byte(`,"data":`)...), nil
}

func digest(e *envelope) string {
	p, _ := prefix(e, "") // Timestamps have already been validated.
	h := sha256.New()
	_, _ = h.Write(p)
	_, _ = h.Write(e.Data)
	return hex.EncodeToString(h.Sum(nil))
}

func encode(e *envelope) ([]byte, error) {
	e.SHA256 = digest(e)
	p, err := prefix(e, e.SHA256)
	if err != nil || len(p)+len(e.Data)+1 > MaxEnvelopeBytes {
		return nil, ErrInvalid
	}
	p = append(p, e.Data...)
	p = append(p, '}')
	// The envelope adds one nesting level to the payload. Check the combined
	// document too so a maximum-depth payload cannot produce an unreadable save.
	if !utf8.Valid(p) || !json.Valid(p) {
		return nil, ErrInvalid
	}
	return p, nil
}

func decode(raw []byte, now time.Time) (*envelope, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes || !utf8.Valid(raw) {
		return nil, ErrCorrupt
	}
	var e envelope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF || e.Schema != checkpointSchema || !validKey(e.Key) || !validKey(e.SHA256) || !validTime(e.CreatedAt) || !validTime(e.UpdatedAt) || !validTime(e.ExpiresAt) || e.UpdatedAt.Before(e.CreatedAt) || !e.UpdatedAt.Before(e.ExpiresAt) || now.Before(e.UpdatedAt) {
		return nil, ErrCorrupt
	}
	p, err := prefix(&e, e.SHA256)
	// Canonical metadata rejects duplicate members, reordered/unknown fields,
	// noncanonical timestamps, and trailing documents without interpreting Data.
	if err != nil || len(raw) <= len(p) || !bytes.HasPrefix(raw, p) || raw[len(raw)-1] != '}' {
		return nil, ErrCorrupt
	}
	e.Data = bytes.Clone(raw[len(p) : len(raw)-1])
	if len(e.Data) == 0 || len(e.Data) > MaxPayloadBytes || !json.Valid(e.Data) || digest(&e) != e.SHA256 {
		return nil, ErrCorrupt
	}
	return &e, nil
}

func validKey(key string) bool {
	if len(key) != sha256.Size*2 {
		return false
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validTime(t time.Time) bool {
	year := t.UTC().Year()
	return !t.IsZero() && year >= 1970 && year <= 9999
}
