package fullinventory

import (
	"context"
	"encoding/json"
	"hash"
	"localrmm/internal/linuxpackages"
)

// Validator is a single-owner streaming state machine. Add accepts exactly the
// next chunk once. Every error is terminal; restart/retry policy belongs to the
// staging owner, which must never promote a failed or incomplete generation.
// No rows are retained. Copies of the handle share the entire state, including
// counters, hash and terminal status. It is not safe for concurrent use.
type Validator struct {
	*validatorState
}

type validatorState struct {
	ctx                                      context.Context
	manifest                                 Manifest
	manifestSHA256                           string
	rows                                     hash.Hash
	next                                     uint32
	observed, installed, rowBytes, wireBytes uint64
	previous                                 string
	last                                     linuxpackages.PackageRow
	failure                                  error
	closed                                   bool
}

func NewValidator(ctx context.Context, m Manifest) (*Validator, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCanceled
	}
	md, err := ManifestDigest(m)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(m)
	return &Validator{validatorState: &validatorState{ctx: ctx, manifest: cloneManifest(m), manifestSHA256: md, rows: newRowsHash(), wireBytes: uint64(len(raw))}}, nil
}
func (v *Validator) fail(err error) error { v.failure = err; return err }
func (v *Validator) ready() error {
	if v == nil || v.validatorState == nil || v.rows == nil || v.ctx == nil {
		return ErrInvalid
	}
	if v.failure != nil {
		return v.failure
	}
	if v.closed {
		return ErrClosed
	}
	if v.ctx.Err() != nil {
		return v.fail(ErrCanceled)
	}
	return nil
}
func (v *Validator) Add(c Chunk) error {
	if err := v.ready(); err != nil {
		return err
	}
	if err := ValidateChunk(c); err != nil {
		return v.fail(err)
	}
	m := v.manifest
	if c.GenerationID != m.GenerationID || c.ManifestSHA256 != v.manifestSHA256 ||
		c.ChunkCount != m.ChunkCount || c.Ordinal != v.next || c.RowOffset != v.observed ||
		c.PreviousSHA256 != v.previous || v.next >= m.ChunkCount {
		return v.fail(ErrInvalid)
	}
	if uint64(len(c.Items)) > m.ObservedCount-v.observed {
		return v.fail(ErrInvalid)
	}
	if v.observed != 0 && !rowLess(v.last, c.Items[0]) {
		return v.fail(ErrInvalid)
	}
	raw, _ := json.Marshal(c)
	if uint64(len(raw)) > MaxCanonicalWireBytes-v.wireBytes {
		return v.fail(ErrLimit)
	}
	for _, p := range c.Items {
		if v.ctx.Err() != nil {
			return v.fail(ErrCanceled)
		}
		b := canonicalRow(p)
		if uint64(len(b)) > m.CanonicalRowBytes-v.rowBytes {
			return v.fail(ErrInvalid)
		}
		v.rowBytes += uint64(len(b))
		v.observed++
		if p.InstallState == "installed" {
			v.installed++
		}
		if v.installed > m.InstalledCount {
			return v.fail(ErrInvalid)
		}
		_, _ = v.rows.Write(b)
	}
	v.wireBytes += uint64(len(raw))
	v.next++
	v.previous = c.SHA256
	// Keep only the identity, not a reference to any row slice or source pointers.
	last := c.Items[len(c.Items)-1]
	v.last = linuxpackages.PackageRow{Name: last.Name, Architecture: last.Architecture}
	if v.ctx.Err() != nil {
		return v.fail(ErrCanceled)
	}
	return nil
}

// Finish returns only a full consistency receipt. A premature Finish is a
// terminal incomplete failure, including zero received chunks for a nonempty
// manifest. Callers must not translate any failure into zero-CVE/update claims.
func (v *Validator) Finish() (Complete, error) {
	if err := v.ready(); err != nil {
		return Complete{}, err
	}
	m := v.manifest
	if v.next != m.ChunkCount || v.observed != m.ObservedCount || v.installed != m.InstalledCount ||
		v.rowBytes != m.CanonicalRowBytes || hashHex(v.rows) != m.RowsSHA256 {
		return Complete{}, v.fail(ErrIncomplete)
	}
	v.closed = true
	return Complete{manifest: cloneManifest(m), manifestSHA256: v.manifestSHA256, lastSHA256: v.previous,
		wireBytes: v.wireBytes, valid: true}, nil
}
