package overviewgeneration

import (
	"context"
	"encoding/json"
	"hash"
	"localrmm/internal/completeoverview"
)

// Validator is single-owner and streaming. Every error is terminal. Copies share
// state. It retains only bounded counters, a numeric identity and hash state.
type Validator struct{ *validatorState }
type validatorState struct {
	sectionBase                                    uint64
	ctx                                            context.Context
	manifest                                       Manifest
	manifestSHA256                                 string
	rows                                           hash.Hash
	next                                           uint32
	observed, rowBytes, wireBytes, sectionRowBytes uint64
	coverage                                       completeoverview.FieldCoverage
	previous                                       string
	last                                           uint32
	failure                                        error
	closed                                         bool
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
	_, p, b := emptyBytes(m)
	if m.Section == "volumes" {
		p = b
	}
	return &Validator{&validatorState{ctx: ctx, manifest: cloneManifest(m), manifestSHA256: md, rows: newRowsHash(), wireBytes: uint64(len(raw)), sectionBase: p}}, nil
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
	if c.Section != m.Section || c.GenerationID != m.GenerationID || c.ManifestSHA256 != v.manifestSHA256 || c.ChunkCount != m.ChunkCount || c.Ordinal != v.next || c.RowOffset != v.observed || c.PreviousSHA256 != v.previous || v.next >= m.ChunkCount {
		return v.fail(ErrInvalid)
	}
	if uint64(len(c.Items)) > m.ObservedCount-v.observed || v.observed != 0 && v.last >= rowIdentity(c.Items[0]) {
		return v.fail(ErrInvalid)
	}
	raw, _ := json.Marshal(c)
	if uint64(len(raw)) > MaxCanonicalWireBytes-v.wireBytes {
		return v.fail(ErrLimit)
	}
	for _, r := range c.Items {
		if v.ctx.Err() != nil {
			return v.fail(ErrCanceled)
		}
		b := canonicalRow(r)
		if uint64(len(b)) > m.CanonicalRowBytes-v.rowBytes {
			return v.fail(ErrInvalid)
		}
		v.rowBytes += uint64(len(b))
		v.observed++
		var source []byte
		if r.Process != nil {
			source, _ = json.Marshal(*r.Process)
			addCoverage(&v.coverage, r.Process.Observation.Status)
		} else {
			source, _ = json.Marshal(*r.Volume)
			addCoverage(&v.coverage, r.Volume.Measurement.Status)
		}
		v.sectionRowBytes += uint64(len(source))
		if !coverageWithin(v.coverage, m.SelectedMeta().FieldCoverage) || v.sectionBytes() > m.CanonicalSectionBytes {
			return v.fail(ErrInvalid)
		}
		_, _ = v.rows.Write(b)
	}
	v.wireBytes += uint64(len(raw))
	v.next++
	v.previous = c.SHA256
	v.last = rowIdentity(c.Items[len(c.Items)-1])
	if v.ctx.Err() != nil {
		return v.fail(ErrCanceled)
	}
	return nil
}
func (v *Validator) sectionBytes() uint64 {
	return v.sectionBase + v.sectionRowBytes + commaBytes(v.observed)
}

// Finish confirms exactly the selected section. Sibling metadata and original
// whole-snapshot size are capture context, not receipts for omitted sibling rows.
func (v *Validator) Finish() (Complete, error) {
	if err := v.ready(); err != nil {
		return Complete{}, err
	}
	m := v.manifest
	if v.next != m.ChunkCount || v.observed != m.ObservedCount || v.rowBytes != m.CanonicalRowBytes || v.sectionBytes() != m.CanonicalSectionBytes || v.coverage != m.SelectedMeta().FieldCoverage || hashHex(v.rows) != m.RowsSHA256 {
		return Complete{}, v.fail(ErrIncomplete)
	}
	v.closed = true
	return Complete{manifest: cloneManifest(m), manifestSHA256: v.manifestSHA256, lastSHA256: v.previous, wireBytes: v.wireBytes, valid: true}, nil
}
func coverageValues(c completeoverview.FieldCoverage) [7]uint64 {
	return [7]uint64{c.Observed, c.Denied, c.Exited, c.Invalid, c.Unsupported, c.Unavailable, c.NotApplicable}
}
func coverageWithin(a, b completeoverview.FieldCoverage) bool {
	x, y := coverageValues(a), coverageValues(b)
	for i := range x {
		if x[i] > y[i] {
			return false
		}
	}
	return true
}
func coverageCount(c completeoverview.FieldCoverage) uint64 {
	var n uint64
	for _, x := range coverageValues(c) {
		n += x
	}
	return n
}
func addCoverage(c *completeoverview.FieldCoverage, s completeoverview.Status) {
	switch s {
	case completeoverview.Observed:
		c.Observed++
	case completeoverview.Denied:
		c.Denied++
	case completeoverview.Exited:
		c.Exited++
	case completeoverview.Invalid:
		c.Invalid++
	case completeoverview.Unsupported:
		c.Unsupported++
	case completeoverview.Unavailable:
		c.Unavailable++
	case completeoverview.NotApplicable:
		c.NotApplicable++
	}
}
