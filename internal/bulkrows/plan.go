// Package bulkrows provides pure bounded row planning shared by fixed inventory
// adapters. It has no wire registry, source/transport/store access or authority.
// Configs are compile-time adapter policy, never decoded from incoming data.
package bulkrows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

var (
	ErrInvalid  = errors.New("bulk_rows_invalid")
	ErrLimit    = errors.New("bulk_rows_limit")
	ErrCanceled = errors.New("bulk_rows_canceled")
)

// Row adapters must use value-only rows and deterministic, side-effect-free
// callbacks. Plan copies and sorts descriptors; it cannot deep-clone arbitrary
// pointer-bearing T. Both initial users contain strings and scalar values only.
type Config[T any] struct {
	MaxRows           int
	MaxChunkRows      int
	MaxPayloadBytes   int
	MaxChunks         int
	MaxCanonicalBytes uint64
	Domain            string
	Validate          func(T) error
	Less              func(T, T) bool
	Canonical         func(T) []byte
}
type PlanResult[T any] struct {
	Rows           []T
	Boundaries     []int
	CanonicalBytes uint64
	RowsSHA256     string
}

// Plan validates the complete input before sorting, rejects duplicates, then
// computes deterministic bounded chunks. It returns no usable prefix on error.
// Boundaries is {0} for a successful empty scope and ends at len(Rows) otherwise.
func Plan[T any](ctx context.Context, input []T, c Config[T]) (PlanResult[T], error) {
	zero := PlanResult[T]{}
	if ctx == nil || ctx.Err() != nil {
		return zero, ErrCanceled
	}
	if input == nil || c.MaxRows < 1 || c.MaxRows > 100000 || c.MaxChunkRows < 1 || c.MaxChunkRows > c.MaxRows || c.MaxPayloadBytes < 1 || c.MaxPayloadBytes > 1<<20 || c.MaxChunks < 1 || c.MaxChunks > 100000 || c.MaxCanonicalBytes < 1 || c.MaxCanonicalBytes > 64<<20 || len(c.Domain) < 2 || len(c.Domain) > 256 || !strings.HasSuffix(c.Domain, "\x00") || c.Validate == nil || c.Less == nil || c.Canonical == nil {
		return zero, ErrInvalid
	}
	if len(input) > c.MaxRows {
		return zero, ErrLimit
	}
	var total uint64
	for _, row := range input {
		if ctx.Err() != nil {
			return zero, ErrCanceled
		}
		if e := c.Validate(row); e != nil {
			return zero, e
		}
		size := len(c.Canonical(row))
		if size == 0 {
			return zero, ErrInvalid
		}
		if size > c.MaxPayloadBytes || uint64(size) > c.MaxCanonicalBytes-total {
			return zero, ErrLimit
		}
		total += uint64(size)
	}
	rows := append(make([]T, 0, len(input)), input...)
	sort.Slice(rows, func(i, j int) bool { return c.Less(rows[i], rows[j]) })
	if ctx.Err() != nil {
		return zero, ErrCanceled
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(c.Domain))
	boundaries := []int{0}
	start, payload := 0, 0
	var reencodedBytes uint64
	for i, row := range rows {
		if ctx.Err() != nil {
			return zero, ErrCanceled
		}
		if i > 0 && !c.Less(rows[i-1], row) {
			return zero, ErrInvalid
		}
		raw := c.Canonical(row)
		if len(raw) == 0 || len(raw) > c.MaxPayloadBytes || uint64(len(raw)) > c.MaxCanonicalBytes-reencodedBytes {
			return zero, ErrLimit
		}
		reencodedBytes += uint64(len(raw))
		if i-start == c.MaxChunkRows || len(raw) > c.MaxPayloadBytes-payload {
			boundaries = append(boundaries, i)
			start, payload = i, 0
		}
		payload += len(raw)
		_, _ = hash.Write(raw)
	}
	if len(rows) > 0 {
		boundaries = append(boundaries, len(rows))
	}
	if len(boundaries)-1 > c.MaxChunks {
		return zero, ErrLimit
	}
	if reencodedBytes != total {
		return zero, ErrInvalid
	}
	if ctx.Err() != nil {
		return zero, ErrCanceled
	}
	return PlanResult[T]{Rows: rows, Boundaries: boundaries, CanonicalBytes: total, RowsSHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

// Digest hashes already-canonical, already-bounded adapter bytes with its fixed
// domain. Adapters own exact wire field order and shape; no map is marshalled here.
func Digest(domain string, canonical []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}
