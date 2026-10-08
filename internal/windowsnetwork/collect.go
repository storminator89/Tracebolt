package windowsnetwork

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"time"
)

const collectionBudget = 5 * time.Second

// ErrInsufficientBuffer is the injected reader's bounded-resize signal.
var ErrInsufficientBuffer = errors.New("windows_network_resize")
var errBuffer = ErrInsufficientBuffer

type tableSpec struct {
	protocol, family string
	af, class        uint32
	stride           int
}

var tables = [...]tableSpec{
	{"tcp", "ipv4", 2, 5, 24}, // TCP_TABLE_OWNER_PID_ALL
	{"tcp", "ipv6", 23, 5, 56},
	{"udp", "ipv4", 2, 1, 12}, // UDP_TABLE_OWNER_PID
	{"udp", "ipv6", 23, 1, 28},
}

// query reports API output size. Buffer is at most MaxTableBytes; nil is a size
// probe. It is synchronous: an in-flight OS call cannot be forcibly canceled.
type query func(tableSpec, []byte) (uint32, error)
type tableResult struct {
	rows                []Endpoint
	complete, available bool
	err                 error
}

// TableReader is a synthetic source seam for the production parser. protocol is
// tcp/udp and family is ipv4/ipv6. A nil buffer probes size; return the required
// size with ErrInsufficientBuffer. On success write the Windows OWNER_PID table
// bytes (DWORD count, then rows) and return the used size. Never resize buffer.
type TableReader func(protocol, family string, buffer []byte) (uint32, error)

// CollectWithReader runs the same bounded collection path using an injected
// reader. It is intended for source/pipeline fixtures with no native reads.
func CollectWithReader(ctx context.Context, generation, grant string, capturedAt time.Time, read TableReader) (Snapshot, error) {
	if read == nil {
		return Snapshot{}, ErrInvalid
	}
	return collectUsing(ctx, generation, grant, capturedAt, func(s tableSpec, b []byte) (uint32, error) { return read(s.protocol, s.family, b) })
}

// Collect requires an active, identity-bound local grant checked by its caller.
// capturedAt is the original UTC capture, never refreshed by wire-budget fitting
// or retry. No native call occurs before validating these arguments.
func Collect(ctx context.Context, generation, grant string, capturedAt time.Time) (Snapshot, error) {
	return collectUsing(ctx, generation, grant, capturedAt, queryNative)
}
func collectUsing(ctx context.Context, generation, grant string, capturedAt time.Time, q query) (Snapshot, error) {
	if ctx == nil || q == nil || !validGeneration(generation) || !hex(grant, 32) || !validTime(capturedAt) {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	bounded, cancel := context.WithTimeout(ctx, collectionBudget)
	defer cancel()
	s := Snapshot{SchemaVersion: SchemaVersion, Scope: Scope, GrantID: grant, GenerationID: generation, CollectedAt: capturedAt, Quality: "observed", CountExact: true, Rows: []Endpoint{}}
	successes, denied := 0, 0
	for _, spec := range tables {
		r := readTable(bounded, spec, q)
		if r.available {
			successes++
		}
		if errors.Is(r.err, ErrDenied) {
			denied++
		}
		if !r.complete {
			s.CountExact = false
		}
		s.ObservedCount += uint32(len(r.rows))
		// Retain at most 64 across completed tables. Discarded rows still contribute
		// to observedCount. Sorting does not depend on volatile native row order.
		s.Rows = append(s.Rows, r.rows...)
		sort.Slice(s.Rows, func(i, j int) bool { return compareRows(s.Rows[i], s.Rows[j]) < 0 })
		if len(s.Rows) > MaxRows {
			s.Rows = s.Rows[:MaxRows]
		}
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if !s.CountExact {
		s.Quality = "partial"
		if successes == 0 {
			s.Quality = "unavailable"
			if denied == len(tables) {
				s.Quality = "denied"
			}
		}
	}
	s.Truncated = int(s.ObservedCount) > len(s.Rows)
	return fit(s, MaxBytes)
}
func readTable(ctx context.Context, spec tableSpec, q query) tableResult {
	var buf []byte
	for attempt := 0; attempt < MaxTableCalls; attempt++ {
		if e := ctx.Err(); e != nil {
			return tableResult{err: e}
		}
		size, e := q(spec, buf)
		if e2 := ctx.Err(); e2 != nil {
			return tableResult{err: e2}
		}
		if e == nil {
			if size < 4 || size > uint32(len(buf)) {
				return tableResult{err: ErrUnavailable}
			}
			return parseTable(ctx, spec, buf[:size])
		}
		if !errors.Is(e, errBuffer) {
			return tableResult{err: e}
		}
		if size < 4 || size > MaxTableBytes || int(size) <= len(buf) {
			return tableResult{err: ErrBounds}
		}
		if attempt+1 < MaxTableCalls {
			buf = make([]byte, int(size))
		}
	}
	return tableResult{err: ErrBounds}
}
func parseTable(ctx context.Context, spec tableSpec, buf []byte) tableResult {
	if len(buf) < 4 || len(buf) > MaxTableBytes || spec.stride <= 0 {
		return tableResult{err: ErrUnavailable}
	}
	count := binary.LittleEndian.Uint32(buf[:4])
	// Division before multiplication prevents malformed header overflow on 386.
	if uint64(count) > uint64((len(buf)-4)/spec.stride) {
		return tableResult{err: ErrUnavailable}
	}
	// pdwSize describes allocated/estimated table size, not a guarantee of exact
	// used length after a table shrinks. Count is authoritative after the fit
	// check: parse exactly those rows and never expose unused allocation bytes.
	n := int(count)
	if n > MaxRowsPerTable {
		n = MaxRowsPerTable
	}
	r := tableResult{rows: make([]Endpoint, 0, n), available: true}
	for i := 0; i < n; i++ {
		if e := ctx.Err(); e != nil {
			r.err = e
			return r
		}
		row, e := parseRow(spec, buf[4+i*spec.stride:4+(i+1)*spec.stride])
		if e != nil {
			r.err = e
			return r
		}
		r.rows = append(r.rows, row)
	}
	r.complete = int(count) == n
	if !r.complete {
		r.err = ErrBounds
	}
	return r
}
func ip4(b []byte) string { return netip.AddrFrom4([4]byte(b[:4])).String() }
func ip6(b, scope []byte) string {
	a := netip.AddrFrom16([16]byte(b[:16]))
	// IP Helper OWNER_PID documents scopes in network byte order, unlike PID,
	// state and table count. Do not use a host-endian scope or interface name.
	if n := binary.BigEndian.Uint32(scope[:4]); n != 0 {
		a = a.WithZone(strconv.FormatUint(uint64(n), 10))
	}
	return a.String()
}
func parseRow(spec tableSpec, b []byte) (Endpoint, error) {
	if len(b) != spec.stride {
		return Endpoint{}, ErrUnavailable
	}
	r := Endpoint{Protocol: spec.protocol, Family: spec.family}
	var state uint32
	switch {
	case spec.protocol == "tcp" && spec.family == "ipv4" && len(b) == 24:
		state = binary.LittleEndian.Uint32(b[0:4])
		r.LocalAddress = ip4(b[4:8])
		r.LocalPort = binary.BigEndian.Uint16(b[8:10])
		remote, port := ip4(b[12:16]), binary.BigEndian.Uint16(b[16:18])
		r.RemoteAddress = &remote
		r.RemotePort = &port
		r.PID = binary.LittleEndian.Uint32(b[20:24])
	case spec.protocol == "tcp" && spec.family == "ipv6" && len(b) == 56:
		r.LocalAddress = ip6(b[:16], b[16:20])
		r.LocalPort = binary.BigEndian.Uint16(b[20:22])
		remote, port := ip6(b[24:40], b[40:44]), binary.BigEndian.Uint16(b[44:46])
		r.RemoteAddress = &remote
		r.RemotePort = &port
		state = binary.LittleEndian.Uint32(b[48:52])
		r.PID = binary.LittleEndian.Uint32(b[52:56])
	case spec.protocol == "udp" && spec.family == "ipv4" && len(b) == 12:
		r.LocalAddress = ip4(b[:4])
		r.LocalPort = binary.BigEndian.Uint16(b[4:6])
		r.PID = binary.LittleEndian.Uint32(b[8:12])
	case spec.protocol == "udp" && spec.family == "ipv6" && len(b) == 28:
		r.LocalAddress = ip6(b[:16], b[16:20])
		r.LocalPort = binary.BigEndian.Uint16(b[20:22])
		r.PID = binary.LittleEndian.Uint32(b[24:28])
	default:
		return Endpoint{}, ErrUnavailable
	}
	if r.Protocol == "tcp" {
		states := [...]string{"", "closed", "listen", "syn-sent", "syn-received", "established", "fin-wait-1", "fin-wait-2", "close-wait", "closing", "last-ack", "time-wait", "delete-tcb"}
		if state == 0 || state >= uint32(len(states)) {
			return Endpoint{}, ErrUnavailable
		}
		s := states[state]
		r.State = &s
		// Microsoft marks a listener's remote address/port meaningless. Never
		// turn those undefined DWORDs into an apparent remote peer.
		if s == "listen" {
			r.RemoteAddress = nil
			r.RemotePort = nil
		}
	}
	if !validEndpoint(r) {
		return Endpoint{}, ErrUnavailable
	}
	return r, nil
}
