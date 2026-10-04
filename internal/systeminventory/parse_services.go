package systeminventory

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

type ServiceSource string

const (
	RuntimeSource   ServiceSource = "runtime"
	UnitFilesSource ServiceSource = "unit_files"
)

type SocketSource string

const (
	TCP4Source SocketSource = "tcp"
	TCP6Source SocketSource = "tcp6"
	UDP4Source SocketSource = "udp"
	UDP6Source SocketSource = "udp6"
)

// ParseServices joins fixed plain, full, no-legend list-units/list-unit-files
// output. Descriptions/presets are discarded; no arbitrary command is executed.
// A unit absent from one complete list gets null for that observation, never an
// invented inactive/disabled state. MainPID remains null (not collected).
func ParseServices(ctx context.Context, runtime, files io.Reader) ([]Service, error) {
	a, e := readBounded(ctx, runtime)
	if e != nil {
		return nil, e
	}
	b, e := readBounded(ctx, files)
	if e != nil {
		return nil, e
	}
	rows := map[string]Service{}
	for _, src := range []struct {
		data    []byte
		runtime bool
	}{{a, true}, {b, false}} {
		seen := map[string]bool{}
		scan := bufio.NewScanner(bytes.NewReader(src.data))
		scan.Buffer(make([]byte, 4096), 64<<10)
		for scan.Scan() {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			line := scan.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			f := strings.Fields(line)
			if src.runtime && len(f) < 4 || !src.runtime && (len(f) < 2 || len(f) > 3) || !validServiceName(f[0]) || seen[f[0]] {
				return nil, ErrInvalidSource
			}
			seen[f[0]] = true
			row := rows[f[0]]
			row.Name = f[0]
			if src.runtime {
				row.Runtime = &ServiceRuntime{f[1], f[2], f[3]}
			} else {
				s := f[1]
				row.Enablement = &s
			}
			if !validService(row) {
				return nil, ErrInvalidSource
			}
			rows[row.Name] = row
			if len(rows) > MaxServiceRows {
				return nil, ErrItemLimit
			}
		}
		if scan.Err() != nil {
			return nil, ErrSourceLimit
		}
	}
	out := make([]Service, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
func readBounded(ctx context.Context, r io.Reader) ([]byte, error) {
	if ctx == nil || r == nil {
		return nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, e := io.ReadAll(io.LimitReader(&contextReader{ctx, r}, MaxRawSourceBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > MaxRawSourceBytes {
		return nil, ErrSourceLimit
	}
	if !utf8.Valid(b) {
		return nil, ErrInvalidSource
	}
	return b, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	n, e := r.r.Read(p)
	if ce := r.ctx.Err(); ce != nil {
		return n, ce
	}
	return n, e
}
