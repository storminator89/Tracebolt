package packageplan

import (
	"bytes"
	"context"
	"strings"

	"localrmm/internal/actionpermit"
	"localrmm/internal/debianversion"
)

const (
	MaxHookBytes     = 256 << 10
	MaxConfigBytes   = 128 << 10
	MaxConfigLines   = 2048
	MaxHookLineBytes = 8192
	MaxOperations    = 2 * MaxPackages
)

type Operation struct {
	Name            string
	OldVersion      string
	OldArchitecture string
	OldMultiArch    string
	NewVersion      string
	NewArchitecture string
	NewMultiArch    string
	Action          string // unpack or configure
	ArchivePath     string // only unpack; never an executable/command argument
}

// Hook is a parsed observation, not a trusted execution boundary. Configuration
// directives are not interpreted as policy. Their exact ordered bytes are hashed.
type Hook struct {
	ConfigDigest string
	Operations   []Operation
}

func hexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
func validEscaped(s string, key bool) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) || !hexByte(s[i+1]) || !hexByte(s[i+2]) {
				return false
			}
			i += 2
			continue
		}
		if c <= 32 || c >= 127 || key && (c == '=' || c == '"') {
			return false
		}
	}
	return true
}
func canonicalMultiArch(s string) string {
	if s == "none" {
		return "no"
	}
	return s
}

// ParseHook accepts a deliberately conservative v3 subset with complete final
// LF framing. The config digest excludes "VERSION 3\n" and the terminating
// empty line, and includes the LF after every directive. Duplicated list entries,
// their order, escapes, literal plus signs and equals signs in values survive.
// Valid protocol work outside this narrow subset is rejected, never ignored.
func ParseHook(ctx context.Context, raw []byte) (Hook, error) {
	bad := func() (Hook, error) { return Hook{}, ErrProtocol }
	if ctx == nil {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return Hook{}, err
	}
	if len(raw) == 0 || len(raw) > MaxHookBytes || raw[len(raw)-1] != '\n' || bytes.ContainsAny(raw, "\x00\r") || !bytes.HasPrefix(raw, []byte("VERSION 3\n")) {
		return bad()
	}
	offset := len("VERSION 3\n")
	configStart := offset
	configLines := 0
	for {
		if err := ctx.Err(); err != nil {
			return Hook{}, err
		}
		end := bytes.IndexByte(raw[offset:], '\n')
		if end < 0 || end > MaxHookLineBytes {
			return bad()
		}
		line := string(raw[offset : offset+end])
		if line == "" {
			break
		}
		configLines++
		if configLines > MaxConfigLines || offset+end+1-configStart > MaxConfigBytes {
			return bad()
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !validEscaped(key, true) || !validEscaped(value, false) {
			return bad()
		}
		offset += end + 1
	}
	out := Hook{ConfigDigest: actionpermit.Digest(raw[configStart:offset]), Operations: []Operation{}}
	offset++
	for offset < len(raw) {
		if err := ctx.Err(); err != nil {
			return Hook{}, err
		}
		end := bytes.IndexByte(raw[offset:], '\n')
		if end <= 0 || end > MaxHookLineBytes || len(out.Operations) >= MaxOperations {
			return bad()
		}
		fields := strings.Split(string(raw[offset:offset+end]), " ")
		if len(fields) != 9 || !validName(fields[0]) || !validArch(fields[2]) || fields[2] != fields[6] || fields[4] != "<" {
			return bad()
		}
		oldMA, newMA := canonicalMultiArch(fields[3]), canonicalMultiArch(fields[7])
		if !validMultiArch(oldMA) || !validMultiArch(newMA) {
			return bad()
		}
		order, err := (debianversion.Comparator{}).Compare(ctx, fields[1], fields[5])
		if err != nil || order != -1 {
			if err := ctx.Err(); err != nil {
				return Hook{}, err
			}
			return bad()
		}
		op := Operation{Name: fields[0], OldVersion: fields[1], OldArchitecture: fields[2], OldMultiArch: oldMA, NewVersion: fields[5], NewArchitecture: fields[6], NewMultiArch: newMA}
		if fields[8] == "**CONFIGURE**" {
			op.Action = "configure"
		} else {
			if !validPath(fields[8], true) || !strings.HasSuffix(fields[8], ".deb") {
				return bad()
			}
			op.Action = "unpack"
			op.ArchivePath = fields[8]
		}
		out.Operations = append(out.Operations, op)
		offset += end + 1
	}
	if len(out.Operations) == 0 {
		return bad()
	}
	return out, nil
}

// ObservedArchive is trusted future-adapter input, NEVER a hook claim or incoming
// request DTO. SHA256 and Size must be computed from protected actual bytes by
// that adapter. This pure core does not open/hash archives, inspect ownership,
// authenticate indexes, or prevent replacement between hashing and dpkg use.
type ObservedArchive struct {
	Path   string
	SHA256 string
	Size   uint64
}

// Match compares supplied observations to a fresh inert plan. Success means
// equality only: NOT approval, admission, actual archive validation, clean dpkg,
// safe hooks, native acceptance, or proof that no other effects can occur.
// One unpack and one later configure are required for each selected name+arch;
// unknown, repeated, omitted and extra work fail closed. Calls are stateless,
// not a substitute for durable consumption across repeated hook invocations.
func Match(ctx context.Context, p Plan, now int64, raw []byte, archives []ObservedArchive) error {
	if err := CheckFresh(ctx, p, now); err != nil {
		return err
	}
	if len(archives) != len(p.Packages) {
		return ErrMismatch
	}
	hook, err := ParseHook(ctx, raw)
	if err != nil {
		return err
	}
	if hook.ConfigDigest != p.Evidence.ConfigDigest || len(hook.Operations) != 2*len(p.Packages) {
		return ErrMismatch
	}
	observed := make(map[string]ObservedArchive, len(archives))
	for _, a := range archives {
		if !validPath(a.Path, true) || !strings.HasSuffix(a.Path, ".deb") || !actionpermit.ValidDigest(a.SHA256) || a.Size == 0 || a.Size > MaxArchiveBytes {
			return ErrMismatch
		}
		if _, exists := observed[a.Path]; exists {
			return ErrMismatch
		}
		observed[a.Path] = a
	}
	wanted := make(map[string]Upgrade, len(p.Packages))
	stages := make(map[string]int, len(p.Packages))
	for _, u := range p.Packages {
		wanted[u.Name+":"+u.Architecture] = u
	}
	for _, op := range hook.Operations {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := op.Name + ":" + op.OldArchitecture
		u, ok := wanted[key]
		if !ok || op.OldVersion != u.From.Version || op.NewVersion != u.To.Version || op.NewArchitecture != u.Architecture || op.OldMultiArch != u.From.MultiArch || op.NewMultiArch != u.To.MultiArch {
			return ErrMismatch
		}
		if op.Action == "unpack" {
			if stages[key] != 0 {
				return ErrMismatch
			}
			a, ok := observed[op.ArchivePath]
			if !ok || a.SHA256 != u.Archive.SHA256 || a.Size != u.Archive.Size {
				return ErrMismatch
			}
			delete(observed, op.ArchivePath)
			stages[key] = 1
		} else {
			if stages[key] != 1 {
				return ErrMismatch
			}
			stages[key] = 2
		}
	}
	if len(observed) != 0 {
		return ErrMismatch
	}
	for key := range wanted {
		if stages[key] != 2 {
			return ErrMismatch
		}
	}
	return nil
}
