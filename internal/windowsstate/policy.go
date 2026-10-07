// Package windowsstate provides a fail-closed, handle-relative Windows local
// store. Source and in-memory fixture tests are not native lifecycle acceptance.
package windowsstate

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrUnsupported = errors.New("protected Windows state is unavailable on this platform")
	ErrPolicy      = errors.New("protected Windows state policy rejected")
	ErrIntegrity   = errors.New("protected Windows state integrity check failed")
	ErrStorage     = errors.New("protected Windows state storage failed; handle is poisoned")
	ErrPoisoned    = errors.New("protected Windows state handle is poisoned")
	ErrClosed      = errors.New("protected Windows state handle is closed")
)

const (
	maxFileBytes      int64  = 16 << 20
	maxManifestBytes  int64  = 64 << 10
	maxNames                 = 32
	maxDirectories           = 4
	systemSID                = "S-1-5-18"
	administratorsSID        = "S-1-5-32-544"
	fileAllAccess     uint32 = 0x001f01ff
)

// Options is a fixed store schema, bound into its durable manifest. Create is
// create-only: an existing directory, even empty, is never adopted. A caller
// must obtain any required authorization before invoking creation or writes.
// Names and Directories must be disjoint canonical lowercase leaf names.
// MaxBytes is a per-file limit, in (0, 16 MiB].
type Options struct {
	RuntimeSID string
	// InstallerOnly selects an explicit SYSTEM/Administrators-only schema.
	// RuntimeSID must be empty; it cannot be combined with child runtime stores.
	InstallerOnly bool
	Names         []string
	Directories   []string
	LockName      string
	TempName      string
	MaxBytes      int64
	Create        bool
}

func validateOptions(o Options) error {
	if (!o.InstallerOnly && !validRuntimeSID(o.RuntimeSID) || o.InstallerOnly && o.RuntimeSID != "") || o.MaxBytes <= 0 || o.MaxBytes > maxFileBytes || len(o.Names) == 0 || len(o.Names) > maxNames || len(o.Directories) > maxDirectories {
		return ErrPolicy
	}
	seen := map[string]bool{}
	names := append(append(append([]string{}, o.Names...), o.Directories...), o.LockName, o.TempName)
	for _, name := range names {
		if !validName(name) || seen[name] {
			return ErrPolicy
		}
		seen[name] = true
	}
	return nil
}

func validRuntimeSID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 9 || strings.Join(parts[:4], "-") != "S-1-5-80" {
		return false
	}
	nonzero := false
	for _, p := range parts[4:] {
		n, e := strconv.ParseUint(p, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != p {
			return false
		}
		nonzero = nonzero || n != 0
	}
	return nonzero
}

// Conservative lexical policy deliberately excludes DOS aliases, non-ASCII
// paths, environment expansion, extended/device/UNC paths, and 8.3 names.
func validComponent(s string) bool {
	if len(s) == 0 || len(s) > 100 || s == "." || s == ".." || s[0] == ' ' || s[len(s)-1] == ' ' || s[len(s)-1] == '.' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ' ') {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(s, ".", 2)[0])
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return false
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
		return false
	}
	return true
}
func validName(s string) bool {
	return validComponent(s) && strings.ToLower(s) == s && !strings.Contains(s, " ")
}

func splitPath(path string) ([]string, error) {
	if len(path) < 4 || len(path) > 240 || path[0] < 'A' || path[0] > 'Z' || path[1:3] != `:\` {
		return nil, ErrPolicy
	}
	parts := strings.Split(path[3:], `\`)
	for _, p := range parts {
		if !validComponent(p) {
			return nil, ErrPolicy
		}
	}
	return parts, nil
}

// These normalized policy types are populated from a native self-relative
// security descriptor and also exercised by non-mutating fixture tests.
type accessEntry struct {
	kind, flags byte
	mask        uint32
	sid         string
}
type securityPolicy struct {
	owner                         string
	protected, present, defaulted bool
	entries                       []accessEntry
}

func validateSecurity(p securityPolicy, runtimeSID string, installerOnly bool) error {
	count := 3
	if installerOnly {
		count = 2
	}
	if (!installerOnly && !validRuntimeSID(runtimeSID) || installerOnly && runtimeSID != "") || !p.present || !p.protected || p.defaulted || len(p.entries) != count {
		return ErrPolicy
	}
	if p.owner != systemSID && p.owner != administratorsSID && (installerOnly || p.owner != runtimeSID) {
		return ErrPolicy
	}
	required := map[string]bool{systemSID: false, administratorsSID: false}
	if !installerOnly {
		required[runtimeSID] = false
	}
	for _, ace := range p.entries {
		// No inherited, object/callback, conditional, deny, inheritance-only,
		// generic, or unknown ACEs. Every trusted principal gets explicit full
		// file access, and no other principal (including LocalService) is allowed.
		seen, ok := required[ace.sid]
		if !ok || seen || ace.kind != 0 || ace.flags != 0 || ace.mask != fileAllAccess {
			return ErrPolicy
		}
		required[ace.sid] = true
	}
	return nil
}
