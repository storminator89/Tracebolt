// Package nativeapt is the default-off Debian 13 amd64 native preparation
// boundary. It supplies fixed invocation construction and validates evidence
// emitted by the separately built libapt helper. It never grants execution.
package nativeapt

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"localrmm/internal/actionpermit"
	"localrmm/internal/debianversion"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/packageplan"
)

const (
	JobRoot                     = "/var/lib/tracebolt/package-updates"
	PolicyDirectory             = "/etc/tracebolt/package-actions"
	NativeExecutable            = "/usr/libexec/tracebolt-apt-prepare"
	GuardExecutable             = "/usr/libexec/tracebolt-package-guard"
	APTExecutable               = "/usr/bin/apt-get"
	BundleVersion               = "tracebolt.native-apt-prepared.v1"
	SupportedAPTVersion         = "3.0.3"
	MaxBundleBytes              = 256 << 10
	MaxTotalArchiveBytes uint64 = 2 << 30
)

//go:embed config.template
var configTemplate string

var ErrInvalid = errors.New("native_apt_evidence_invalid")
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,255}$`)

// Initial support is amd64 binary packages only; architecture-independent
// versions are deliberately rejected until their v3 hook form passes acceptance.
type Selection struct {
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
}
type ExactSelection struct {
	Name         string
	Architecture string
	Version      string
}
type Paths struct{ Directory, Config, Selection, Prepared, Capture, Archives, Lists, Snapshot string }

func JobPaths(id string) (Paths, error) {
	if !enrollmentcrypto.ValidID(id, "update_") {
		return Paths{}, ErrInvalid
	}
	d := JobRoot + "/" + id
	return Paths{d, d + "/apt.conf", d + "/selection.tsv", d + "/prepared.json", d + "/capture.hook", d + "/archives", d + "/lists", d + "/snapshot"}, nil
}
func SelectionBytes(ss []Selection) ([]byte, error) {
	if len(ss) == 0 || len(ss) > packageplan.MaxPackages {
		return nil, ErrInvalid
	}
	var b strings.Builder
	lastName, lastArch := "", ""
	for _, s := range ss {
		if !nameRE.MatchString(s.Name) || s.Architecture != "amd64" || (s.Name < lastName || s.Name == lastName && s.Architecture <= lastArch) {
			return nil, ErrInvalid
		}
		lastName, lastArch = s.Name, s.Architecture
		fmt.Fprintf(&b, "%s\t%s\n", s.Name, s.Architecture)
	}
	return []byte(b.String()), nil
}

// Invocation has no mode flag. Capture and approved execution MUST use these
// identical bytes; only protected out-of-band guard state chooses whether to
// abort or check a consumed approved admission. An invocation is not authority.
type Invocation struct {
	Executable string
	Args, Env  []string
	Config     []byte
}

func BuildInvocation(id string, ss []ExactSelection) (Invocation, error) {
	p, e := JobPaths(id)
	if e != nil {
		return Invocation{}, e
	}
	selections := make([]Selection, len(ss))
	args := []string{"--assume-yes", "--no-download", "--only-upgrade", "--no-remove", "install"}
	for i, s := range ss {
		selections[i] = Selection{s.Name, s.Architecture}
		if _, e := (debianversion.Comparator{}).Compare(context.Background(), s.Version, s.Version); e != nil {
			return Invocation{}, ErrInvalid
		}
		args = append(args, s.Name+":"+s.Architecture+"="+s.Version)
	}
	if _, e = SelectionBytes(selections); e != nil {
		return Invocation{}, e
	}
	return Invocation{APTExecutable, args, Environment(id), ConfigBytes(p, id)}, nil
}
func Environment(id string) []string {
	p, e := JobPaths(id)
	if e != nil {
		return nil
	}
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive", "APT_CONFIG=" + p.Config}
}

// ConfigBytes uses only internally derived paths. A root-reviewed isolated
// configuration opt-in, pinned host configuration snapshot and native acceptance
// are mandatory outside this pure builder. Never silently exclude host hooks.
func ConfigBytes(p Paths, id string) []byte {
	// Ignore supplied Paths entirely: callers cannot smuggle paths into config.
	q, e := JobPaths(id)
	if e != nil {
		return nil
	}
	p = q
	return []byte(strings.NewReplacer("$JOB", p.Directory, "$ID", id).Replace(configTemplate))
}

// Prepared is emitted ONLY by the protected native helper after a fresh
// authenticated refresh, complete solver checks and archive hashing. Decode
// validates syntax, not origin; do not accept these bytes over a remote API.
type Prepared struct {
	Version              string                `json:"version"`
	UpdateID             string                `json:"updateId"`
	APTVersion           string                `json:"aptVersion"`
	MetadataRefreshedAt  int64                 `json:"metadataRefreshedAt"`
	InventoryAt          int64                 `json:"inventoryAt"`
	InventoryDigest      string                `json:"inventoryDigest"`
	DpkgStateDigest      string                `json:"dpkgStateDigest"`
	HoldsDigest          string                `json:"holdsDigest"`
	SourceSnapshotDigest string                `json:"sourceSnapshotDigest"`
	HostConfigDigest     string                `json:"hostConfigDigest"`
	APTConfigDigest      string                `json:"aptConfigDigest"`
	Packages             []packageplan.Upgrade `json:"packages"`
	Sources              []Source              `json:"sources"`
	Archives             []StagedArchive       `json:"archives"`
}
type Source struct {
	IdentityDigest string `json:"identityDigest"`
	Label          string `json:"label"`
	Suite          string `json:"suite"`
	Component      string `json:"component"`
}

type StagedArchive struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
}

func DecodePrepared(ctx context.Context, raw []byte, id string) (Prepared, error) {
	var b Prepared
	if ctx == nil || ctx.Err() != nil || len(raw) == 0 || len(raw) > MaxBundleBytes {
		return b, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil {
		return Prepared{}, ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return Prepared{}, ErrInvalid
	}
	// JSON encoding equality also rejects duplicate/missing/case-folded keys.
	canonical, e := json.Marshal(b)
	if e != nil || !bytes.Equal(raw, canonical) {
		return Prepared{}, ErrInvalid
	}
	if e = b.Validate(ctx, id); e != nil {
		return Prepared{}, e
	}
	return b, nil
}
func (b Prepared) Validate(ctx context.Context, id string) error {
	p, e := JobPaths(id)
	if e != nil || b.Version != BundleVersion || b.UpdateID != id || b.APTVersion != SupportedAPTVersion || b.MetadataRefreshedAt <= 0 || b.InventoryAt < b.MetadataRefreshedAt || b.InventoryAt-b.MetadataRefreshedAt > packageplan.MaxMetadataAgeSeconds || len(b.Packages) == 0 || len(b.Packages) > packageplan.MaxPackages || len(b.Archives) != len(b.Packages) {
		return ErrInvalid
	}
	for _, d := range []string{b.InventoryDigest, b.DpkgStateDigest, b.HoldsDigest, b.SourceSnapshotDigest, b.HostConfigDigest, b.APTConfigDigest} {
		if !actionpermit.ValidDigest(d) {
			return ErrInvalid
		}
	}
	if b.InventoryDigest != b.DpkgStateDigest || b.APTConfigDigest != actionpermit.Digest(ConfigBytes(p, id)) {
		return ErrInvalid
	}
	// Reuse the canonical manifest validator with temporary syntactic bindings.
	x := "sha256:" + strings.Repeat("1", 64)
	plan := packageplan.Plan{Version: packageplan.Version, Action: packageplan.Action, EndpointID: "agent_" + strings.Repeat("1", 32), IncarnationDigest: x, RootPolicyDigest: x, Release: "debian-13-trixie", CreatedAt: b.InventoryAt, ExpiresAt: b.InventoryAt + 120, Evidence: packageplan.Evidence{InventoryDigest: b.InventoryDigest, InventoryAt: b.InventoryAt, InventoryCoverage: "complete", DpkgState: "clean", DpkgStateDigest: b.DpkgStateDigest, HoldsState: "known", HoldsDigest: b.HoldsDigest, MetadataState: "authenticated-refresh-complete", MetadataRefreshedAt: b.MetadataRefreshedAt, HookPolicyDigest: x, ConfigDigest: x}, Packages: b.Packages}
	if _, e := packageplan.Encode(ctx, plan); e != nil {
		return ErrInvalid
	}
	if len(b.Sources) == 0 || len(b.Sources) > len(b.Packages) {
		return ErrInvalid
	}
	sources := map[string]bool{}
	lastSource := ""
	for _, s := range b.Sources {
		if !actionpermit.ValidDigest(s.IdentityDigest) || s.IdentityDigest <= lastSource {
			return ErrInvalid
		}
		lastSource = s.IdentityDigest
		for _, v := range []string{s.Label, s.Suite, s.Component} {
			if len(v) == 0 || len(v) > 128 {
				return ErrInvalid
			}
			for _, c := range []byte(v) {
				if c < 32 || c > 126 {
					return ErrInvalid
				}
			}
		}
		sources[s.IdentityDigest] = false
	}
	for _, u := range b.Packages {
		if _, ok := sources[u.Archive.SourceIdentityDigest]; !ok {
			return ErrInvalid
		}
		sources[u.Archive.SourceIdentityDigest] = true
	}
	for _, used := range sources {
		if !used {
			return ErrInvalid
		}
	}
	var total uint64
	seen := map[string]bool{}
	for i, a := range b.Archives {
		u := b.Packages[i]
		if u.Architecture != "amd64" || path.Dir(a.Path) != p.Archives || path.Clean(a.Path) != a.Path || !strings.HasSuffix(a.Path, ".deb") || seen[a.Path] || a.SHA256 != u.Archive.SHA256 || a.Size != u.Archive.Size {
			return ErrInvalid
		}
		seen[a.Path] = true
		total += a.Size
		if total > MaxTotalArchiveBytes {
			return ErrInvalid
		}
	}
	return nil
}

type Binding struct {
	EndpointID, IncarnationDigest, RootPolicyDigest, HookPolicyDigest string
	CreatedAt, ExpiresAt                                              int64
}

// FinalizeCapture obtains ConfigDigest exclusively from a real guard capture.
// The caller must establish protected capture origin, exit-before-dpkg and
// actual archive observations; no simulation/download-only substitute is valid.
func FinalizeCapture(ctx context.Context, b Prepared, bind Binding, raw []byte, observed []packageplan.ObservedArchive) (packageplan.Plan, error) {
	if e := b.Validate(ctx, b.UpdateID); e != nil {
		return packageplan.Plan{}, e
	}
	h, e := packageplan.ParseHook(ctx, raw)
	if e != nil {
		return packageplan.Plan{}, e
	}
	p := packageplan.Plan{Version: packageplan.Version, Action: packageplan.Action, EndpointID: bind.EndpointID, IncarnationDigest: bind.IncarnationDigest, RootPolicyDigest: bind.RootPolicyDigest, Release: "debian-13-trixie", CreatedAt: bind.CreatedAt, ExpiresAt: bind.ExpiresAt, Evidence: packageplan.Evidence{InventoryDigest: b.InventoryDigest, InventoryAt: b.InventoryAt, InventoryCoverage: "complete", DpkgState: "clean", DpkgStateDigest: b.DpkgStateDigest, HoldsState: "known", HoldsDigest: b.HoldsDigest, MetadataState: "authenticated-refresh-complete", MetadataRefreshedAt: b.MetadataRefreshedAt, HookPolicyDigest: bind.HookPolicyDigest, ConfigDigest: h.ConfigDigest}, Packages: b.Packages}
	if e = packageplan.Match(ctx, p, bind.CreatedAt, raw, observed); e != nil {
		return packageplan.Plan{}, e
	}
	return p, nil
}

// ConfigSnapshotDigest matches native helper hashing. The digest identifies the
// exact excluded host configuration reviewed by a local administrator.
type SnapshotFile struct {
	Name     string
	Contents []byte
}

func ConfigSnapshotDigest(files []SnapshotFile) (string, error) {
	files = append([]SnapshotFile(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	var b bytes.Buffer
	b.WriteString("Tracebolt excluded APT config v1\x00")
	last := ""
	for _, f := range files {
		if f.Name == "" || f.Name <= last || path.Clean(f.Name) != f.Name || path.IsAbs(f.Name) || strings.ContainsAny(f.Name, "\x00\r\n") || strings.HasPrefix(f.Name, "../") {
			return "", ErrInvalid
		}
		last = f.Name
		fmt.Fprintf(&b, "%s\x00%d\x00", f.Name, len(f.Contents))
		b.Write(f.Contents)
		b.WriteByte(0)
	}
	return actionpermit.Digest(b.Bytes()), nil
}

// ValidateDPKGConfig bounds still-effective dpkg configuration. APT_CONFIG does
// not isolate dpkg's own options; conffile/force/path/hook directives fail closed.
func ValidateDPKGConfig(raw []byte) error {
	if len(raw) > 1<<20 {
		return ErrInvalid
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.Trim(line, " \t\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line != "no-debsig" && line != "log /var/log/dpkg.log" {
			return ErrInvalid
		}
	}
	return nil
}

// SourceSnapshotDigest binds the exact copied source, pin and public keyring
// bytes. Its format is shared with the native preparer, in this fixed order.
func SourceSnapshotDigest(sources, preferences, keyring []byte) (string, error) {
	if len(sources) == 0 || len(sources) > 1<<20 || len(preferences) > 1<<20 || len(keyring) == 0 || len(keyring) > 8<<20 {
		return "", ErrInvalid
	}
	var b bytes.Buffer
	b.WriteString("Tracebolt APT source snapshot v1\x00")
	for _, v := range [][]byte{sources, preferences, keyring} {
		fmt.Fprintf(&b, "%d\x00", len(v))
		b.Write(v)
		b.WriteByte(0)
	}
	return actionpermit.Digest(b.Bytes()), nil
}
