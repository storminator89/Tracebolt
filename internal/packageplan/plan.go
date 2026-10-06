// Package packageplan defines an inert selected-upgrade manifest and matches
// supplied APT hook observations. It does not collect evidence, authenticate
// archives, grant approval, admit execution, open files, or run commands.
package packageplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"

	"localrmm/internal/actionpermit"
	"localrmm/internal/debianversion"
	"localrmm/internal/enrollmentcrypto"
)

const (
	Version                       = "tracebolt.selected-apt-plan.v1"
	Action                        = "package.upgrade-selected"
	MaxPackages                   = 32
	MaxPlanBytes                  = 128 << 10
	MaxLifetimeSeconds     int64  = 120
	MaxInventoryAgeSeconds int64  = 60
	MaxMetadataAgeSeconds  int64  = 300
	MaxArchiveBytes        uint64 = 1 << 30
	maxUnix                int64  = 253402300799
	planDomain                    = "Tracebolt selected APT plan v1\x00"
)

var (
	ErrInvalid  = errors.New("package_plan_invalid")
	ErrStale    = errors.New("package_plan_stale")
	ErrProtocol = errors.New("package_hook_protocol_invalid")
	ErrMismatch = errors.New("package_hook_observation_mismatch")
)

// Plan is a description, not approval or execution authority. Evidence fields
// must eventually come from a protected native adapter, never a request body or
// a relabeled cached-candidate/full-inventory report. There is no such adapter yet.
type Plan struct {
	Version           string    `json:"version"`
	Action            string    `json:"action"`
	EndpointID        string    `json:"endpointId"`
	IncarnationDigest string    `json:"incarnationDigest"`
	RootPolicyDigest  string    `json:"rootPolicyDigest"`
	Release           string    `json:"release"`
	CreatedAt         int64     `json:"createdAt"`
	ExpiresAt         int64     `json:"expiresAt"`
	Evidence          Evidence  `json:"evidence"`
	Packages          []Upgrade `json:"packages"`
}

// Evidence commits to separately established facts, not evidence this package
// can verify. ConfigDigest covers the ENTIRE raw hook configuration block,
// including every directive's LF, excluding the header and blank separator.
// Neither a digest nor these status strings establish source authenticity,
// clean dpkg under lock, a reviewed hook policy, or filesystem protection.
type Evidence struct {
	InventoryDigest     string `json:"inventoryDigest"`
	InventoryAt         int64  `json:"inventoryAt"`
	InventoryCoverage   string `json:"inventoryCoverage"`
	DpkgState           string `json:"dpkgState"`
	DpkgStateDigest     string `json:"dpkgStateDigest"`
	HoldsState          string `json:"holdsState"`
	HoldsDigest         string `json:"holdsDigest"`
	MetadataState       string `json:"metadataState"`
	MetadataRefreshedAt int64  `json:"metadataRefreshedAt"`
	HookPolicyDigest    string `json:"hookPolicyDigest"`
	ConfigDigest        string `json:"configDigest"`
}

type Upgrade struct {
	Name         string         `json:"name"`
	Architecture string         `json:"architecture"`
	InstallState string         `json:"installState"`
	HoldState    string         `json:"holdState"`
	From         PackageVersion `json:"from"`
	To           PackageVersion `json:"to"`
	Archive      Archive        `json:"archive"`
}

type PackageVersion struct {
	Version       string `json:"version"`
	SourcePackage string `json:"sourcePackage"`
	SourceVersion string `json:"sourceVersion"`
	SourceMapping string `json:"sourceMapping"`
	MultiArch     string `json:"multiArch"` // canonical no, same, foreign, allowed
}

// Archive records a future native adapter's authenticated Release -> Packages
// -> archive binding. SourceIdentityDigest identifies the exact approved source
// configuration/index identity, not a CVE source or a URL supplied by a caller.
// This package does not verify any signature or follow any of these paths.
type Archive struct {
	SHA256               string `json:"sha256"`
	Size                 uint64 `json:"size"`
	Filename             string `json:"filename"`
	SourceIdentityDigest string `json:"sourceIdentityDigest"`
	Release              string `json:"release"`
	ReleaseDigest        string `json:"releaseDigest"`
	IndexDigest          string `json:"indexDigest"`
	IndexPath            string `json:"indexPath"`
	Authentication       string `json:"authentication"`
}

func validTime(t int64) bool { return t > 0 && t <= maxUnix }
func recent(observed, now, maximum int64) bool {
	return validTime(observed) && validTime(now) && observed <= now && now-observed <= maximum
}
func validName(s string) bool {
	if len(s) < 2 || len(s) > 256 {
		return false
	}
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if i > 0 && (c == '+' || c == '-' || c == '.') {
			continue
		}
		return false
	}
	return true
}
func validArch(s string) bool {
	if len(s) == 0 || len(s) > 64 || s == "source" {
		return false
	}
	for _, part := range strings.Split(s, "-") {
		if part == "" || part == "any" {
			return false
		}
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func validMultiArch(s string) bool {
	return s == "no" || s == "same" || s == "foreign" || s == "allowed"
}

// Paths are opaque observations, not commands. Reject ambiguous encodings and
// components instead of cleaning/normalizing them. Percent escapes are excluded
// from this first subset; colon is supported for literal Debian epoch filenames.
func validPath(s string, absolute bool) bool {
	if len(s) == 0 || len(s) > 1024 || strings.HasPrefix(s, "/") != absolute || path.Clean(s) != s || s == "." || strings.HasSuffix(s, "/") {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(s, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/+_.-:", rune(c)) {
			continue
		}
		return false
	}
	return true
}
func validPackageVersion(ctx context.Context, name string, v PackageVersion) bool {
	if !validName(v.SourcePackage) || !validMultiArch(v.MultiArch) {
		return false
	}
	if v.SourceMapping != "source-field" && (v.SourceMapping != "binary-default" || v.SourcePackage != name || v.SourceVersion != v.Version) {
		return false
	}
	for _, s := range []string{v.Version, v.SourceVersion} {
		if _, err := (debianversion.Comparator{}).Compare(ctx, s, s); err != nil {
			return false
		}
	}
	return true
}
func validate(ctx context.Context, p Plan) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.Version != Version || p.Action != Action || !enrollmentcrypto.ValidID(p.EndpointID, "agent_") || !actionpermit.ValidDigest(p.IncarnationDigest) || !actionpermit.ValidDigest(p.RootPolicyDigest) || (p.Release != "debian-13-trixie" && p.Release != "ubuntu-24.04-noble") || !validTime(p.CreatedAt) || !validTime(p.ExpiresAt) || p.ExpiresAt <= p.CreatedAt || p.ExpiresAt-p.CreatedAt > MaxLifetimeSeconds || len(p.Packages) == 0 || len(p.Packages) > MaxPackages {
		return ErrInvalid
	}
	e := p.Evidence
	if e.InventoryCoverage != "complete" || e.DpkgState != "clean" || e.HoldsState != "known" || e.MetadataState != "authenticated-refresh-complete" {
		return ErrInvalid
	}
	for _, d := range []string{e.InventoryDigest, e.DpkgStateDigest, e.HoldsDigest, e.HookPolicyDigest, e.ConfigDigest} {
		if !actionpermit.ValidDigest(d) {
			return ErrInvalid
		}
	}
	if !recent(e.InventoryAt, p.CreatedAt, MaxInventoryAgeSeconds) || !recent(e.MetadataRefreshedAt, p.CreatedAt, MaxMetadataAgeSeconds) {
		return ErrStale
	}
	lastName, lastArch := "", ""
	for _, u := range p.Packages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !validName(u.Name) || !validArch(u.Architecture) || (u.Name < lastName || u.Name == lastName && u.Architecture <= lastArch) || u.InstallState != "installed" || u.HoldState != "unheld" || !validPackageVersion(ctx, u.Name, u.From) || !validPackageVersion(ctx, u.Name, u.To) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrInvalid
		}
		lastName, lastArch = u.Name, u.Architecture
		order, err := (debianversion.Comparator{}).Compare(ctx, u.From.Version, u.To.Version)
		if err != nil || order != -1 {
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrInvalid
		}
		a := u.Archive
		if a.Size == 0 || a.Size > MaxArchiveBytes || !validPath(a.Filename, false) || !strings.HasSuffix(a.Filename, ".deb") || !validPath(a.IndexPath, false) || a.Release != p.Release || a.Authentication != "native-apt-authenticated" {
			return ErrInvalid
		}
		for _, d := range []string{a.SHA256, a.SourceIdentityDigest, a.ReleaseDigest, a.IndexDigest} {
			if !actionpermit.ValidDigest(d) {
				return ErrInvalid
			}
		}
	}
	return ctx.Err()
}

// Encode validates the inert historical description at its original creation
// time. It does not refresh timestamps. Use CheckFresh or Match at observation
// time; neither returns an execution permit.
func Encode(ctx context.Context, p Plan) ([]byte, error) {
	if err := validate(ctx, p); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxPlanBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}
func Decode(ctx context.Context, raw []byte) (Plan, error) {
	if ctx == nil {
		return Plan{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	var p Plan
	if len(raw) == 0 || len(raw) > MaxPlanBytes || json.Unmarshal(raw, &p) != nil {
		return Plan{}, ErrInvalid
	}
	canonical, err := Encode(ctx, p)
	if err != nil {
		return Plan{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Plan{}, ErrInvalid
	}
	return p, nil
}
func Digest(ctx context.Context, p Plan) (string, error) {
	raw, err := Encode(ctx, p)
	if err != nil {
		return "", err
	}
	return actionpermit.Digest(append([]byte(planDomain), raw...)), nil
}

// CheckFresh rejects changed-time, future, expired and aged evidence. Freshness
// is relative to the caller's trusted clock, whose durable rollback protection
// remains a future runner requirement.
func CheckFresh(ctx context.Context, p Plan, now int64) error {
	if _, err := Encode(ctx, p); err != nil {
		return err
	}
	if !validTime(now) || now < p.CreatedAt || now >= p.ExpiresAt || !recent(p.Evidence.InventoryAt, now, MaxInventoryAgeSeconds) || !recent(p.Evidence.MetadataRefreshedAt, now, MaxMetadataAgeSeconds) {
		return ErrStale
	}
	return nil
}
