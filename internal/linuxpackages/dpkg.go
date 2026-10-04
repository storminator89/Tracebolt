package linuxpackages

import (
	"context"
	"errors"
	"io"
	"localrmm/internal/assessment"
	"strings"
)

// Source parsing limits are NOT transmission limits. No function in this
// package exports observations; see the separately bounded proposed contract.
const (
	MaxDpkgBytes    = assessment.MaxInventoryBytes
	MaxDpkgLine     = assessment.MaxInventoryLine
	MaxDpkgRecords  = assessment.MaxInventoryPackages
	MaxDpkgFields   = assessment.MaxInventoryFields
	MaxPackageName  = 256
	MaxArchitecture = 64
	MaxVersion      = 512
)

var (
	ErrDpkgInvalid = errors.New("dpkg_source_invalid")
	ErrDpkgLimit   = errors.New("dpkg_source_limit_exceeded")
	ErrDpkgEmpty   = errors.New("dpkg_source_empty")
	ErrDpkgRead    = errors.New("dpkg_source_read_failed")
)

// ParseDpkgStatus reuses the existing pure status parser. It returns selected
// installed/incomplete binary rows, excluding residual/config-only records. The
// raw-file digest is deliberately discarded: ignored content must not become an
// exported fingerprint. This wrapper never invokes the assessment collector or
// native comparator. It supplies no hold, origin, update, or CVE assertion.
func ParseDpkgStatus(ctx context.Context, r io.Reader) ([]PackageRow, error) {
	if r == nil || ctx.Err() != nil {
		return nil, ErrDpkgRead
	}
	parsed, _, err := assessment.ParseDpkgStatus(ctx, r)
	if err != nil {
		switch {
		case errors.Is(err, assessment.ErrInventoryLimit):
			return nil, ErrDpkgLimit
		case errors.Is(err, assessment.ErrInventoryEmpty):
			return nil, ErrDpkgEmpty
		case errors.Is(err, assessment.ErrInventoryInvalid):
			return nil, ErrDpkgInvalid
		default:
			return nil, ErrDpkgRead
		}
	}
	rows := make([]PackageRow, 0, len(parsed))
	for _, p := range parsed {
		if ctx.Err() != nil {
			return nil, ErrDpkgRead
		}
		// Debian Policy requires at least two characters. The shared parser is
		// more permissive here; tighten only this proposed adapter's boundary.
		// Source/wildcard architectures are not installed binary identities.
		if len(p.Name) < 2 || len(p.SourcePackage) < 2 || !binaryArchitecture(p.Architecture) {
			return nil, ErrDpkgInvalid
		}
		rows = append(rows, PackageRow{
			Name: p.Name, Version: p.Version, Architecture: p.Architecture,
			SourcePackage: p.SourcePackage, SourceVersion: p.SourceVersion,
			SourceMapping: p.SourceMapping, InstallState: p.InstallState,
		})
	}
	return rows, nil
}

func binaryArchitecture(arch string) bool {
	if arch == "source" {
		return false
	}
	for _, component := range strings.Split(arch, "-") {
		if component == "any" {
			return false
		}
	}
	return true
}
