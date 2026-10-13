package macosservice

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/macho"
	"encoding/hex"
	"io"
	"runtime/debug"
)

const MaxBinaryBytes = int64(128 << 20)
const MaxSourceBytes = int64(256 << 20)

// inspectBinary uses the same held descriptor for exact bytes, Mach-O identity
// and Go build metadata. This proves selected-byte integrity, not publisher trust,
// code signing, notarization or a reproducible source-to-binary relationship.
func inspectBinary(ctx context.Context, r io.ReaderAt, size int64, expected, arch string) error {
	return inspectBinaryWithBuild(ctx, r, size, expected, arch, buildinfo.Read)
}
func inspectBinaryWithBuild(ctx context.Context, r io.ReaderAt, size int64, expected, arch string, readBuild func(io.ReaderAt) (*debug.BuildInfo, error)) error {
	if size < 1 || size > MaxBinaryBytes || readBuild == nil || hashArtifact(ctx, r, size, expected) != nil {
		return ErrPreflight
	}
	image, err := macho.NewFile(r)
	if err != nil {
		return ErrPreflight
	}
	defer image.Close()
	wanted := macho.CpuAmd64
	if arch == "arm64" {
		wanted = macho.CpuArm64
	} else if arch != "amd64" {
		return ErrPreflight
	}
	if image.Magic != macho.Magic64 || image.Type != macho.TypeExec || image.Cpu != wanted {
		return ErrPreflight
	}
	build, err := readBuild(r)
	if err != nil || build == nil || build.Path != "localrmm/cmd/macos-agent" || build.Main.Path != "localrmm" {
		return ErrPreflight
	}
	settings := map[string]string{}
	for _, s := range build.Settings {
		if _, duplicate := settings[s.Key]; duplicate {
			return ErrPreflight
		}
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != "darwin" || settings["GOARCH"] != arch {
		return ErrPreflight
	}
	return nil
}
func hashArtifact(ctx context.Context, r io.ReaderAt, size int64, expected string) error {
	if ctx == nil || r == nil || size < 1 || size > MaxSourceBytes || !validDigest(expected) {
		return ErrPreflight
	}
	h := sha256.New()
	src := io.NewSectionReader(r, 0, size)
	n, err := io.Copy(h, &cancelReader{ctx: ctx, r: src})
	if err != nil || n != size || ctx.Err() != nil || hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrPreflight
	}
	return nil
}

type cancelReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *cancelReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}
