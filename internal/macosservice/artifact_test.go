package macosservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"runtime/debug"
	"testing"
)

func machoFixture(cpu macho.Cpu, kind macho.Type) []byte {
	var out bytes.Buffer
	for _, word := range []uint32{macho.Magic64, uint32(cpu), 0, uint32(kind), 0, 0, 0, 0} {
		_ = binary.Write(&out, binary.LittleEndian, word)
	}
	return out.Bytes()
}
func TestBinaryRequiresExactNativeMachORoleArchitecture(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			cpu := macho.CpuAmd64
			if arch == "arm64" {
				cpu = macho.CpuArm64
			}
			raw := machoFixture(cpu, macho.TypeExec)
			sum := sha256.Sum256(raw)
			want := hex.EncodeToString(sum[:])
			valid := func() *debug.BuildInfo {
				return &debug.BuildInfo{Path: "localrmm/cmd/macos-agent", Main: debug.Module{Path: "localrmm"}, Settings: []debug.BuildSetting{{Key: "GOOS", Value: "darwin"}, {Key: "GOARCH", Value: arch}}}
			}
			read := func(io.ReaderAt) (*debug.BuildInfo, error) { return valid(), nil }
			if inspectBinaryWithBuild(context.Background(), bytes.NewReader(raw), int64(len(raw)), want, arch, read) != nil {
				t.Fatal("valid fixture rejected")
			}
			tests := []struct {
				name string
				edit func(*debug.BuildInfo)
			}{
				{"wrong-role", func(b *debug.BuildInfo) { b.Path = "localrmm/cmd/enroll-agent" }},
				{"wrong-module", func(b *debug.BuildInfo) { b.Main.Path = "untrusted" }},
				{"wrong-os", func(b *debug.BuildInfo) { b.Settings[0].Value = "linux" }},
				{"wrong-architecture", func(b *debug.BuildInfo) { b.Settings[1].Value = "386" }},
				{"missing-build-settings", func(b *debug.BuildInfo) { b.Settings = nil }},
				{"duplicate-setting", func(b *debug.BuildInfo) { b.Settings = append(b.Settings, b.Settings[0]) }},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					read := func(io.ReaderAt) (*debug.BuildInfo, error) { b := valid(); test.edit(b); return b, nil }
					if inspectBinaryWithBuild(context.Background(), bytes.NewReader(raw), int64(len(raw)), want, arch, read) == nil {
						t.Fatal("untrusted build accepted")
					}
				})
			}
			if inspectBinaryWithBuild(context.Background(), bytes.NewReader(raw), int64(len(raw)), want, "386", read) == nil {
				t.Fatal("unsupported architecture")
			}
			other := "arm64"
			if arch == "arm64" {
				other = "amd64"
			}
			if inspectBinaryWithBuild(context.Background(), bytes.NewReader(raw), int64(len(raw)), want, other, read) == nil {
				t.Fatal("mismatched architecture")
			}
			if inspectBinaryWithBuild(context.Background(), bytes.NewReader(raw), int64(len(raw)), want, arch, func(io.ReaderAt) (*debug.BuildInfo, error) { return nil, errors.New("missing") }) == nil {
				t.Fatal("missing build info")
			}
			if inspectBinary(context.Background(), bytes.NewReader(raw), int64(len(raw)), want, arch) == nil {
				t.Fatal("synthetic header without real Go metadata accepted")
			}
		})
	}
	for _, raw := range [][]byte{[]byte("not a binary"), machoFixture(macho.CpuAmd64, macho.TypeDylib), machoFixture(macho.Cpu386, macho.TypeExec), {0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0}} {
		sum := sha256.Sum256(raw)
		if inspectBinaryWithBuild(context.Background(), bytes.NewReader(raw), int64(len(raw)), hex.EncodeToString(sum[:]), "amd64", func(io.ReaderAt) (*debug.BuildInfo, error) {
			t.Fatal("invalid image reached build metadata")
			return nil, nil
		}) == nil {
			t.Fatal("invalid image")
		}
	}
}
