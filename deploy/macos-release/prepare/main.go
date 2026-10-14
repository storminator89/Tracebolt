// macos-package-prepare verifies an exact unsigned test package and prepares
// fresh host custody only after a separate, explicit --apply. It never enrolls,
// starts a service, grants a scope, or removes identity state.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/enrollmentclient"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const (
	payloadSchema = "tracebolt.macos-service-test-payload.v1"
	maxPackage    = int64(384 << 20)
	maxSource     = int64(128 << 20)
	maxBinary     = int64(64 << 20)
	maxDocument   = int64(128 << 10)
	maxManifest   = int64(16 << 10)
)

var errRejected = errors.New("macOS package rejected; preserve all existing data")
var gitID = regexp.MustCompile(`^[0-9a-f]{40}$`)
var versionID = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?$`)

type asset struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type payloadManifest struct {
	Schema          string           `json:"schema"`
	Repository      string           `json:"repository"`
	Version         string           `json:"version"`
	SourceCommit    string           `json:"sourceCommit"`
	SourceTree      string           `json:"sourceTree"`
	GoVersion       string           `json:"goVersion"`
	Target          string           `json:"target"`
	CandidateKind   string           `json:"candidateKind"`
	NativeAccepted  bool             `json:"nativeAccepted"`
	PublisherSigned bool             `json:"publisherSigned"`
	Notarized       bool             `json:"notarized"`
	Published       bool             `json:"published"`
	ProductionReady bool             `json:"productionReady"`
	Assets          map[string]asset `json:"assets"`
}

type packageBytes struct {
	Manifest     payloadManifest
	Digest       string
	Files        map[string][]byte
	Profile      string
	Bootstrap    []byte
	BootstrapSHA string
}

var memberNames = []string{
	"TESTING.md", "bin/enroll-agent", "bin/macos-agent", "bin/macos-agent-service",
	"bin/macos-package-prepare", "payload-manifest.json", "source/source.tar",
}

func validSHA(raw string) bool {
	b, err := hex.DecodeString(raw)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == raw
}

func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	return append(raw, '\n'), err
}

func decodeManifest(raw []byte) (payloadManifest, error) {
	var m payloadManifest
	if len(raw) == 0 || len(raw) > int(maxManifest) {
		return m, errRejected
	}
	var generic map[string]json.RawMessage
	if json.Unmarshal(raw, &generic) != nil || len(generic) != 14 {
		return m, errRejected
	}
	for _, key := range []string{"schema", "repository", "version", "sourceCommit", "sourceTree", "goVersion", "target", "candidateKind", "nativeAccepted", "publisherSigned", "notarized", "published", "productionReady", "assets"} {
		if _, ok := generic[key]; !ok {
			return m, errRejected
		}
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return m, errRejected
	}
	encoded, err := canonicalJSON(generic)
	if err != nil || string(encoded) != string(raw) || m.Schema != payloadSchema ||
		m.Repository != "storminator89/Tracebolt" || m.CandidateKind != "publisher-unsigned-service-test" ||
		m.NativeAccepted || m.PublisherSigned || m.Notarized || m.Published || m.ProductionReady ||
		!gitID.MatchString(m.SourceCommit) || !gitID.MatchString(m.SourceTree) || m.GoVersion != "go1.27.1" ||
		(m.Target != "darwin/amd64" && m.Target != "darwin/arm64") ||
		!versionID.MatchString(m.Version) || len(m.Version) > 64 || len(m.Assets) != len(memberNames)-1 {
		return m, errRejected
	}
	return m, nil
}

func maxMember(name string) int64 {
	switch {
	case name == "source/source.tar":
		return maxSource
	case strings.HasPrefix(name, "bin/"):
		return maxBinary
	case name == "payload-manifest.json":
		return maxManifest
	default:
		return maxDocument
	}
}

func machoCPU(arch string) uint32 {
	if arch == "amd64" {
		return 0x01000007
	}
	return 0x0100000c
}

var roleImports = map[string]string{
	"bin/enroll-agent":          "localrmm/cmd/enroll-agent",
	"bin/macos-agent":           "localrmm/cmd/macos-agent",
	"bin/macos-agent-service":   "localrmm/cmd/macos-agent-service",
	"bin/macos-package-prepare": "localrmm/deploy/macos-release/prepare",
}

func checkRoleBuildInfo(raw []byte, name, arch string) error {
	info, err := buildinfo.Read(bytes.NewReader(raw))
	if err != nil || info.GoVersion != "go1.27.1" || info.Path != roleImports[name] || info.Main.Path != "localrmm" {
		return errRejected
	}
	settings := map[string]string{}
	for _, entry := range info.Settings {
		if _, exists := settings[entry.Key]; exists || strings.HasPrefix(entry.Key, "vcs.") {
			return errRejected
		}
		settings[entry.Key] = entry.Value
	}
	if settings["GOOS"] != "darwin" || settings["GOARCH"] != arch || settings["CGO_ENABLED"] != "0" {
		return errRejected
	}
	return nil
}

// The seam lets inert archive fixtures exercise the archive contract without
// executing or embedding a Darwin binary. Production uses Go's build-info reader.
var inspectRole = checkRoleBuildInfo

type onlyZero struct{ size int64 }

func (z *onlyZero) Write(p []byte) (int, error) {
	if z.size+int64(len(p)) > maxPackage {
		return 0, errRejected
	}
	for _, b := range p {
		if b != 0 {
			return 0, errRejected
		}
	}
	z.size += int64(len(p))
	return len(p), nil
}

func verifyPackage(filename, expectedHash, arch string) (packageBytes, error) {
	var out packageBytes
	if !validSHA(expectedHash) || (arch != "amd64" && arch != "arm64") ||
		!filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return out, errRejected
	}
	f, err := openSelectedRegular(filename, maxPackage)
	if err != nil {
		return out, errRejected
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return out, errRejected
	}
	archiveBytes, err := io.ReadAll(io.LimitReader(f, maxPackage+1))
	if err != nil || int64(len(archiveBytes)) != st.Size() {
		return out, errRejected
	}
	checksum := sha256.Sum256(archiveBytes)
	if hex.EncodeToString(checksum[:]) != expectedHash {
		return out, errRejected
	}
	compressed := bytes.NewReader(archiveBytes)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return out, errRejected
	}
	defer gz.Close()
	gz.Multistream(false)
	if gz.Name != "" || gz.Comment != "" || len(gz.Extra) != 0 || !gz.ModTime.IsZero() || gz.OS != 255 {
		return out, errRejected
	}
	r := tar.NewReader(gz)
	files := make(map[string][]byte, len(memberNames))
	allowed := make(map[string]bool, len(memberNames))
	for _, name := range memberNames {
		allowed[name] = true
	}
	var total int64
	var stamp int64 = -1
	index := 0
	for {
		h, nextErr := r.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil || h == nil || index >= len(memberNames) || h.Name != memberNames[index] || !allowed[h.Name] || files[h.Name] != nil || h.Typeflag != tar.TypeReg ||
			h.Format != tar.FormatUSTAR || h.Linkname != "" || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 ||
			h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" ||
			h.Mode != func() int64 {
				if strings.HasPrefix(h.Name, "bin/") {
					return 0755
				}
				return 0644
			}() ||
			h.Size <= 0 || h.Size > maxMember(h.Name) || total+h.Size > maxPackage {
			return out, errRejected
		}
		if stamp == -1 {
			stamp = h.ModTime.Unix()
		} else if stamp != h.ModTime.Unix() {
			return out, errRejected
		}
		total += h.Size
		b, readErr := io.ReadAll(io.LimitReader(r, h.Size+1))
		if readErr != nil || int64(len(b)) != h.Size {
			return out, errRejected
		}
		files[h.Name] = b
		index++
	}
	if len(files) != len(memberNames) || index != len(memberNames) || stamp <= 0 {
		return out, errRejected
	}
	// Force gzip CRC/trailer validation and reject any nonzero tar padding,
	// concatenated gzip member or trailing compressed bytes.
	if _, err = io.Copy(&onlyZero{}, gz); err != nil || compressed.Len() != 0 {
		return out, errRejected
	}
	m, err := decodeManifest(files["payload-manifest.json"])
	if err != nil || m.Target != "darwin/"+arch {
		return out, errRejected
	}
	for _, name := range memberNames {
		if name == "payload-manifest.json" {
			continue
		}
		a, ok := m.Assets[name]
		b := files[name]
		sha := sha256.Sum256(b)
		if !ok || a.Size != int64(len(b)) || a.SHA256 != hex.EncodeToString(sha[:]) {
			return out, errRejected
		}
		if strings.HasPrefix(name, "bin/") {
			if len(b) < 16 || string(b[:4]) != "\xcf\xfa\xed\xfe" ||
				binary.LittleEndian.Uint32(b[4:8]) != machoCPU(arch) ||
				binary.LittleEndian.Uint32(b[12:16]) != 2 {
				return out, errRejected
			}
			if inspectRole(b, name, arch) != nil {
				return out, errRejected
			}
		}
	}
	for name := range m.Assets {
		if !allowed[name] || name == "payload-manifest.json" {
			return out, errRejected
		}
	}
	out = packageBytes{Manifest: m, Digest: expectedHash, Files: files}
	return out, nil
}

func readBootstrap(filename, expectedHash, profile string, fresh bool) ([]byte, error) {
	if !validSHA(expectedHash) || !filepath.IsAbs(filename) || filepath.Clean(filename) != filename ||
		(profile != "basic-readonly-v1" && profile != "macos-read-inventory-v1") {
		return nil, errRejected
	}
	f, err := openSelectedRegular(filename, 64<<10)
	if err != nil {
		return nil, errRejected
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, errRejected
	}
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || int64(len(raw)) != st.Size() {
		return nil, errRejected
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != expectedHash {
		return nil, errRejected
	}
	if fresh {
		b, err := enrollmentclient.ParseBootstrap(raw)
		if err != nil || b.Profile != "tls" || b.CollectionProfile != profile {
			return nil, errRejected
		}
	}
	return raw, nil
}

type hostStage interface {
	Inspect(uint32, uint32, packageBytes, bool) error
	Apply(uint32, uint32, packageBytes) error
	Rollback(uint32, uint32, packageBytes) error
}

func identity(raw string) (uint32, uint32, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, 0, errRejected
	}
	u, e1 := strconv.ParseUint(parts[0], 10, 32)
	g, e2 := strconv.ParseUint(parts[1], 10, 32)
	if e1 != nil || e2 != nil || u < 502 || g < 502 || u > 60000 || g > 60000 ||
		strconv.FormatUint(u, 10) != parts[0] || strconv.FormatUint(g, 10) != parts[1] {
		return 0, 0, errRejected
	}
	return uint32(u), uint32(g), nil
}

func execute(action string, apply bool, id string, pkg packageBytes, host hostStage) error {
	if action == "verify" {
		if apply || id != "" {
			return errRejected
		}
		return nil
	}
	u, g, err := identity(id)
	if err != nil || host == nil || (action != "stage" && action != "rollback") {
		return errRejected
	}
	if err = host.Inspect(u, g, pkg, action == "rollback"); err != nil {
		return err
	}
	if !apply {
		return nil
	}
	if action == "stage" {
		return host.Apply(u, g, pkg)
	}
	return host.Rollback(u, g, pkg)
}

func run(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("macos-package-prepare", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "verify", "verify, stage or rollback")
	archive := f.String("archive", "", "absolute reviewed package archive")
	checksum := f.String("package-sha256", "", "independently selected package SHA-256")
	serviceIdentity := f.String("service-identity", "", "new dedicated numeric UID:GID")
	profile := f.String("profile", "", "basic-readonly-v1 or macos-read-inventory-v1")
	bootstrap := f.String("bootstrap", "", "absolute exact public TLS bootstrap")
	bootstrapSHA := f.String("bootstrap-sha256", "", "independently selected public bootstrap SHA-256")
	apply := f.Bool("apply", false, "explicit host mutation boundary")
	if f.Parse(args) != nil || f.NArg() != 0 || *archive == "" || !validSHA(*checksum) {
		fmt.Fprintln(errOut, "Usage: macos-package-prepare --action verify|stage|rollback --archive ABS_PATH --package-sha256 REVIEWED_SHA256 [--service-identity UID:GID --profile basic-readonly-v1|macos-read-inventory-v1 --bootstrap ABS_PUBLIC_JSON --bootstrap-sha256 REVIEWED_SHA256] [--apply].")
		return 2
	}
	pkg, err := verifyPackage(*archive, *checksum, runtime.GOARCH)
	if err != nil {
		fmt.Fprintln(errOut, "Package verification failed. Preserve the archive and host state; nothing was repaired.")
		return 2
	}
	if *action == "verify" {
		if *profile != "" || *bootstrap != "" || *bootstrapSHA != "" {
			fmt.Fprintln(errOut, "Verification accepts no host or bootstrap inputs.")
			return 2
		}
	} else {
		pkg.Profile = *profile
		pkg.BootstrapSHA = *bootstrapSHA
		pkg.Bootstrap, err = readBootstrap(*bootstrap, *bootstrapSHA, *profile, *action == "stage")
		if err != nil {
			fmt.Fprintln(errOut, "Selected public TLS bootstrap is invalid, changed, or mismatched; no host action occurred.")
			return 2
		}
	}
	var host hostStage
	if *action != "verify" {
		host = newNativeStage()
	}
	if err = execute(*action, *apply, *serviceIdentity, pkg, host); err != nil {
		fmt.Fprintln(errOut, "Package host preparation is unavailable, rejected, or indeterminate. Preserve all account, file, enrollment and service state for inspection; no automatic retry or cleanup is safe.")
		return 1
	}
	source := pkg.Manifest.Assets["source/source.tar"].SHA256
	names := make([]string, 0, len(pkg.Manifest.Assets))
	for name := range pkg.Manifest.Assets {
		names = append(names, name)
	}
	sort.Strings(names)
	result := map[string]any{"status": "verified", "action": *action, "applied": *apply,
		"target": pkg.Manifest.Target, "sourceCommit": pkg.Manifest.SourceCommit,
		"packageSHA256": pkg.Digest, "sourceSHA256": source,
		"bootstrapSHA256": pkg.BootstrapSHA, "profile": pkg.Profile,
		"agentSHA256":    pkg.Manifest.Assets["bin/macos-agent"].SHA256,
		"nativeAccepted": false, "publisherSigned": false, "notarized": false,
		"assets": names}
	if *action == "stage" {
		result["status"] = "stage-reviewed"
		if *apply {
			result["status"] = "staged-awaiting-separate-enrollment"
		}
	}
	if *action == "rollback" {
		result["status"] = "rollback-reviewed"
		if *apply {
			result["status"] = "package-stage-removed-account-retained"
		}
	}
	raw, _ := json.Marshal(result)
	_, _ = fmt.Fprintln(out, string(raw))
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
