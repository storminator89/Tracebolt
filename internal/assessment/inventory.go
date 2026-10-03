package assessment

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxInventoryBytes    = 32 << 20
	MaxInventoryLine     = 64 << 10
	MaxInventoryPackages = 100000
	MaxInventoryFields   = 256
	maxIdentityLength    = 512
)

var (
	ErrInventoryInvalid = errors.New("inventory_invalid")
	ErrInventoryLimit   = errors.New("inventory_limit_exceeded")
	ErrInventoryEmpty   = errors.New("inventory_empty")
	ErrInventoryRead    = errors.New("inventory_read_failed")
	packageName         = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,255}$`)
	archName            = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// ParseDpkgStatus retains ONLY Package, Status, Version, Architecture, and Source.
// A malformed, duplicate, or over-limit record invalidates the entire snapshot;
// a parsed prefix must never become a successful empty/partial package inventory.
func ParseDpkgStatus(ctx context.Context, r io.Reader) ([]InstalledPackage, string, error) {
	hash := sha256.New()
	limited := &io.LimitedReader{R: r, N: MaxInventoryBytes + 1}
	scanner := bufio.NewScanner(io.TeeReader(limited, hash))
	scanner.Buffer(make([]byte, 4096), MaxInventoryLine)
	fields := map[string]string{}
	seen := map[string]bool{}
	packages := []InstalledPackage{}
	identities := map[string]bool{}
	stanzaCount := 0
	lastSelected := false
	flush := func() error {
		if len(seen) == 0 {
			return nil
		}
		stanzaCount++
		if stanzaCount > MaxInventoryPackages {
			return ErrInventoryLimit
		}
		pkg, retain, err := parseDpkgRecord(fields)
		if err != nil {
			return err
		}
		key := pkg.Name + ":" + pkg.Architecture
		if identities[key] {
			return ErrInventoryInvalid
		}
		identities[key] = true
		if retain {
			packages = append(packages, pkg)
		}
		fields = map[string]string{}
		seen = map[string]bool{}
		lastSelected = false
		return nil
	}
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, "", ErrInventoryRead
		}
		line := scanner.Text()
		if !utf8.ValidString(line) || strings.ContainsAny(line, "\x00\r") {
			return nil, "", ErrInventoryInvalid
		}
		if line == "" {
			if err := flush(); err != nil {
				return nil, "", err
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if len(seen) == 0 || lastSelected {
				return nil, "", ErrInventoryInvalid
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || len(key) == 0 || len(key) > 128 || seen[strings.ToLower(key)] || len(seen) >= MaxInventoryFields {
			return nil, "", ErrInventoryInvalid
		}
		for _, ch := range key {
			if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return nil, "", ErrInventoryInvalid
			}
		}
		seen[strings.ToLower(key)] = true
		if canonical, ok := map[string]string{"package": "Package", "status": "Status", "version": "Version", "architecture": "Architecture", "source": "Source"}[strings.ToLower(key)]; ok {
			key = canonical
		}
		lastSelected = key == "Package" || key == "Status" || key == "Version" || key == "Architecture" || key == "Source"
		if lastSelected {
			value = strings.TrimSpace(value)
			if len(value) > maxIdentityLength {
				return nil, "", ErrInventoryLimit
			}
			fields[key] = value
		}
	}
	if limited.N <= 0 {
		return nil, "", ErrInventoryLimit
	}
	if scanner.Err() != nil {
		return nil, "", ErrInventoryRead
	}
	if ctx.Err() != nil {
		return nil, "", ErrInventoryRead
	}
	if err := flush(); err != nil {
		return nil, "", err
	}
	if stanzaCount == 0 {
		return nil, "", ErrInventoryEmpty
	}
	return packages, hex.EncodeToString(hash.Sum(nil)), nil
}
func parseDpkgRecord(f map[string]string) (InstalledPackage, bool, error) {
	p := InstalledPackage{Name: f["Package"], Version: f["Version"], Architecture: f["Architecture"], SourcePackage: f["Package"], SourceVersion: f["Version"], SourceMapping: "binary-default"}
	if !packageName.MatchString(p.Name) {
		return p, false, ErrInventoryInvalid
	}
	status := strings.Fields(f["Status"])
	if len(status) != 3 || !oneOf(status[0], "unknown", "install", "hold", "deinstall", "purge") || !oneOf(status[1], "ok", "reinstreq") || !oneOf(status[2], "not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed") {
		return p, false, ErrInventoryInvalid
	}
	if status[2] == "not-installed" || status[2] == "config-files" {
		return p, false, nil
	}
	if !ValidDebianVersion(p.Version) || !archName.MatchString(p.Architecture) {
		return p, false, ErrInventoryInvalid
	}
	p.InstallState = "incomplete"
	if status[2] == "installed" && status[1] == "ok" {
		p.InstallState = "installed"
	}
	if source, ok := f["Source"]; ok {
		parts := strings.Fields(source)
		if len(parts) < 1 || len(parts) > 2 || !packageName.MatchString(parts[0]) {
			return p, false, ErrInventoryInvalid
		}
		p.SourcePackage = parts[0]
		p.SourceMapping = "source-field"
		if len(parts) == 2 {
			version := parts[1]
			if len(version) < 3 || version[0] != '(' || version[len(version)-1] != ')' {
				return p, false, ErrInventoryInvalid
			}
			p.SourceVersion = version[1 : len(version)-1]
			if !ValidDebianVersion(p.SourceVersion) {
				return p, false, ErrInventoryInvalid
			}
		}
	}
	return p, true, nil
}
func oneOf(v string, choices ...string) bool {
	for _, c := range choices {
		if v == c {
			return true
		}
	}
	return false
}

type LocalDebianInventory struct{}

// Collect opens one fixed regular file. It never calls apt/dpkg-query, invokes
// hooks, refreshes a cache, enumerates users/files, or guesses a derivative OS.
func (LocalDebianInventory) Collect(ctx context.Context, p Platform, now time.Time) Inventory {
	if runtime.GOOS != "linux" || !p.supportedDebian() {
		return unknownInventory(p, now, "inventory_adapter_unimplemented")
	}
	const path = "/var/lib/dpkg/status"
	info, err := os.Lstat(path)
	if err != nil {
		return unknownInventory(p, now, inventoryErrorReason(err))
	}
	if !info.Mode().IsRegular() {
		return unknownInventory(p, now, "package_database_not_regular")
	}
	file, err := os.Open(path)
	if err != nil {
		return unknownInventory(p, now, inventoryErrorReason(err))
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return unknownInventory(p, now, "package_database_changed")
	}
	if opened.Size() > MaxInventoryBytes {
		return unknownInventory(p, now, "inventory_limit_exceeded")
	}
	packages, digest, err := ParseDpkgStatus(ctx, file)
	if err != nil {
		return unknownInventory(p, now, err.Error())
	}
	final, err := file.Stat()
	if err != nil || final.Size() != opened.Size() || !final.ModTime().Equal(opened.ModTime()) {
		return unknownInventory(p, now, "package_database_changed")
	}
	result := InventoryFromParsed(p, packages, SourceSnapshot{ID: "dpkg-" + digest, Provider: "dpkg-status", Kind: "inventory", SHA256: digest, FetchedAt: now.UTC(), ValidatedAt: now.UTC(), ExpiresAt: now.UTC().Add(15 * time.Minute), Trust: "local"}, now)
	return result
}
func inventoryErrorReason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "package_database_unavailable"
	case errors.Is(err, os.ErrPermission):
		return "package_database_denied"
	default:
		return "package_database_read_failed"
	}
}

// InventoryFromParsed is a trusted adapter boundary, not a wire deserializer.
// Only validated package rows and adapter-supplied provenance belong here.
func InventoryFromParsed(p Platform, packages []InstalledPackage, source SourceSnapshot, now time.Time) Inventory {
	installed := 0
	for _, pkg := range packages {
		if pkg.InstallState == "installed" {
			installed++
		}
	}
	return Inventory{SchemaVersion: SchemaVersion, Platform: p, Source: source, Packages: append([]InstalledPackage(nil), packages...), InstalledCount: count(installed), Quality: Quality{Coverage: Assessed, Freshness: source.FreshnessAt(now), Scope: "dpkg-installed-and-incomplete-packages", ExcludedScopes: []string{"non-dpkg-software", "running-process-activation", "host-scope-not-established"}, AssessedAt: now.UTC(), AssessedItems: count(len(packages)), UnassessedItems: count(0)}}
}
