// Package macosservice prepares an inert launchd candidate and performs explicit,
// local read-only checks. Its create-only lifecycle coordinator has no native
// mutation adapter; fake backends exercise ownership and phase ordering only.
package macosservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"strconv"
	"strings"
)

const (
	BasicProfile        = "basic-readonly-v1"
	InventoryProfile    = "macos-read-inventory-v1"
	Account             = "_traceboltagent"
	Label               = "com.tracebolt.agent"
	InstallDirectory    = "/Library/Application Support/TraceboltAgent"
	AgentPath           = InstallDirectory + "/macos-agent"
	StateDirectory      = InstallDirectory + "/state"
	EnrollmentDirectory = StateDirectory + "/enrollment"
	ConfigPath          = EnrollmentDirectory + "/agent.json"
	PlistPath           = "/Library/LaunchDaemons/" + Label + ".plist"
)

var ErrRequest = errors.New("invalid macOS service planning request")
var ErrPreflight = errors.New("macOS service read-only preflight blocked")

type Request struct {
	// Empty retains the historical basic-only default. Inventory must be explicit.
	Profile         string
	ServiceIdentity string
	AgentSHA256     string
	SourceArchive   string
	SourceSHA256    string
	RenderOnly      bool
}

type Check struct {
	Code   string `json:"code"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type Result struct {
	SchemaVersion         string   `json:"schemaVersion"`
	ReadOnly              bool     `json:"readOnly"`
	LocalChecksPerformed  bool     `json:"localChecksPerformed"`
	LocalPreflightPassed  bool     `json:"localPreflightPassed"`
	InstallationAvailable bool     `json:"installationAvailable"`
	ReadyForInstallation  bool     `json:"readyForInstallation"`
	ServiceIdentity       string   `json:"serviceIdentity"`
	CollectionProfile     string   `json:"collectionProfile"`
	ServiceAccount        string   `json:"serviceAccount"`
	AgentPath             string   `json:"agentPath"`
	AgentSHA256           string   `json:"agentSHA256"`
	SourceArchive         string   `json:"sourceArchive"`
	SourceSHA256          string   `json:"sourceSHA256"`
	ConfigPath            string   `json:"configPath"`
	PlistPath             string   `json:"plistPath"`
	Plist                 string   `json:"plist"`
	PlistSHA256           string   `json:"plistSHA256"`
	Checks                []Check  `json:"checks"`
	RemainingGates        []string `json:"remainingGates"`
}

// Backend can only inspect. It deliberately has no apply, account, enrollment,
// launchctl, rollback, file-write or deletion surface.
type Backend interface {
	Inspect(context.Context, Request) ([]Check, error)
}

var checkOrder = []string{"platform", "service-identity", "dedicated-account", "protected-paths", "agent-artifact", "source-artifact", "activated-enrollment", "plist-absent", "final-identity"}

func identity(raw string) (int, int, bool) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	uid, e1 := strconv.ParseUint(parts[0], 10, 32)
	gid, e2 := strconv.ParseUint(parts[1], 10, 32)
	if e1 != nil || e2 != nil || uid == 0 || gid == 0 || uid >= 1<<32-1 || gid >= 1<<32-1 || strconv.FormatUint(uid, 10) != parts[0] || strconv.FormatUint(gid, 10) != parts[1] {
		return 0, 0, false
	}
	return int(uid), int(gid), true
}
func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}
func validSourcePath(s string) bool {
	if !path.IsAbs(s) || path.Clean(s) != s || s == "/" || len(s) > 4096 || s == AgentPath || s == PlistPath || s == InstallDirectory || strings.HasPrefix(s, InstallDirectory+"/") {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 || r == '\ufffd' {
			return false
		}
	}
	return true
}
func selectedProfile(r Request) string {
	if r.Profile == "" {
		return BasicProfile
	}
	return r.Profile
}

func Plan(r Request) (Result, error) {
	if _, _, ok := identity(r.ServiceIdentity); !ok || (selectedProfile(r) != BasicProfile && selectedProfile(r) != InventoryProfile) || !validDigest(r.AgentSHA256) || !validDigest(r.SourceSHA256) || !validSourcePath(r.SourceArchive) {
		return Result{}, ErrRequest
	}
	plist := plistForRequest(r)
	sum := sha256.Sum256([]byte(plist))
	return Result{
		SchemaVersion: "tracebolt.macos-service-plan.v1", ReadOnly: true,
		CollectionProfile: selectedProfile(r), ServiceIdentity: r.ServiceIdentity, ServiceAccount: Account, AgentPath: AgentPath,
		AgentSHA256: r.AgentSHA256, SourceArchive: r.SourceArchive, SourceSHA256: r.SourceSHA256,
		ConfigPath: ConfigPath, PlistPath: PlistPath, Plist: plist, PlistSHA256: hex.EncodeToString(sum[:]),
		Checks: []Check{}, RemainingGates: []string{
			"This candidate cannot install, bootstrap, enable, restart, upgrade or uninstall a service; no native state was changed.",
			"An administrator must separately approve the exact existing dedicated account, reviewed artifacts, protected paths and launchd registration. This plan is not that approval.",
			"Check the native launchd system domain for foreign or retained jobs before any future create-only registration; an absent plist does not prove an absent job.",
			"Recheck account mapping, protected paths, exact artifacts and activated enrollment immediately before any separately implemented installation.",
			"A separately approved disposable Mac gate must establish native credential isolation, stop behavior, manager reporting and operating-system reboot persistence. Source checks and plist generation establish none of these.",
		},
	}, nil
}

// Execute does not execute the agent or contact the manager. Even a complete
// successful preflight remains explicitly not ready for installation.
func Execute(ctx context.Context, r Request, b Backend) (Result, error) {
	p, err := Plan(r)
	if err != nil {
		return p, err
	}
	if ctx == nil {
		return p, ErrRequest
	}
	if err = ctx.Err(); err != nil {
		return p, err
	}
	if r.RenderOnly {
		return p, nil
	}
	if b == nil {
		return p, ErrPreflight
	}
	p.LocalChecksPerformed = true
	p.Checks, err = b.Inspect(ctx, r)
	if p.Checks == nil {
		p.Checks = []Check{}
	}
	if err != nil {
		return p, ErrPreflight
	}
	if len(p.Checks) != len(checkOrder) {
		return p, ErrPreflight
	}
	for i, c := range p.Checks {
		if c.Code != checkOrder[i] || !c.Passed {
			return p, ErrPreflight
		}
	}
	if ctx.Err() != nil {
		return p, ErrPreflight
	}
	p.LocalPreflightPassed = true
	return p, nil
}
