// windows-action-manager-setup is an explicit source-only create-only local
// manager provisioning command. It never generates keys, grants endpoint rights,
// starts a listener or dispatches a service action. Native use needs separate approval.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"localrmm/internal/actionmanager"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
	"localrmm/internal/packagecontroller"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionmanager"
	"os"
	"path/filepath"
	"sort"
	"time"
)

var errSetup = errors.New("Windows action setup blocked; preserve existing state and review the supplied configuration")

type plan struct {
	PlanDigest    string                `json:"planDigest"`
	Version       string                `json:"version"`
	Binding       windowsaction.Binding `json:"binding"`
	BindingDigest string                `json:"bindingDigest"`
	Profile       string                `json:"profile"`
	Operators     []string              `json:"operators"`
	Status        string                `json:"status"`
	Notice        string                `json:"notice"`
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("windows-action-manager-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	lan := flags.String("lan-config", "", "Existing protected LAN config")
	enrollment := flags.String("enrollment-config", "", "Existing protected guided enrollment config")
	bindingPath := flags.String("binding-file", "", "Protected exact public broker Binding JSON")
	apply := flags.Bool("apply", false, "Explicitly create manager action state once")
	approve := flags.String("approve-plan", "", "Exact reviewed public plan digest, including binding, transport and named operators")
	acknowledge := flags.Bool("ack-windows-service-control", false, "Approve persistent selected Windows service start/stop/restart authority for the listed named operators")
	httpRisk := flags.Bool("ack-http-action-risk", false, "Acknowledge plaintext operator session and action authorization theft in disposable HTTP")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *lan == "" || *enrollment == "" || *bindingPath == "" || !*apply && (*approve != "" || *acknowledge || *httpRisk) {
		return errSetup
	}
	now := time.Now().UTC()
	m, e := lanconfig.Load(*lan)
	if e != nil || !m.Config.WindowsInventoryEnabled || m.Config.WindowsServiceActionsConfigFile == "" || len(m.Operators) == 0 {
		return errSetup
	}
	en, e := enrollmentconfig.Load(*enrollment, m, now)
	if e != nil {
		return errSetup
	}
	cfg, e := en.WindowsStoreConfig()
	if e != nil {
		return errSetup
	}
	raw, e := lanconfig.ReadProtected(*bindingPath, true, windowsaction.MaxMessageBytes)
	if e != nil {
		return errSetup
	}
	var binding windowsaction.Binding
	if windowsaction.DecodeCanonical(raw, &binding, windowsaction.MaxMessageBytes) != nil || !windowsaction.ValidBinding(binding) || binding.ManagerID != cfg.Binding.InstanceID {
		return errSetup
	}
	forbidden := []ed25519.PublicKey{}
	for _, der := range append([][]byte{en.Issuer().IssuerDER(), en.Issuer().RootDER()}, m.Server.Certificate...) {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return errSetup
		}
		if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			forbidden = append(forbidden, pub)
		}
	}
	// Existing Linux command material is public-key compared, never adopted.
	if m.Config.ServiceActionsConfigFile != "" {
		var c actionmanager.Config
		b, e := lanconfig.ReadProtected(m.Config.ServiceActionsConfigFile, true, 4096)
		if e != nil || json.Unmarshal(b, &c) != nil {
			return errSetup
		}
		key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
		if e != nil || len(key) != ed25519.PrivateKeySize {
			clear(key)
			return errSetup
		}
		forbidden = append(forbidden, append(ed25519.PublicKey(nil), key[ed25519.SeedSize:]...))
		clear(key)
	}

	if m.Config.PackageActionsConfigFile != "" {
		var c packagecontroller.Config
		b, e := lanconfig.ReadProtected(m.Config.PackageActionsConfigFile, true, 8192)
		if e != nil || json.Unmarshal(b, &c) != nil {
			return errSetup
		}
		key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
		if e != nil || len(key) != ed25519.PrivateKeySize {
			clear(key)
			return errSetup
		}
		forbidden = append(forbidden, append(ed25519.PublicKey(nil), key[ed25519.SeedSize:]...))
		clear(key)
	}
	_, public, e := windowsactionmanager.InspectConfiguration(m.Config.WindowsServiceActionsConfigFile, cfg.Binding.InstanceID, cfg.Binding.Profile, forbidden...)
	if e != nil || windowsaction.Digest(public) != binding.KeyID {
		return errSetup
	}
	dbPath := filepath.Join(m.Config.StateDirectory, enrollmentconfig.WindowsDatabaseFile)
	inspection, e := enrollmentstore.InspectWindowsServiceActionSetup(context.Background(), dbPath, en.Issuer().IssuerDER(), binding.EndpointID, now)
	if e != nil || inspection.Status != "absent" || inspection.Config != cfg || binding.IncarnationDigest != "sha256:"+inspection.Identity.Issuance.CertificateHash {
		return errSetup
	}
	p := plan{Version: "tracebolt.windows-service-action-manager-plan.v1", Binding: binding, BindingDigest: windowsaction.Digest(raw), Profile: cfg.Binding.Profile, Operators: []string{}, Status: "absent", Notice: "Persistent authority for this exact activated Windows identity and one locally reviewed broker target. Each start/stop/restart still requires a named operator's exact preview approval. No endpoint grant, service change, listener, or first action is performed by this command."}
	for _, op := range m.Operators {
		for _, cap := range op.Capabilities {
			if cap == operatorauth.WindowsServiceControl {
				p.Operators = append(p.Operators, op.ID)
			}
		}
	}
	if len(p.Operators) == 0 {
		return errSetup
	}
	sort.Strings(p.Operators)
	canonical, _ := json.Marshal(p)
	p.PlanDigest = windowsaction.Digest(canonical)
	if !*apply {
		return json.NewEncoder(out).Encode(p)
	}
	if !*acknowledge || *approve != p.PlanDigest || (*httpRisk != (cfg.Binding.Profile == "http-test")) {
		return errSetup
	}
	// The existing path was verified without writes. Opening cannot turn missing
	// used optional state into a new domain: its immutable credential marker wins.
	s, e := enrollmentstore.Open(dbPath, cfg, en.Issuer().IssuerDER())
	if e != nil {
		return errSetup
	}
	defer s.Close()
	if e = s.SetupWindowsServiceActionsCreateOnly(context.Background(), public, binding, time.Now().UTC()); e != nil {
		return errSetup
	}
	manager, e := windowsactionmanager.Load(context.Background(), s, m.Config.WindowsServiceActionsConfigFile, forbidden...)
	if e != nil {
		return errSetup
	}
	manager.Close()
	_, e = fmt.Fprintln(out, "Created the exact Windows manager action domain. No service action was requested. Preserve this database and its immutable used-state fence.")
	return e
}
func main() {
	if e := run(os.Args[1:], os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
