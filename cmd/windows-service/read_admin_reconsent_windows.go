//go:build windows

package main

import (
	"context"
	"errors"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssetup"
	"localrmm/internal/windowsstate"
	"os"
	"time"
)

func nativeReadAdminReconsent(ctx context.Context, r request, installed installReceipt, lease receiptStore) (readAdminReconsentResult, error) {
	layout := installed.Service.Layout
	options := func(create bool) windowsstate.Options {
		return windowsstate.Options{InstallerOnly: true, Names: []string{"intent.json", "receipt.json"}, LockName: "read-admin.lock", TempName: "read-admin.tmp", MaxBytes: 64 << 10, Create: create}
	}
	path := layout.StateRoot + "-read-admin-setup"
	return readAdminReconsent(ctx, r, installed, readAdminReconsentSteps{
		executable: os.Executable,
		inspect:    windowsservice.InspectOwned,
		originalReceipt: func() ([]byte, error) {
			if e := lease.Verify(); e != nil {
				return nil, e
			}
			return lease.Read("receipt.json")
		},
		identity: lanclient.WindowsCapabilityIdentity,
		preview:  lanclient.PreviewWindowsReadAdmin,
		preserve: lanclient.VerifyWindowsReadAdminPreservedGrants,
		existingPhase: func() (string, error) {
			s, e := windowsstate.Open(path, options(false))
			if errors.Is(e, os.ErrNotExist) {
				return "absent", nil
			}
			if e != nil {
				return "", e
			}
			if s.Close() != nil {
				return "", errLifecycle
			}
			return "retained", nil
		},
		compatibility: func(ctx context.Context) error {
			b, e := bootstrap(layout)
			if e != nil {
				return e
			}
			if validateWindowsBootstrapConsent(b, readAdminSetupConsent(r.insecureHTTP).CollectionProfile, r.insecureHTTP) != nil {
				return errLifecycle
			}
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			return lanclient.CheckWindowsSetupManager(bounded, b.EnrollmentOrigin, b.Profile, []byte(b.ServerCAPEM), windowssetup.ExpectedReadAdmin(b.ManagerInstanceID, b.EnrollmentOrigin, b.AgentOrigin))
		},
		create: func() (setupJournal, error) {
			s, e := windowsstate.Open(path, options(true))
			if e != nil {
				return nil, e
			}
			return s, nil
		},
		configure: lanclient.ConfigureWindowsReadAdminCapabilities,
		digests:   lanclient.WindowsCapabilityGrantDigests,
	})
}
