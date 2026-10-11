package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsusersoftware"
	"os"
	"path/filepath"
	"time"
)

func windowsUserSoftwareDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-user-software"
}
func windowsUserSoftwareOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json", "sender.json", "pack.json"}, LockName: "user-software.lock", TempName: "user-software.tmp", MaxBytes: windowsusersoftware.MaxPackBytes, Create: create}
}

type WindowsUserSoftwareConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// This function is reachable only through the independent stopped-owned-service
// CLI. It neither widens existing grants nor changes the original sender ledger.
func ConfigureWindowsUserSoftware(path, mode string, acknowledged, insecure bool) (WindowsUserSoftwareConsentResult, error) {
	return configureWindowsUserSoftware(path, mode, acknowledged, insecure)
}

func configureWindowsUserSoftware(path, mode string, acknowledged, insecure bool) (WindowsUserSoftwareConsentResult, error) {
	zero := WindowsUserSoftwareConsentResult{}
	if mode != "preview" && mode != "enable" && mode != "disable" || acknowledged != (mode == "enable") {
		return zero, ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return zero, ErrState
	}
	m, e := Load(path)
	if e != nil || !m.config.windowsInventory() || insecure != (m.config.Profile == "http-test") || validateUpdatesActivatedMaterial(path, m) != nil {
		return zero, ErrConfiguration
	}
	main, e := lanclientstate.AcquireWindowsUserSoftwareInitialization(m.config.StateDirectory, m.binding)
	if e != nil {
		return zero, ErrState
	}
	defer main.Close()
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return zero, ErrState
	}
	out, e := updateWindowsUserSoftwareConsent(m.config.AgentID, m.binding, mode, func(create bool) (windowsusersoftware.Storage, error) {
		return windowsstate.Open(windowsUserSoftwareDirectory(m), windowsUserSoftwareOptions(sid, create))
	}, func() time.Time { return time.Now().UTC() }, main)
	if e != nil || main.Close() != nil {
		return zero, ErrState
	}
	return out, nil
}
func updateWindowsUserSoftwareConsent(device, binding, mode string, open func(bool) (windowsusersoftware.Storage, error), now func() time.Time, marker userSoftwareUsedMarker) (WindowsUserSoftwareConsentResult, error) {
	zero := WindowsUserSoftwareConsentResult{}
	scope := windowsusersoftware.Scope
	if open == nil || now == nil || marker == nil || mode != "preview" && mode != "enable" && mode != "disable" {
		return zero, ErrConfiguration
	}
	used, e := marker.Used()
	if e != nil {
		return zero, ErrState
	}
	st, e := open(false)
	fresh := false
	if errors.Is(e, os.ErrNotExist) && used {
		return zero, ErrState
	}
	if e == nil && !used {
		if st != nil {
			st.Close()
		}
		return zero, ErrState
	}
	if errors.Is(e, os.ErrNotExist) && mode == "enable" {
		if marker.Mark() != nil {
			return zero, ErrState
		}
		st, e = open(true)
		fresh = e == nil
	}
	if errors.Is(e, os.ErrNotExist) && mode != "enable" {
		return WindowsUserSoftwareConsentResult{scope, false, true}, nil
	}
	if e != nil || st == nil {
		return zero, ErrState
	}
	defer st.Close()
	if fresh {
		if windowsusersoftware.InitializeState(st, device, binding) != nil {
			return zero, ErrState
		}
	}
	state, e := windowsusersoftware.OpenState(st, device, binding)
	if e != nil {
		return zero, ErrState
	}
	raw, e := st.Read("consent.json")
	var c windowsusersoftware.Consent
	if e == nil {
		c, e = windowsusersoftware.DecodeConsent(raw)
		if e == nil && c.SenderBinding != binding {
			e = ErrState
		}
	} else if fresh && errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	if e != nil {
		return zero, ErrState
	}
	enabled := c.Enabled
	change := mode == "enable" && !enabled || mode == "disable" && enabled
	if change {
		at := now().UTC()
		if !windowsusersoftware.ValidTime(at) || !c.ChangedAt.IsZero() && at.Before(c.ChangedAt) || c.Revision == windowsusersoftware.MaxSequence {
			return zero, ErrState
		}
		if mode == "enable" {
			var id [16]byte
			if _, e = rand.Read(id[:]); e != nil {
				return zero, ErrState
			}
			next := windowsusersoftware.Consent{SchemaVersion: windowsusersoftware.ConsentVersion, Scope: windowsusersoftware.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Revision: c.Revision + 1, Enabled: mode == "enable", ChangedAt: at}
			c = next
		} else {
			c.Enabled = false
			c.Revision++
			c.ChangedAt = at
		}
		raw, e = windowsusersoftware.EncodeConsent(c)
		if e != nil || st.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	enabled = c.Enabled
	return WindowsUserSoftwareConsentResult{scope, enabled, true}, nil
}

type userSoftwareUsedMarker interface {
	Used() (bool, error)
	Mark() error
}
