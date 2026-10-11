package lanclient

import (
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

// reload is a private test seam; production always uses Load. The protected
// config/ready receipt is read again even after Load to catch replacement races.
func currentWindowsContextMaterial(m Material, reload func(string) (Material, error)) bool {
	if !m.valid() || !m.config.windowsInventory() || reload == nil {
		return false
	}
	current, e := reload(m.configPath)
	return e == nil && current.binding == m.binding && current.config == m.config && validateUpdatesActivatedMaterial(m.configPath, current) == nil
}

// Native receipt lookup is separated only to exercise each reader's authority
// boundary against disposable files without looking up a Windows service SID.
type windowsContextConsentStore interface {
	Read(string) ([]byte, error)
	Close() error
}
type windowsContextConsentDependencies struct {
	reload func(string) (Material, error)
	open   func(string, windowsstate.Options) (windowsContextConsentStore, error)
}

func openWindowsContextConsent(path string, options windowsstate.Options) (windowsContextConsentStore, error) {
	sid, err := windowsservice.LookupServiceSID()
	if err != nil {
		return nil, err
	}
	options.RuntimeSID = sid
	return windowsstate.Open(path, options)
}
