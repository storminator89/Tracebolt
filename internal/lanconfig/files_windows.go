//go:build windows

package lanconfig

import (
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func ReadProtected(path string, private bool, limit int64) ([]byte, error) {
	sid, err := windowsservice.LookupServiceSID()
	if err != nil {
		return nil, ErrConfiguration
	}
	raw, err := windowsstate.ReadProtected(path, sid, private, limit)
	if err != nil {
		return nil, ErrConfiguration
	}
	return raw, nil
}
