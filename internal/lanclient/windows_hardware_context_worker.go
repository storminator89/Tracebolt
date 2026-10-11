package lanclient

import "localrmm/internal/windowshardware"

func ValidateWindowsHardwareContextWorkerRequest(path string, request windowshardware.Request) (windowshardware.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowshardware.Request{}, ErrState
	}
	c, ok := readWindowsHardwareContextConsent(m)
	if !ok || c != request.Consent || !validHardwareContextConsent(c, m.binding) {
		return windowshardware.Request{}, ErrState
	}
	return request, nil
}
