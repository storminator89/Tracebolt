package lanclient

import "localrmm/internal/windowssecurity"

func ValidateWindowsSecurityPostureWorkerRequest(path string, request windowssecurity.Request) (windowssecurity.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowssecurity.Request{}, ErrState
	}
	c, ok := readWindowsSecurityPostureConsent(m)
	if !ok || c != request.Consent || !validSecurityPostureConsent(c, m.binding) {
		return windowssecurity.Request{}, ErrState
	}
	return request, nil
}
