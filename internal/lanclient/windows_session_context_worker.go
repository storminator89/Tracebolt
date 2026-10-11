package lanclient

import "localrmm/internal/windowssessions"

func ValidateWindowsSessionContextWorkerRequest(path string, request windowssessions.Request) (windowssessions.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowssessions.Request{}, ErrState
	}
	c, ok := readWindowsSessionContextConsent(m)
	if !ok || c != request.Consent || !validSessionContextConsent(c, m.binding) {
		return windowssessions.Request{}, ErrState
	}
	return request, nil
}
