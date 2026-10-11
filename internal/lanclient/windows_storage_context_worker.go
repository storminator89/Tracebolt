package lanclient

import "localrmm/internal/windowsstorage"

func ValidateWindowsStorageContextWorkerRequest(path string, request windowsstorage.Request) (windowsstorage.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowsstorage.Request{}, ErrState
	}
	c, ok := readWindowsStorageContextConsent(m)
	if !ok || c != request.Consent || !validStorageContextConsent(c, m.binding) {
		return windowsstorage.Request{}, ErrState
	}
	return request, nil
}
