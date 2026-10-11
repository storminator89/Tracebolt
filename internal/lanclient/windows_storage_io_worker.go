package lanclient

import "localrmm/internal/windowsstorageio"

func ValidateWindowsStorageIOWorkerRequest(path string, request windowsstorageio.Request) (windowsstorageio.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowsstorageio.Request{}, ErrState
	}
	c, ok := readWindowsStorageIOConsent(m)
	if !ok || c != request.Consent || !validStorageIOConsent(c, m.binding) {
		return windowsstorageio.Request{}, ErrState
	}
	return request, nil
}
