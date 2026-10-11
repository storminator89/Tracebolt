package lanclient

import "localrmm/internal/windowsresourcecontext"

func ValidateWindowsResourceContextWorkerRequest(path string, request windowsresourcecontext.Request) (windowsresourcecontext.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowsresourcecontext.Request{}, ErrState
	}
	c, ok := readWindowsResourceContextConsent(m)
	if !ok || c != request.Consent || !validResourceContextConsent(c, m.binding) {
		return windowsresourcecontext.Request{}, ErrState
	}
	return request, nil
}
