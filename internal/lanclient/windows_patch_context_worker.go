package lanclient

import "localrmm/internal/windowspatchcontext"

func ValidateWindowsPatchContextWorkerRequest(path string, request windowspatchcontext.Request) (windowspatchcontext.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowspatchcontext.Request{}, ErrState
	}
	c, ok := readWindowsPatchContextConsent(m)
	if !ok || c != request.Consent || !validPatchContextConsent(c, m.binding) {
		return windowspatchcontext.Request{}, ErrState
	}
	return request, nil
}
