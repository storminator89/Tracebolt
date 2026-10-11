package lanclient

import "localrmm/internal/windowssecuritycoverage"

func ValidateWindowsSecurityCoverageWorkerRequest(path string, request windowssecuritycoverage.Request) (windowssecuritycoverage.Request, error) {
	m, err := Load(path)
	if err != nil || !m.config.windowsInventory() || m.binding != request.SenderBinding || validateUpdatesActivatedMaterial(path, m) != nil {
		return windowssecuritycoverage.Request{}, ErrState
	}
	c, ok := readWindowsSecurityCoverageConsent(m)
	if !ok || c != request.Consent || !validSecurityCoverageConsent(c, m.binding) {
		return windowssecuritycoverage.Request{}, ErrState
	}
	return request, nil
}
