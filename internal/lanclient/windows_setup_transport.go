package lanclient

import (
	"context"
	"io"
	"localrmm/internal/windowssetup"
	"net/http"
)

// NewWindowsSetupHTTPClient uses the existing explicit-CA, destination-vetted,
// no-proxy/no-redirect transport with exactly one public bodyless GET. The
// placeholder is only constructor validation; no invitation is transmitted.
func NewWindowsSetupHTTPClient(origin, profile string, serverCAPEM []byte) (*http.Client, error) {
	return newWindowsSetupHTTPClient(origin, profile, serverCAPEM, windowssetup.CapabilitiesPath)
}
func newWindowsSetupHTTPClient(origin, profile string, serverCAPEM []byte, path string) (*http.Client, error) {
	if path != windowssetup.CapabilitiesPath && path != windowssetup.ReadAdminCapabilitiesPath && path != windowssetup.ReadAdminCapabilitiesPathV2 {
		return nil, ErrConfiguration
	}
	c, err := NewPublicBootstrapHTTPClient(origin, profile, serverCAPEM, "invite_00000000000000000000000000000001")
	if err != nil {
		return nil, err
	}
	t, ok := c.Transport.(*publicBootstrapTransport)
	if !ok {
		c.CloseIdleConnections()
		return nil, ErrConfiguration
	}
	t.path = path
	return c, nil
}

// CheckWindowsSetupManager performs one bounded public request, before any
// endpoint files, persistent key, service or grants are created.
func CheckWindowsSetupManager(ctx context.Context, origin, profile string, serverCAPEM []byte, expected windowssetup.Capabilities) error {
	if ctx == nil {
		return windowssetup.ErrCompatibility
	}
	path, err := windowssetup.CapabilityPath(expected)
	if err != nil {
		return windowssetup.ErrCompatibility
	}
	c, err := newWindowsSetupHTTPClient(origin, profile, serverCAPEM, path)
	if err != nil {
		return windowssetup.ErrCompatibility
	}
	defer c.CloseIdleConnections()
	return checkWindowsSetupManager(ctx, c, origin, expected)
}
func checkWindowsSetupManager(ctx context.Context, c *http.Client, origin string, expected windowssetup.Capabilities) error {
	path, err := windowssetup.CapabilityPath(expected)
	if err != nil {
		return windowssetup.ErrCompatibility
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
	if err != nil {
		return windowssetup.ErrCompatibility
	}
	r.Header.Set("Accept", "application/json")
	response, err := c.Do(r)
	if err != nil {
		return windowssetup.ErrCompatibility
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || response.Header.Get("Content-Encoding") != "" || len(response.Header.Values("Set-Cookie")) != 0 || response.ContentLength > 2048 {
		return windowssetup.ErrCompatibility
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	if err != nil || windowssetup.Match(raw, expected) != nil {
		return windowssetup.ErrCompatibility
	}
	return nil
}
