// Package bootstrapfetch retrieves public enrollment configuration only. A
// selected checksum is byte integrity, not publisher or binary authenticity.
// This package never reads an invitation secret or fetches executable content.
package bootstrapfetch

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/lanclient"
	"net/http"
	"strings"
)

const MaxBootstrapBytes = 64 << 10
const MaxPublicCABytes = 32 << 10

var ErrRequest = errors.New("public bootstrap fetch parameters are invalid")
var ErrFetch = errors.New("public bootstrap fetch was not verified")

type Request struct {
	ManagerOrigin    string
	InvitationID     string // Public identifier, never the one-time invitation secret.
	ExpectedSHA256   string
	ServerCABase64   string // Canonical base64 of public certificates only.
	InsecureHTTPTest bool
}

// Fetch binds the exact response bytes to a separately selected checksum, then
// applies the existing strict parser and all explicit origin/profile/CA checks.
// Public CA input is not installed globally and normal TLS verification remains.
func Fetch(ctx context.Context, in Request) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !validDigest(in.ExpectedSHA256) {
		return nil, ErrRequest
	}
	profile := "tls"
	var ca []byte
	if in.InsecureHTTPTest {
		profile = "http-test"
		if in.ServerCABase64 != "" {
			return nil, ErrRequest
		}
	} else {
		if len(in.ServerCABase64) == 0 || len(in.ServerCABase64) > base64.StdEncoding.EncodedLen(MaxPublicCABytes) {
			return nil, ErrRequest
		}
		var err error
		ca, err = base64.StdEncoding.Strict().DecodeString(in.ServerCABase64)
		if err != nil || len(ca) == 0 || len(ca) > MaxPublicCABytes || base64.StdEncoding.EncodeToString(ca) != in.ServerCABase64 {
			return nil, ErrRequest
		}
	}
	client, err := lanclient.NewPublicBootstrapHTTPClient(in.ManagerOrigin, profile, ca, in.InvitationID)
	if err != nil {
		return nil, ErrRequest
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, in.ManagerOrigin+lanclient.PublicBootstrapPathPrefix+in.InvitationID, nil)
	if err != nil {
		return nil, ErrRequest
	}
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return nil, ErrFetch
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > MaxBootstrapBytes || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Content-Encoding")) != 0 || response.Uncompressed {
		return nil, ErrFetch
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxBootstrapBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxBootstrapBytes || ctx.Err() != nil {
		return nil, ErrFetch
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != in.ExpectedSHA256 {
		return nil, ErrFetch
	}
	b, err := enrollmentclient.ParseBootstrap(raw)
	if err != nil || b.EnrollmentOrigin != in.ManagerOrigin || b.InvitationID != in.InvitationID || b.Profile != profile || b.ServerCAPEM != string(ca) {
		return nil, ErrFetch
	}
	return raw, nil
}
func validDigest(s string) bool {
	if len(s) != 64 || strings.Trim(s, "0") == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
