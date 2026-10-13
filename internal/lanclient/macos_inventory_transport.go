package lanclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"localrmm/internal/lantrust"
	sender "localrmm/internal/macosinventorysender"
	wire "localrmm/internal/macosinventorywire"
	"net/http"
)

// NewMacOSInventoryEnrollmentHTTPClient is the distinct fresh inventory route.
func NewMacOSInventoryEnrollmentHTTPClient(origin string, serverCAPEM []byte) (*http.Client, error) {
	return newBootstrapHTTPClient(origin, "tls", serverCAPEM, "/v2/macos-inventory/enrollment/")
}

// MacOSInventoryExchange owns exactly one admitted TLS credential. Enrollment
// supplies the protected provenance and keeps its exclusive lock while in use.
// Construction is inert; no generic Material or ordinary telemetry is accepted.
type MacOSInventoryExchange struct {
	client *http.Client
	origin string
	leaf   []byte
}

func (*MacOSInventoryExchange) String() string               { return "macOS inventory TLS exchange (redacted)" }
func (*MacOSInventoryExchange) MarshalJSON() ([]byte, error) { return []byte(`{"redacted":true}`), nil }
func NewMacOSInventoryExchange(origin string, pair tls.Certificate, ca, expectedLeaf []byte) (*MacOSInventoryExchange, error) {
	u, e := canonicalOrigin(origin, "https")
	if e != nil || len(pair.Certificate) != 2 || !bytes.Equal(pair.Certificate[0], expectedLeaf) {
		return nil, ErrConfiguration
	}
	config, e := lantrust.ClientTLSConfig(pair, ca, u.Hostname())
	if e != nil {
		return nil, ErrConfiguration
	}
	c := newHTTPClient(config, false)
	return &MacOSInventoryExchange{client: c, origin: origin, leaf: bytes.Clone(expectedLeaf)}, nil
}
func (x *MacOSInventoryExchange) Close() {
	if x != nil && x.client != nil {
		x.client.CloseIdleConnections()
	}
}
func (x *MacOSInventoryExchange) Exchange(ctx context.Context, path string, body []byte) ([]byte, error) {
	if x == nil || x.client == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrTransport
	}
	switch path {
	case sender.ControlPath:
		if _, e := wire.DecodeControl(body); e != nil {
			return nil, ErrTransport
		}
	case sender.ReportPath:
		if _, e := wire.DecodeReport(body); e != nil {
			return nil, ErrTransport
		}
	default:
		return nil, ErrTransport
	}
	// One bounded synchronous request; no retryable body or detached worker.
	run, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, e := http.NewRequestWithContext(run, http.MethodPost, x.origin+path, bytes.NewReader(body))
	if e != nil {
		return nil, ErrTransport
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, e := x.client.Do(req)
	if e != nil {
		return nil, ErrTransport
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.TLS == nil || res.TLS.Version < tls.VersionTLS13 || len(res.TLS.VerifiedChains) == 0 || res.Uncompressed || len(res.Header.Values("Content-Encoding")) != 0 || len(res.Header.Values("Content-Type")) != 1 || res.Header.Get("Content-Type") != "application/json" && res.Header.Get("Content-Type") != "application/json; charset=utf-8" || res.ContentLength > wire.MaxReceiptBytes {
		return nil, ErrTransport
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, wire.MaxReceiptBytes+1))
	if e != nil || len(raw) == 0 || len(raw) > wire.MaxReceiptBytes || run.Err() != nil {
		return nil, ErrTransport
	}
	if _, e = wire.DecodeReceipt(raw, body); e != nil {
		return nil, ErrReceipt
	}
	return raw, nil
}
