package actionwire

import (
	"net/http"
	"strconv"
	"strings"
)

// ValidateShape is framing only, never identity or possession authorization.
func ValidateShape(r *http.Request, authority, profile string) error {
	if profile != "tls" && profile != "http-test" {
		return ErrConfiguration
	}
	scheme := "https"
	if profile == "http-test" {
		scheme = "http"
	}
	if r == nil || r.URL == nil || r.Method != http.MethodPost || r.Host != authority || !validPath(r.URL.Path) || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" || r.URL.Opaque != "" || r.URL.User != nil || (r.URL.Scheme != "" && r.URL.Scheme != scheme) || (r.URL.Host != "" && r.URL.Host != authority) || (r.RequestURI != "" && r.RequestURI != r.URL.Path) || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.Body == nil || r.ContentLength <= 0 || !requestHeaders(r.Header) {
		return ErrRequest
	}
	if r.ContentLength > BodyLimit(r.URL.Path) {
		return ErrTooLarge
	}
	if (profile == "tls") != (r.TLS != nil) {
		return ErrRequest
	}
	lengths := 0
	for key, values := range r.Header {
		lower := strings.ToLower(key)
		if profile == "http-test" && strings.HasPrefix(lower, "x-tracebolt-") && lower != strings.ToLower(CertificateHeader) && lower != strings.ToLower(SequenceHeader) && lower != strings.ToLower(SignedAtHeader) && lower != strings.ToLower(SignatureHeader) {
			return ErrRequest
		}
		if lower == "expect" || lower == "upgrade" || lower == "host" || lower == "transfer-encoding" {
			return ErrRequest
		}
		if lower == "content-length" {
			lengths += len(values)
			if len(values) != 1 || values[0] != strconv.FormatInt(r.ContentLength, 10) {
				return ErrRequest
			}
		}
	}
	if lengths > 1 {
		return ErrRequest
	}
	if profile == "tls" {
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-tracebolt-") {
				return ErrRequest
			}
		}
	}
	return nil
}
