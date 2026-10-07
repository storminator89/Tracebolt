// Package signedhttp verifies signed observations exclusively for the explicit,
// insecure HTTP LAN test profile. It provides neither confidentiality nor server
// authentication. It does not replace mutual TLS, persist credentials, open a
// listener, or commit observations/replay state.
package signedhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lantrust"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	Path                      = "/v1/agent/telemetry"
	WindowsPath               = "/v1/windows/agent/telemetry"
	MaxBodyBytes              = 72 * 1024
	MaxCertificateHeaderBytes = 4096
	MaxHeaderBytes            = 8192
	MaxAge                    = 2 * time.Minute
	ClockSkew                 = 30 * time.Second
	CertificateHeader         = "X-Tracebolt-Certificate"
	SequenceHeader            = "X-Tracebolt-Sequence"
	SignedAtHeader            = "X-Tracebolt-Signed-At"
	SignatureHeader           = "X-Tracebolt-Signature"
	domain                    = "Tracebolt insecure HTTP agent telemetry; Ed25519; v1"
)

var (
	ErrConfiguration = errors.New("signed HTTP test configuration is invalid")
	ErrUnauthorized  = errors.New("signed HTTP agent authentication failed")
	ErrRequest       = errors.New("signed HTTP request contract is invalid")
	ErrTooLarge      = errors.New("signed HTTP request exceeds its byte limit")
	ErrUnavailable   = errors.New("signed HTTP trust is unavailable")
)

// PublicCertificateAuthorizer checks current public certificate authorization.
// This lookup alone never proves possession; Verify retains the fixed Ed25519
// signature protocol and the caller must still atomically commit replay state.
type PublicCertificateAuthorizer interface {
	AuthorizePublicCertificate([]byte) (lantrust.Agent, error)
}

type Config struct {
	// Path is selected by trusted server configuration; empty preserves Path.
	// Only the fixed Linux/basic and Windows inventory telemetry routes are valid.
	Path     string
	Origin   string
	Registry PublicCertificateAuthorizer
}
type Verifier struct {
	origin, authority, path string
	registry                PublicCertificateAuthorizer
	now                     func() time.Time
}

// Verified is a detached request snapshot, not a committed telemetry receipt.
// The caller MUST match Sequence to frame.Sequence and SignedAt to the frame's
// GeneratedAt, validate the whole frame, and atomically persist observation +
// replay state while rechecking durable approval/revocation. Never refresh age
// for an identical retry. Verification alone does not prevent cross-request or
// restart replay and cannot authorize a different body or device identifier.
type Verified struct {
	Agent    lantrust.Agent
	Body     []byte
	Sequence uint64
	SignedAt time.Time
}

func New(config Config) (*Verifier, error) {
	if config.Path == "" {
		config.Path = Path
	}
	if !validPath(config.Path) {
		return nil, ErrConfiguration
	}
	authority, err := canonicalOrigin(config.Origin)
	if err != nil || config.Registry == nil || (reflect.ValueOf(config.Registry).Kind() == reflect.Pointer && reflect.ValueOf(config.Registry).IsNil()) {
		return nil, ErrConfiguration
	}
	return &Verifier{origin: config.Origin, authority: authority, path: config.Path, registry: config.Registry, now: func() time.Time { return time.Now().UTC() }}, nil
}

func canonicalOrigin(origin string) (string, error) {
	if len(origin) == 0 || len(origin) > 512 {
		return "", ErrConfiguration
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || origin != "http://"+u.Host || u.Host != strings.ToLower(u.Host) {
		return "", ErrConfiguration
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.String() != host {
			return "", ErrConfiguration
		}
	} else {
		if len(host) == 0 || len(host) > 253 {
			return "", ErrConfiguration
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrConfiguration
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
					return "", ErrConfiguration
				}
			}
		}
	}
	port := u.Port()
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || n == 80 || strconv.Itoa(n) != port {
			return "", ErrConfiguration
		}
		authority = net.JoinHostPort(host, port)
	}
	if u.Host != authority {
		return "", ErrConfiguration
	}
	return authority, nil
}

func singleton(header http.Header, name string) (string, bool) {
	var values []string
	for key, list := range header {
		if strings.EqualFold(key, name) {
			values = append(values, list...)
		}
	}
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && returnValue != ""
}
func requestHeaders(header http.Header) bool {
	size := 128 // Reserve framing/host space in addition to the bounded header map.
	for key, list := range header {
		lower := strings.ToLower(key)
		if lower == "cookie" || lower == "authorization" || lower == "proxy-authorization" || lower == "origin" || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "sec-fetch-") || lower == "content-encoding" || lower == "trailer" {
			return false
		}
		for _, value := range list {
			size += len(key) + len(value) + 4
			if size > MaxHeaderBytes {
				return false
			}
		}
	}
	contentType, ok := singleton(header, "Content-Type")
	return ok && contentType == "application/json"
}
func canonicalSequence(text string) (uint64, bool) {
	sequence, err := strconv.ParseUint(text, 10, 63)
	return sequence, err == nil && sequence != 0 && strconv.FormatUint(sequence, 10) == text
}
func canonicalTime(text string, now time.Time) (time.Time, bool) {
	if len(text) > 30 {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, text)
	return at, err == nil && at.UTC().Format(time.RFC3339Nano) == text && now.Sub(at) <= MaxAge && at.Sub(now) <= ClockSkew
}
func decodeBase64(text string, limit int) ([]byte, bool) {
	if text == "" || len(text) > limit {
		return nil, false
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(text)
	return raw, err == nil && base64.RawStdEncoding.EncodeToString(raw) == text
}
func validPath(path string) bool { return path == Path || path == WindowsPath }

func transcript(origin, fingerprint, sequence, signedAt string, body []byte) []byte {
	return transcriptForPath(origin, Path, fingerprint, sequence, signedAt, body)
}
func transcriptForPath(origin, path, fingerprint, sequence, signedAt string, body []byte) []byte {
	digest := sha256.Sum256(body)
	var message bytes.Buffer
	for _, field := range []string{domain, origin, http.MethodPost, path, "application/json", fingerprint, sequence, signedAt, hex.EncodeToString(digest[:])} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		message.Write(size[:])
		message.WriteString(field)
	}
	return message.Bytes()
}

// Verify consumes the body once. It refuses TLS requests so this verifier cannot
// quietly become an authentication fallback on the mutual-TLS HTTPS surface.
func (v *Verifier) Verify(req *http.Request) (Verified, error) {
	bad := func(err error) (Verified, error) { return Verified{}, err }
	if v == nil || v.registry == nil || v.now == nil || !validPath(v.path) || req == nil || req.URL == nil || req.TLS != nil || req.Method != http.MethodPost || req.Host != v.authority || req.URL.Path != v.path || req.URL.RawPath != "" || req.URL.RawQuery != "" || req.URL.ForceQuery || req.URL.Fragment != "" || req.URL.RawFragment != "" || req.URL.Opaque != "" || req.URL.User != nil || (req.URL.Scheme != "" && req.URL.Scheme != "http") || (req.URL.Host != "" && req.URL.Host != v.authority) || (req.RequestURI != "" && req.RequestURI != v.path) || len(req.TransferEncoding) != 0 || len(req.Trailer) != 0 || req.Body == nil || req.ContentLength <= 0 || !requestHeaders(req.Header) {
		return bad(ErrRequest)
	}
	if req.ContentLength > MaxBodyBytes {
		return bad(ErrTooLarge)
	}
	certText, ok1 := singleton(req.Header, CertificateHeader)
	sequenceText, ok2 := singleton(req.Header, SequenceHeader)
	timeText, ok3 := singleton(req.Header, SignedAtHeader)
	sigText, ok4 := singleton(req.Header, SignatureHeader)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return bad(ErrUnauthorized)
	}
	sequence, ok := canonicalSequence(sequenceText)
	if !ok {
		return bad(ErrUnauthorized)
	}
	signedAt, ok := canonicalTime(timeText, v.now())
	if !ok {
		return bad(ErrUnauthorized)
	}
	certDER, ok := decodeBase64(certText, MaxCertificateHeaderBytes)
	if !ok {
		return bad(ErrUnauthorized)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return bad(ErrUnauthorized)
	}
	publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(publicKey) {
		return bad(ErrUnauthorized)
	}
	signature, ok := decodeBase64(sigText, base64.RawStdEncoding.EncodedLen(ed25519.SignatureSize))
	if !ok || len(signature) != ed25519.SignatureSize {
		return bad(ErrUnauthorized)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if _, err := v.registry.AuthorizePublicCertificate(publicPEM); err != nil {
		if errors.Is(err, lantrust.ErrRegistryUnavailable) {
			return bad(ErrUnavailable)
		}
		return bad(ErrUnauthorized)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxBodyBytes+1))
	if err != nil {
		return bad(ErrRequest)
	}
	if len(body) > MaxBodyBytes {
		return bad(ErrTooLarge)
	}
	if int64(len(body)) != req.ContentLength {
		return bad(ErrRequest)
	}
	if !ed25519.Verify(publicKey, transcriptForPath(v.origin, v.path, lantrust.Fingerprint(cert), sequenceText, timeText, body), signature) {
		return bad(ErrUnauthorized)
	}
	// A slow body may cross expiry/revocation/time boundaries; recheck before
	// returning. The durable observation transaction performs the final check.
	if _, ok := canonicalTime(timeText, v.now()); !ok {
		return bad(ErrUnauthorized)
	}
	agent, err := v.registry.AuthorizePublicCertificate(publicPEM)
	if err != nil {
		if errors.Is(err, lantrust.ErrRegistryUnavailable) {
			return bad(ErrUnavailable)
		}
		return bad(ErrUnauthorized)
	}
	return Verified{Agent: agent, Body: body, Sequence: sequence, SignedAt: signedAt}, nil
}

// NewSignedRequest prepares an HTTP request using an already provided Ed25519
// key pair. It creates no key, reads no file, and sends nothing. The returned
// request is plaintext; a caller must explicitly choose the insecure HTTP test
// profile, disable proxies/redirects and accept that the server is unauthenticated.
func NewSignedRequest(ctx context.Context, origin string, certificate tls.Certificate, sequence uint64, signedAt time.Time, body []byte) (*http.Request, error) {
	return NewSignedRequestForPath(ctx, origin, Path, certificate, sequence, signedAt, body)
}

// NewSignedRequestForPath binds a finite, explicitly selected telemetry route.
// It never accepts an arbitrary URL path or rewrites an existing signature.
func NewSignedRequestForPath(ctx context.Context, origin, path string, certificate tls.Certificate, sequence uint64, signedAt time.Time, body []byte) (*http.Request, error) {
	if !validPath(path) {
		return nil, ErrConfiguration
	}
	if _, err := canonicalOrigin(origin); err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > MaxBodyBytes || sequence == 0 || sequence > 1<<63-1 || len(certificate.Certificate) == 0 {
		return nil, ErrRequest
	}
	cert, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, ErrUnauthorized
	}
	key, ok := certificate.PrivateKey.(ed25519.PrivateKey)
	public, publicOK := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PrivateKeySize || !publicOK || !keyvalidation.Ed25519(public) || !bytes.Equal(key.Public().(ed25519.PublicKey), public) {
		return nil, ErrUnauthorized
	}
	certText := base64.RawStdEncoding.EncodeToString(cert.Raw)
	if len(certText) > MaxCertificateHeaderBytes {
		return nil, ErrTooLarge
	}
	timeText := signedAt.UTC().Format(time.RFC3339Nano)
	if _, ok := canonicalTime(timeText, time.Now().UTC()); !ok {
		return nil, ErrRequest
	}
	sequenceText := strconv.FormatUint(sequence, 10)
	bodyCopy := bytes.Clone(body)
	signature := ed25519.Sign(key, transcriptForPath(origin, path, lantrust.Fingerprint(cert), sequenceText, timeText, bodyCopy))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(bodyCopy))
	if err != nil {
		return nil, ErrRequest
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(CertificateHeader, certText)
	req.Header.Set(SequenceHeader, sequenceText)
	req.Header.Set(SignedAtHeader, timeText)
	req.Header.Set(SignatureHeader, base64.RawStdEncoding.EncodeToString(signature))
	return req, nil
}
