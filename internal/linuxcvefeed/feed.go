// Package linuxcvefeed provides an explicit fixed-origin Debian feed fetch and
// protected last-good cache. It has no scheduler, endpoint collector, credentials,
// repository configuration, or configurable remote URL.
package linuxcvefeed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/linuxcve"
	"mime"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	DebianURL     = "https://security-tracker.debian.org/tracker/data/json"
	FetchTimeout  = 45 * time.Second
	MaxFeedBytes  = linuxcve.MaxBundleBytes - 1024
	MaxCacheBytes = (linuxcve.MaxBundleBytes+2)/3*4 + 4096
	cacheSchema   = "tracebolt.linux-cve-cache.v1"
	officialKind  = "debian_https"
	importKind    = "operator_import"
)

var (
	ErrFetch       = errors.New("linux_cve_fetch_failed")
	ErrResponse    = errors.New("linux_cve_response_invalid")
	ErrParse       = errors.New("linux_cve_parse_failed")
	ErrCache       = errors.New("linux_cve_cache_invalid")
	ErrIO          = errors.New("linux_cve_cache_io")
	ErrUnsafe      = errors.New("linux_cve_cache_unsafe")
	ErrLocked      = errors.New("linux_cve_cache_locked")
	ErrUnsupported = errors.New("linux_cve_cache_unsupported")
	ErrNotLoaded   = errors.New("linux_cve_cache_not_loaded")
	ErrUncertain   = errors.New("linux_cve_cache_commit_uncertain")
)

// Candidate contains parsed immutable records and their exact original bytes.
// Neither an HTTP request nor an imported JSON member can set its provenance.
// Prepare before the operator commit lease; Commit is the only state mutation.
type Candidate struct {
	snapshot *linuxcve.Snapshot
	encoded  []byte
}

func (c *Candidate) Metadata(now time.Time) linuxcve.FeedMetadata {
	if c == nil {
		return (*linuxcve.Snapshot)(nil).Metadata(now)
	}
	return c.snapshot.Metadata(now)
}

type cacheEnvelope struct {
	SchemaVersion string    `json:"schemaVersion"`
	Provider      string    `json:"provider"`
	Kind          string    `json:"kind"`
	FetchedAt     time.Time `json:"fetchedAt"`
	SHA256        string    `json:"sha256"`
	PayloadSHA256 string    `json:"payloadSha256"`
	// A byte string, rather than RawMessage, preserves exact fetched bytes.
	Data []byte `json:"data"`
}

type storage interface {
	read(string) ([]byte, error)
	replace(string, []byte) error
	close() error
}

type Cache struct {
	mu     sync.Mutex
	disk   storage
	client *http.Client
	loaded bool
	closed bool
	last   map[string]linuxcve.FeedMetadata
}

// New opens (or creates only the final component of) a dedicated 0700 directory.
// Its existing parent must already be protected. It makes no network request.
// The lifetime lock prevents two managers from replacing the same cache.
func New(cacheDir string) (*Cache, error) {
	disk, err := openStorage(cacheDir)
	if err != nil {
		return nil, err
	}
	return &Cache{disk: disk, client: newHTTPClient(), last: make(map[string]linuxcve.FeedMetadata)}, nil
}

func newHTTPClient() *http.Client {
	transport := &http.Transport{
		// Never use proxy environment variables or caller-provided credentials.
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxConnsPerHost:        1,
	}
	return &http.Client{Transport: transport, Timeout: FetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (c *Cache) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
	if c.disk == nil {
		return nil
	}
	return c.disk.close()
}

// FetchDebian performs exactly one credential-free GET with static headers to
// DebianURL. Redirects, compressed bodies, non-JSON responses and oversized or
// invalid documents fail closed. The combined fetch and parse deadline is 45s.
func (c *Cache) FetchDebian(ctx context.Context, now time.Time) (*Candidate, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, linuxcve.ErrCanceled
	}
	if c == nil || c.client == nil || !validTime(now) {
		return nil, linuxcve.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DebianURL, nil)
	if err != nil {
		return nil, ErrFetch
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "Tracebolt-CVE-Feed/1")
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, linuxcve.ErrCanceled
		}
		return nil, ErrFetch
	}
	defer resp.Body.Close()
	contentType, _, typeErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	encoding := resp.Header.Get("Content-Encoding")
	if resp.StatusCode != http.StatusOK || typeErr != nil || contentType != "application/json" || (encoding != "" && encoding != "identity") || resp.Uncompressed {
		return nil, ErrResponse
	}
	if resp.ContentLength > MaxFeedBytes {
		return nil, fmt.Errorf("%w: %w", ErrResponse, linuxcve.ErrLimit)
	}
	raw, err := readBounded(ctx, resp.Body, MaxFeedBytes)
	if err != nil {
		if errors.Is(err, linuxcve.ErrLimit) {
			return nil, fmt.Errorf("%w: %w", ErrResponse, err)
		}
		return nil, err
	}
	if resp.ContentLength >= 0 && int64(len(raw)) != resp.ContentLength {
		return nil, ErrResponse
	}
	snapshot, err := linuxcve.ParseOfficialDebian(ctx, bytes.NewReader(raw), now, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	candidate, err := prepareCandidate(ctx, snapshot, raw, officialKind, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	return candidate, nil
}

// PrepareImport retains the parser's unverified operator-import provenance.
// This accepts only an envelope, never an arbitrary URL or official-trust flag.
func (c *Cache) PrepareImport(ctx context.Context, r io.Reader, now time.Time) (*Candidate, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, linuxcve.ErrCanceled
	}
	if c == nil || r == nil || !validTime(now) {
		return nil, linuxcve.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := readBounded(ctx, r, linuxcve.MaxBundleBytes)
	if err != nil {
		return nil, err
	}
	snapshot, err := linuxcve.Parse(ctx, bytes.NewReader(raw), now)
	if err != nil {
		return nil, err
	}
	return prepareCandidate(ctx, snapshot, raw, importKind, now)
}

func prepareCandidate(ctx context.Context, snapshot *linuxcve.Snapshot, raw []byte, kind string, now time.Time) (*Candidate, error) {
	m := snapshot.Metadata(now)
	h := sha256.Sum256(raw)
	envelope := cacheEnvelope{SchemaVersion: cacheSchema, Provider: m.Provider, Kind: kind, FetchedAt: m.FetchedAt, SHA256: hex.EncodeToString(h[:]), PayloadSHA256: m.SHA256, Data: raw}
	encoded, err := json.Marshal(envelope)
	if ctx.Err() != nil {
		return nil, linuxcve.ErrCanceled
	}
	if err != nil || len(encoded) > MaxCacheBytes {
		return nil, linuxcve.ErrLimit
	}
	return &Candidate{snapshot: snapshot, encoded: encoded}, nil
}

// Load must run before the first Commit. It never fetches, promotes staging
// files, or resets an imported timestamp. Each provider is independently valid;
// one corrupt provider does not discard the other provider's last-good records.
func (c *Cache) Load(ctx context.Context, store *linuxcve.Store, now time.Time) error {
	if ctx == nil || ctx.Err() != nil {
		return linuxcve.ErrCanceled
	}
	if c == nil || store == nil || !validTime(now) {
		return linuxcve.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.disk == nil {
		return ErrIO
	}
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	var first error
	for _, provider := range []string{linuxcve.DebianProvider, linuxcve.UbuntuProvider} {
		name, _ := providerFilename(provider)
		raw, err := c.disk.read(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil {
			var snapshot *linuxcve.Snapshot
			snapshot, err = restore(ctx, raw, provider, now)
			if err == nil {
				err = store.Replace(snapshot, now)
			}
			if err == nil {
				c.last[provider] = snapshot.Metadata(now)
			}
		}
		if first == nil && err != nil {
			first = err
		}
	}
	// A canceled partial read cannot establish the persistent rollback floor of
	// an unexamined provider. Require a completed reload before any commit.
	c.loaded = ctx.Err() == nil
	if ctx.Err() != nil {
		first = linuxcve.ErrCanceled
	}
	if first != nil {
		store.RecordFailure(now, first.Error())
	}
	return first
}

// Commit must be called inside the live operator commit lease. It rejects
// rollback, durably stages/replaces one fixed file, then atomically publishes
// memory under Store.ReplaceWith. Fetch/validation are deliberately absent.
func (c *Cache) Commit(candidate *Candidate, store *linuxcve.Store, now time.Time) error {
	if c == nil || candidate == nil || candidate.snapshot == nil || len(candidate.encoded) == 0 || len(candidate.encoded) > MaxCacheBytes || store == nil || !validTime(now) {
		return linuxcve.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.disk == nil {
		return ErrIO
	}
	if !c.loaded {
		return ErrNotLoaded
	}
	m := candidate.Metadata(now)
	name, err := providerFilename(m.Provider)
	if err != nil {
		return err
	}
	if prior, ok := c.last[m.Provider]; ok && (m.FetchedAt.Before(prior.FetchedAt) || m.FetchedAt.Equal(prior.FetchedAt) && m.SHA256 != prior.SHA256) {
		return linuxcve.ErrRollback
	}
	if err = store.ReplaceWith(candidate.snapshot, now, func() error { return c.disk.replace(name, candidate.encoded) }); err != nil {
		if errors.Is(err, ErrUncertain) {
			c.loaded = false
		}
		return err
	}
	c.last[m.Provider] = m
	return nil
}

func restore(ctx context.Context, raw []byte, provider string, now time.Time) (*linuxcve.Snapshot, error) {
	if len(raw) == 0 || len(raw) > MaxCacheBytes {
		return nil, ErrCache
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var envelope cacheEnvelope
	if err := d.Decode(&envelope); err != nil {
		return nil, ErrCache
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, ErrCache
	}
	// Canonical encoding rejects duplicate keys as well as silently ignored JSON
	// members. Only this writer produces caches; arbitrary local imports use Parse.
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(raw, canonical) || envelope.SchemaVersion != cacheSchema || envelope.Provider != provider || !validTime(envelope.FetchedAt) || envelope.FetchedAt.After(now) || len(envelope.Data) == 0 || len(envelope.Data) > linuxcve.MaxBundleBytes {
		return nil, ErrCache
	}
	h := sha256.Sum256(envelope.Data)
	if envelope.SHA256 != hex.EncodeToString(h[:]) {
		return nil, ErrCache
	}
	var snapshot *linuxcve.Snapshot
	switch envelope.Kind {
	case officialKind:
		if provider != linuxcve.DebianProvider || len(envelope.Data) > MaxFeedBytes {
			return nil, ErrCache
		}
		snapshot, err = linuxcve.ParseOfficialDebian(ctx, bytes.NewReader(envelope.Data), envelope.FetchedAt, now)
	case importKind:
		snapshot, err = linuxcve.Parse(ctx, bytes.NewReader(envelope.Data), now)
	default:
		return nil, ErrCache
	}
	if err != nil {
		return nil, err
	}
	m := snapshot.Metadata(now)
	if m.Provider != provider || !m.FetchedAt.Equal(envelope.FetchedAt) || m.SHA256 != envelope.PayloadSHA256 {
		return nil, ErrCache
	}
	return snapshot, nil
}

func providerFilename(provider string) (string, error) {
	switch provider {
	case linuxcve.DebianProvider:
		return "debian-security-tracker.json", nil
	case linuxcve.UbuntuProvider:
		return "canonical-ubuntu-osv.json", nil
	default:
		return "", linuxcve.ErrInvalid
	}
}

func validTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 }

func readBounded(ctx context.Context, r io.Reader, max int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(contextReader{ctx, r}, max+1))
	if ctx.Err() != nil {
		return nil, linuxcve.ErrCanceled
	}
	if err != nil {
		return nil, ErrFetch
	}
	if int64(len(raw)) > max {
		return nil, linuxcve.ErrLimit
	}
	return raw, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, linuxcve.ErrCanceled
	}
	return r.reader.Read(p)
}
