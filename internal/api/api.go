// Package api exposes the deliberately loopback-only development manager.
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/model"
	"localrmm/internal/rules"
	"localrmm/internal/store"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

type Server struct {
	store  *store.Store
	port   int
	web    string
	csrf   string
	mu     sync.RWMutex
	sample model.Device
}

func New(s *store.Store, port int, web string, sample model.Device) (*Server, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("port out of range")
	}
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return nil, e
	}
	absolute, e := filepath.Abs(web)
	if e != nil {
		return nil, e
	}
	return &Server{store: s, port: port, web: absolute, csrf: hex.EncodeToString(raw), sample: sample}, nil
}
func (s *Server) SetSample(d model.Device)   { s.mu.Lock(); s.sample = d; s.mu.Unlock() }
func (s *Server) sampleDevice() model.Device { s.mu.RLock(); defer s.mu.RUnlock(); return s.sample }
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, message string) {
	write(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(remote)
	if err != nil || ip == nil || !ip.IsLoopback() {
		fail(w, 403, "loopback_required", "Only loopback clients are allowed.")
		return
	}
	authority1 := fmt.Sprintf("127.0.0.1:%d", s.port)
	authority2 := fmt.Sprintf("localhost:%d", s.port)
	if r.Host != authority1 && r.Host != authority2 {
		fail(w, 403, "invalid_host", "Host is not an allowed local authority.")
		return
	}
	origin := r.Header.Get("Origin")
	if len(r.Header.Values("Origin")) > 1 || (origin != "" && origin != "http://"+r.Host) {
		fail(w, 403, "invalid_origin", "Origin must match this local manager.")
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		fail(w, 403, "cross_site", "Cross-site requests are not allowed.")
		return
	}
	if len(r.TransferEncoding) > 0 {
		fail(w, 400, "invalid_framing", "Chunked request bodies are not accepted.")
		return
	}
	if strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, "\\") || strings.Contains(r.URL.EscapedPath(), "%") || strings.Contains(r.URL.Path, "/../") || strings.HasSuffix(r.URL.Path, "/..") || strings.Contains(r.URL.Path, "/./") {
		fail(w, 400, "invalid_path", "Path is not canonical.")
		return
	}
	for _, component := range strings.Split(r.URL.Path, "/") {
		if strings.HasPrefix(component, ".") {
			fail(w, 404, "not_found", "Hidden paths are not served.")
			return
		}
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if r.URL.RawQuery != "" {
			fail(w, 400, "invalid_query", "This endpoint does not accept query parameters.")
			return
		}
		s.api(w, r)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		h.Set("Allow", "GET, HEAD")
		fail(w, 405, "method_not_allowed", "Method is not supported.")
		return
	}
	s.static(w, r)
}
func (s *Server) devices() ([]model.Device, error) {
	ds, err := s.store.Devices()
	if err != nil {
		return nil, err
	}
	return append(ds, s.sampleDevice()), nil
}
func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if r.Method == "POST" {
		s.mutation(w, r)
		return
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		fail(w, 405, "method_not_allowed", "Method is not supported.")
		return
	}
	switch p {
	case "/api/health":
		write(w, 200, map[string]any{"status": "ok", "version": model.Version, "mode": "local-development"})
	case "/api/session":
		write(w, 200, map[string]string{"csrfToken": s.csrf})
	case "/api/capabilities":
		write(w, 200, map[string]any{"mode": "local-development", "version": model.Version, "syntheticFleet": true, "realCollector": "Linux sandbox: CPU, memory, root filesystem, OS only", "remoteEnrollment": false, "shellExecution": false, "aiConnected": false, "persistence": "SQLite", "limitations": []string{"Loopback-only development app; no production authentication or fleet enrollment.", "Seven synthetic devices are examples, not enrolled customer endpoints.", "The live Linux sample has sandbox scope and incomplete host visibility.", "Windows and macOS native collection are unimplemented stubs, cross-build checks only.", "No systemd, journal, service, software, update or vulnerability assessment is performed on the sandbox.", "Deterministic rules produce demo findings. No language model is connected.", "Runbooks are read-only guidance. No remote shell, jobs or remediation are available.", "SQLite state is local and not encrypted; protect your operating-system account and workspace.", "Metric quality healthy means observation validity; it does not mean the endpoint or metric is healthy."}})
	case "/api/devices":
		ds, e := s.devices()
		if e != nil {
			s.internal(w)
			return
		}
		write(w, 200, map[string]any{"items": ds, "total": len(ds)})
	case "/api/cases":
		cs, e := s.store.Cases()
		if e != nil {
			s.internal(w)
			return
		}
		write(w, 200, map[string]any{"items": cs, "total": len(cs)})
	case "/api/runbooks":
		bs := rules.Runbooks()
		write(w, 200, map[string]any{"items": bs, "total": len(bs)})
	case "/api/overview":
		ds, e := s.devices()
		if e != nil {
			s.internal(w)
			return
		}
		cs, e := s.store.Cases()
		if e != nil {
			s.internal(w)
			return
		}
		stats := model.Stats{TotalDevices: len(ds)}
		activity := []model.Activity{}
		for _, d := range ds {
			switch d.Status {
			case "healthy":
				stats.HealthyDevices++
			case "critical", "attention":
				stats.AttentionDevices++
			default:
				stats.UnknownDevices++
			}
		}
		for _, c := range cs {
			if c.Status != "resolved" {
				stats.OpenCases++
				if c.Severity == "critical" {
					stats.CriticalCases++
				}
			}
			activity = append(activity, c.Timeline...)
		}
		sort.SliceStable(activity, func(i, j int) bool { return activity[i].Time.After(activity[j].Time) })
		if len(activity) > 12 {
			activity = activity[:12]
		}
		write(w, 200, model.Overview{Product: "Tracebolt", Mode: "local-development", GeneratedAt: time.Now().UTC(), Stats: stats, Devices: ds, Cases: cs, Activity: activity})
	default:
		if strings.HasPrefix(p, "/api/devices/") {
			id := strings.TrimPrefix(p, "/api/devices/")
			if !validID(id) {
				fail(w, 404, "not_found", "Device not found.")
				return
			}
			ds, e := s.devices()
			if e != nil {
				s.internal(w)
				return
			}
			for _, d := range ds {
				if d.ID == id {
					write(w, 200, d)
					return
				}
			}
			fail(w, 404, "not_found", "Device not found.")
			return
		}
		if strings.HasPrefix(p, "/api/cases/") {
			id := strings.TrimPrefix(p, "/api/cases/")
			if !validID(id) {
				fail(w, 404, "not_found", "Case not found.")
				return
			}
			c, e := s.store.Case(id)
			if errors.Is(e, store.ErrNotFound) {
				fail(w, 404, "not_found", "Case not found.")
				return
			}
			if e != nil {
				s.internal(w)
				return
			}
			write(w, 200, c)
			return
		}
		fail(w, 404, "not_found", "Endpoint not found.")
	}
}
func validID(s string) bool {
	if len(s) < 1 || len(s) > 96 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
func (s *Server) internal(w http.ResponseWriter) {
	fail(w, 500, "storage_error", "Local state could not be read or saved.")
}

// oneField rejects unknown fields, duplicate keys, invalid Unicode, nonstrings and trailing JSON.
func oneField(body []byte, key string) (string, error) {
	if !utf8.Valid(body) || !json.Valid(body) {
		return "", errors.New("invalid JSON or UTF-8")
	}
	d := json.NewDecoder(strings.NewReader(string(body)))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return "", errors.New("expected object")
	}
	seen := false
	value := ""
	for d.More() {
		k, e := d.Token()
		if e != nil || k != key || seen {
			return "", errors.New("exactly one expected field required")
		}
		seen = true
		if e = d.Decode(&value); e != nil {
			return "", e
		}
	}
	if _, e = d.Token(); e != nil || !seen {
		return "", errors.New("expected one field")
	}
	if _, e = d.Token(); e != io.EOF {
		return "", errors.New("trailing JSON")
	}
	for _, r := range value {
		if r == utf8.RuneError || unicode.IsControl(r) && r != '\n' && r != '\t' {
			return "", errors.New("invalid text character")
		}
	}
	return value, nil
}
func (s *Server) mutation(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != "http://"+r.Host {
		fail(w, 403, "origin_required", "Same-origin header is required for local changes.")
		return
	}
	tokens := r.Header.Values("X-CSRF-Token")
	if len(tokens) != 1 || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(s.csrf)) != 1 {
		fail(w, 403, "csrf_required", "A current CSRF token is required.")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, 415, "json_required", "Content-Type must be application/json.")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "cases" || !validID(parts[2]) || (parts[3] != "notes" && parts[3] != "status") {
		fail(w, 404, "not_found", "Mutation endpoint not found.")
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if e != nil {
		var max *http.MaxBytesError
		if errors.As(e, &max) {
			fail(w, 413, "body_too_large", "Request body exceeds 4096 bytes.")
		} else {
			fail(w, 400, "invalid_body", "Request body could not be read.")
		}
		return
	}
	key := "text"
	kind := "note"
	if parts[3] == "status" {
		key = "status"
		kind = "status"
	}
	value, e := oneField(body, key)
	if e != nil {
		fail(w, 400, "invalid_json", "Exactly one valid string field is required.")
		return
	}
	value = strings.TrimSpace(value)
	if kind == "note" && (len(value) == 0 || len(value) > 2000) {
		fail(w, 400, "invalid_note", "Note must contain 1 to 2000 UTF-8 bytes.")
		return
	}
	if kind == "status" && value != "open" && value != "investigating" && value != "resolved" {
		fail(w, 400, "invalid_status", "Status must be open, investigating or resolved.")
		return
	}
	c, e := s.store.Mutate(parts[2], kind, value)
	if errors.Is(e, store.ErrNotFound) {
		fail(w, 404, "not_found", "Case not found.")
		return
	}
	if errors.Is(e, store.ErrLimit) {
		fail(w, 409, "local_limit", "Local case history limit reached.")
		return
	}
	if e != nil {
		s.internal(w)
		return
	}
	write(w, 200, c)
}
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.web, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/")))
	if r.URL.Path == "/" || filepath.Ext(r.URL.Path) == "" {
		path = filepath.Join(s.web, "index.html")
	}
	actual, e := filepath.EvalSymlinks(path)
	if e != nil {
		fail(w, 404, "ui_not_built", "UI file not found. Build web/dist first.")
		return
	}
	root, e := filepath.EvalSymlinks(s.web)
	if e != nil {
		fail(w, 404, "ui_not_built", "UI build is unavailable.")
		return
	}
	relative, e := filepath.Rel(root, actual)
	if e != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		fail(w, 403, "invalid_path", "Static path is outside the UI.")
		return
	}
	info, e := os.Stat(actual)
	if e != nil || !info.Mode().IsRegular() {
		fail(w, 404, "not_found", "File not found.")
		return
	}
	http.ServeFile(w, r, actual)
}
