//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanconfig"
	"localrmm/internal/windowseventwire"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWindowsEventOuterMuxExactNamespaceIsolation(t *testing.T) {
	primary := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("fixture-route", "primary")
		w.WriteHeader(202)
	})
	windows := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("fixture-route", "windows")
		w.WriteHeader(203)
	})
	paths := []string{windowseventwire.CapabilityPath, windowseventwire.PeekPath, windowseventwire.ClaimPath, windowseventwire.ResultPath, windowseventwire.StatusPath, "/v1/windows/agent/telemetry"}
	for _, path := range paths {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			w := httptest.NewRecorder()
			withWindowsIngress(primary, windows).ServeHTTP(w, httptest.NewRequest(method, "https://manager.test"+path, nil))
			if w.Code != 203 || w.Header().Get("fixture-route") != "windows" {
				t.Fatal("exact Windows path not routed to authenticating ingress", path, method)
			}
		}
		w := httptest.NewRecorder()
		withWindowsIngress(primary, nil).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://manager.test"+path, nil))
		if w.Code != 404 || w.Header().Get("fixture-route") != "" {
			t.Fatal("disabled Windows scope fell through to primary", path)
		}
	}
	for _, path := range []string{windowseventwire.PathPrefix, windowseventwire.PeekPath + "/", windowseventwire.PathPrefix + "unknown", "/v1/windows/agent/journal", "/v1/windows/agent/actions"} {
		w := httptest.NewRecorder()
		withWindowsIngress(primary, windows).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://manager.test"+path, nil))
		if w.Code != 404 || w.Header().Get("fixture-route") != "" {
			t.Fatal("unknown Windows route escaped explicit allowlist", path)
		}
	}
	for _, path := range []string{"/v1/agent/telemetry", "/v3/agent/journal/peek", "/v3/agent/actions/peek"} {
		w := httptest.NewRecorder()
		withWindowsIngress(primary, windows).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "https://manager.test"+path, nil))
		if w.Code != 202 || w.Header().Get("fixture-route") != "primary" {
			t.Fatal("Linux namespace routed into Windows scope", path)
		}
	}
}

func TestWindowsEventPreparedRuntimeRequiresIndependentScopeAndAuthentication(t *testing.T) {
	for _, profile := range []string{lanconfig.TLS, lanconfig.HTTPTest} {
		t.Run(profile, func(t *testing.T) {
			m, enrolled, configPath := guidedFixture(t, profile)
			p, err := prepareWithEnrollment(m, &enrolled)
			if err != nil {
				t.Fatal(err)
			}
			if p.windowsMaintenance != nil {
				t.Fatal("Windows manager scope enabled without configuration")
			}
			p.close()
			m.Config.WindowsInventoryEnabled = true
			enrolled, err = enrollmentconfig.Load(configPath, m, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			p, err = prepareWithEnrollment(m, &enrolled)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			if p.windowsMaintenance == nil || p.windowsMaintenance.Binding().CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || p.windowsMaintenance.WindowsEventCache() == nil {
				t.Fatal("Windows runtime did not configure its isolated ephemeral cache")
			}
			if err := p.windowsMaintenance.MaintainWindowsEventContent(context.Background(), p.windowsMaintenance.Now()); err != nil {
				t.Fatal("prepared Windows metadata maintenance", err)
			}
			for _, path := range []string{windowseventwire.CapabilityPath, windowseventwire.PeekPath, windowseventwire.ClaimPath, windowseventwire.ResultPath, windowseventwire.StatusPath} {
				r := httptest.NewRequest(http.MethodPost, m.Config.AgentOrigin+path, bytes.NewBufferString("{}"))
				r.RequestURI = path
				r.Header.Set("Content-Type", "application/json")
				if profile == lanconfig.TLS {
					r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
				} else {
					r.TLS = nil
				}
				w := httptest.NewRecorder()
				p.agent.ServeHTTP(w, r)
				if w.Code != 403 {
					t.Fatal("real prepared Windows route bypassed authentication or was unreachable", path, w.Code, w.Body.String())
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := runWindowsEventMaintenance(ctx, p.windowsMaintenance, nil); err != nil {
				t.Fatal("configured loop did not stop cleanly", err)
			}
		})
	}
}
