//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsusersoftware"
	"localrmm/internal/windowsusersoftwarelocal"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func userSoftwareLocal(t *testing.T, m Material, at time.Time) *fullSoftwareMemory {
	t.Helper()
	st := &fullSoftwareMemory{files: map[string][]byte{}}
	if e := windowsusersoftware.InitializeState(st, m.config.AgentID, m.binding); e != nil {
		t.Fatal(e)
	}
	c := windowsusersoftware.Consent{SchemaVersion: windowsusersoftware.ConsentVersion, Scope: windowsusersoftware.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("c", 32), Revision: 1, Enabled: true, ChangedAt: at}
	st.files["consent.json"], _ = windowsusersoftware.EncodeConsent(c)
	return st
}
func userSoftwarePeer() windowsusersoftwarelocal.Peer {
	return windowsusersoftwarelocal.Peer{SID: "S-1-5-21-100-200-300-1001", ProcessID: 91, SessionID: 2}
}
func userSoftwareCapture(at time.Time, n int) windowsusersoftware.Capture {
	rows := make([]windowsusersoftware.Row, n)
	for i := range rows {
		name := fmt.Sprintf("SelectedProgram%04d", i)
		version, publisher := "1.0", "Invented publisher"
		source := "hkcu"
		if i%2 != 0 {
			source = "msix"
		}
		rows[i] = windowsusersoftware.Row{RegistrationID: fmt.Sprintf("%064x", i+1), Source: source, Name: &name, NameQuality: "observed", Version: &version, VersionQuality: "observed", Publisher: &publisher, PublisherQuality: "observed"}
	}
	return windowsusersoftware.Capture{StartedAt: at, FinishedAt: at, Rows: rows, HKCUStatus: "complete", MSIXStatus: "complete", Complete: true}
}
func TestWindowsUserSoftwareForegroundToManagerExactRetryAndPages(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			ctx := context.Background()
			f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", profile)
			if e := f.store.InitializeWindowsUserSoftware(ctx); e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC()
			st := userSoftwareLocal(t, f.material, now)
			sender, e := newUserSoftwareSender(f.material, st, func() time.Time { return time.Now().UTC() })
			if e != nil {
				t.Fatal(e)
			}
			peer := userSoftwarePeer()
			ch, e := sender.Begin(ctx, peer, strings.Repeat("a", 64))
			if e != nil {
				t.Fatal(e)
			}
			if ch.DeviceID != f.material.config.AgentID || ch.ManagerOrigin != f.material.config.ManagerOrigin || ch.InsecureHTTP != (profile == "http-test") {
				t.Fatal("destination omitted or changed")
			}
			// Consent-free begin cannot consume/read/send. Scheduler never performs collection.
			if sender.state.Floor() != 0 {
				t.Fatal("begin consumed capture")
			}
			out, e := sender.Burst(ctx)
			if e != nil || out.Operations != 0 || out.Status != "foreground_pending" {
				t.Fatal("scheduler interfered with explicit foreground consent", out, e)
			}
			if e = sender.Reserve(ctx, peer, ch); e != nil {
				t.Fatal(e)
			}
			if e = sender.Reserve(ctx, peer, ch); e == nil {
				t.Fatal("capture reserved twice")
			}
			cap := userSoftwareCapture(time.Now().UTC(), 257)
			cap.AccountContextID = strings.Repeat("f", 64)
			cap.AccountLabel = "Untrusted label"
			cap.CaptureNonce = strings.Repeat("e", 64)
			if e = sender.Submit(ctx, peer, ch, cap); e != nil {
				t.Fatal(e)
			}
			if e = sender.Submit(ctx, peer, ch, cap); e == nil {
				t.Fatal("consumed capture resubmitted")
			}
			client := fullSoftwareSocket(t, f)
			transport := client.Transport
			var lostBody, originalReceipt []byte
			lost, replayed := false, false
			client.Transport = fullSoftwareRoundTrip(func(r *http.Request) (*http.Response, error) {
				body, e := io.ReadAll(r.Body)
				if e != nil {
					return nil, e
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
				result, e := transport.RoundTrip(r)
				if e != nil {
					return nil, e
				}
				m, e := windowsusersoftware.DecodeMessage(body)
				if e != nil {
					return result, nil
				}
				if m.Operation == "chunk" && m.Index == 0 {
					b, e := io.ReadAll(result.Body)
					result.Body.Close()
					if e != nil {
						return nil, e
					}
					if !lost {
						lost = true
						lostBody = bytes.Clone(body)
						originalReceipt = bytes.Clone(b)
						return nil, errors.New("invented lost acknowledgement")
					}
					if !bytes.Equal(lostBody, body) || !bytes.Equal(originalReceipt, b) {
						t.Error("retry or receipt changed")
					}
					replayed = true
					result.Body = io.NopCloser(bytes.NewReader(b))
				}
				return result, nil
			})
			sender.client = client
			out, e = sender.Burst(ctx)
			if e != windowsusersoftware.ErrTransport || out.Status != "pending_retained" || !lost {
				t.Fatal(out, e)
			}
			q := windowsusersoftware.Query{Sort: "name-asc", Limit: 100}
			page, e := f.store.WindowsUserSoftwarePage(ctx, f.material.config.AgentID, q, time.Now().UTC())
			if e != nil || page.Complete != nil || len(page.Rows) != 0 {
				t.Fatal("incomplete chunks disclosed", e)
			}
			sender.Close()
			sender, e = newUserSoftwareSender(f.material, st, func() time.Time { return time.Now().UTC() })
			if e != nil {
				t.Fatal(e)
			}
			defer sender.Close()
			sender.client = client
			out, e = sender.Burst(ctx)
			if e != nil || out.Status != "complete" || !replayed || sender.state.Floor() != 1 {
				t.Fatal("restart lost exact pending", out, e)
			}
			count := 0
			for {
				page, e = f.store.WindowsUserSoftwarePage(ctx, f.material.config.AgentID, q, time.Now().UTC())
				if e != nil || page.Status != "ready" || page.AccountContextID != ch.AccountContextID || page.Complete.Manifest.AccountLabel != ch.AccountLabel || page.Complete.Manifest.CaptureNonce != ch.Nonce || page.Complete.Manifest.RowCount != 257 {
					t.Fatal("account/source binding lost", e)
				}
				count += len(page.Rows)
				if page.NextCursor == "" {
					break
				}
				q.Cursor = page.NextCursor
				q.AccountContextID = ch.AccountContextID
			}
			if count != 257 {
				t.Fatal("complete rows not pageable", count)
			}
			q = windowsusersoftware.Query{AccountContextID: ch.AccountContextID, Source: "msix", Search: "SelectedProgram0255", Sort: "name-asc", Limit: 100}
			page, e = f.store.WindowsUserSoftwarePage(ctx, f.material.config.AgentID, q, time.Now().UTC())
			if e != nil || page.MatchingCount != 1 || len(page.Rows) != 1 || page.Rows[0].Source != "msix" {
				t.Fatal("source search missing", e)
			}
			ordinary, e := f.store.LatestObservations(ctx)
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(ordinary)
			if bytes.Contains(raw, []byte("SelectedProgram")) || bytes.Contains(raw, []byte(ch.AccountContextID)) {
				t.Fatal("selected-account data leaked to ordinary/AI projection")
			}
			c, _ := windowsusersoftware.DecodeConsent(st.files["consent.json"])
			c.Enabled = false
			c.Revision++
			c.ChangedAt = time.Now().UTC()
			st.files["consent.json"], _ = windowsusersoftware.EncodeConsent(c)
			out, e = sender.Burst(ctx)
			if e != nil || out.Status != "disabled" || sender.state.Floor() != 1 {
				t.Fatal("disable reset or recaptured", out, e)
			}
			if _, e = sender.Begin(ctx, peer, strings.Repeat("b", 64)); e == nil {
				t.Fatal("disabled local receiver admitted capture")
			}
		})
	}
}

func TestWindowsUserSoftwareChallengeOwnershipAbortExpiryAndNoRecapture(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "tls")
	now := time.Now().UTC()
	st := userSoftwareLocal(t, f.material, now)
	s, e := newUserSoftwareSender(f.material, st, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	peer := userSoftwarePeer()
	ch, e := s.Begin(ctx, peer, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	other := peer
	other.ProcessID++
	if e = s.Reserve(ctx, other, ch); e == nil {
		t.Fatal("different process admitted")
	}
	other = peer
	other.SID = "S-1-5-21-100-200-300-1002"
	if e = s.Reserve(ctx, other, ch); e == nil {
		t.Fatal("different account admitted")
	}
	if e = s.Abort(ctx, peer, ch); e != nil || s.active != nil || s.state.Floor() != 0 {
		t.Fatal("decline did not release observational challenge")
	}
	ch, e = s.Begin(ctx, peer, strings.Repeat("b", 64))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Reserve(ctx, peer, ch); e != nil {
		t.Fatal(e)
	}
	now = now.Add(16 * time.Second)
	if e = s.Submit(ctx, peer, ch, userSoftwareCapture(now, 1)); e == nil {
		t.Fatal("late capture accepted")
	}
	if e = s.Abort(ctx, peer, ch); e != nil || s.state.Floor() != 1 || !s.state.Pending() {
		t.Fatal("reserved abort lost consume-once failure", e)
	}
	if _, e = s.Begin(ctx, peer, strings.Repeat("c", 64)); e == nil {
		t.Fatal("pending attempt replaced")
	}
	raw, _, e := s.state.Next(mustUserSoftwareConsent(t, st), now)
	if e != nil {
		t.Fatal(e)
	}
	m, e := windowsusersoftware.DecodeMessage(raw)
	if e != nil || m.Operation != "failure" || m.AccountContextID != ch.AccountContextID || m.CaptureNonce != ch.Nonce {
		t.Fatal("wrong failed identity", e)
	}
}
func mustUserSoftwareConsent(t *testing.T, st *fullSoftwareMemory) windowsusersoftware.Consent {
	t.Helper()
	c, e := windowsusersoftware.DecodeConsent(st.files["consent.json"])
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestWindowsUserSoftwareDefaultOffAndUsedRootCannotBeRecreated(t *testing.T) {
	at := time.Now().UTC()
	marker := &fullSoftwareTestMarker{}
	var root *fullSoftwareMemory
	creates := 0
	open := func(create bool) (windowsusersoftware.Storage, error) {
		if root == nil && !create {
			return nil, os.ErrNotExist
		}
		if create {
			creates++
			root = &fullSoftwareMemory{files: map[string][]byte{}}
		}
		return root, nil
	}
	device, binding := "agent_"+strings.Repeat("1", 32), strings.Repeat("a", 64)
	r, e := updateWindowsUserSoftwareConsent(device, binding, "preview", open, func() time.Time { return at }, marker)
	if e != nil || r.Enabled || creates != 0 || marker.used {
		t.Fatal("preview enabled scope")
	}
	r, e = updateWindowsUserSoftwareConsent(device, binding, "enable", open, func() time.Time { return at }, marker)
	if e != nil || !r.Enabled || creates != 1 || !marker.used {
		t.Fatal("explicit enable failed", e)
	}
	root = nil
	for _, mode := range []string{"preview", "enable", "disable"} {
		if _, e = updateWindowsUserSoftwareConsent(device, binding, mode, open, func() time.Time { return at }, marker); e == nil || creates != 1 {
			t.Fatal("used root recreated", mode)
		}
	}
	if s, e := openWindowsUserSoftwareSender(Material{}, nil); e != nil || s != nil {
		t.Fatal("absent scope not inert")
	}
}
