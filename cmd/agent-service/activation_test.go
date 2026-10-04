package main

import (
	"bytes"
	"context"
	"errors"
	"localrmm/internal/agentinstall"
	"localrmm/internal/bootstrapfetch"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func onlineFixtureRequest() agentinstall.Request {
	return agentinstall.Request{Action: agentinstall.Install, Apply: true, AgentBinary: "/verified/lan-agent", AgentSHA256: strings.Repeat("a", 64), EnrollBinary: "/verified/enroll-agent", EnrollSHA256: strings.Repeat("b", 64), SourceArchive: "/verified/source.tar", SourceSHA256: strings.Repeat("c", 64), BootstrapSHA256: strings.Repeat("d", 64), InsecureHTTPTest: true}
}
func onlineFixtureFetch() bootstrapfetch.Request {
	return bootstrapfetch.Request{ManagerOrigin: "http://127.0.0.1:8787", InvitationID: "invite_00000000000000000000000000000001", ExpectedSHA256: strings.Repeat("d", 64), InsecureHTTPTest: true}
}
func TestCLIOnlineFlagsRequireApplyBeforeAnyBackendActivity(t *testing.T) {
	for _, args := range [][]string{
		{"--manager-origin", "http://127.0.0.1:8787", "--invitation-id", "invite_00000000000000000000000000000001"},
		{"--apply", "--manager-origin", "http://127.0.0.1:8787"},
		{"--action", "restart", "--apply", "--manager-origin", "http://127.0.0.1:8787", "--invitation-id", "invite_00000000000000000000000000000001"},
		{"--apply", "--manager-origin", "http://127.0.0.1:8787", "--invitation-id", "invite_00000000000000000000000000000001", "--bootstrap", "/local/bootstrap.json"},
	} {
		b := &inertBackend{}
		var out, stderr bytes.Buffer
		if run(context.Background(), args, &out, &stderr, b) != 2 || b.reads != 0 || b.begins != 0 {
			t.Fatal("online flags escaped early gate")
		}
	}
}
func TestOnlinePreparationGateBeforeFetchAndProtectedPublicSnapshot(t *testing.T) {
	r, in := onlineFixtureRequest(), onlineFixtureFetch()
	events := []string{}
	gate := func(_ context.Context, got agentinstall.Request) error {
		events = append(events, "preflight")
		if got != r {
			t.Fatal("request altered before preflight")
		}
		return nil
	}
	fetch := func(_ context.Context, got bootstrapfetch.Request) ([]byte, error) {
		events = append(events, "fetch")
		if got != in {
			t.Fatal("fetch contract altered")
		}
		return []byte(`{"synthetic":"public-only"}`), nil
	}
	prepared, cleanup, e := prepareOnlineBootstrap(context.Background(), r, in, gate, fetch)
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	if strings.Join(events, ",") != "preflight,fetch" || prepared.BootstrapFile == "" || prepared.BootstrapSHA256 != r.BootstrapSHA256 {
		t.Fatal("preparation order or binding changed")
	}
	info, e := os.Lstat(prepared.BootstrapFile)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("snapshot file unsafe")
	}
	dir, e := os.Lstat(filepath.Dir(prepared.BootstrapFile))
	if e != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 {
		t.Fatal("snapshot directory unsafe")
	}
	raw, e := os.ReadFile(prepared.BootstrapFile)
	if e != nil || string(raw) != `{"synthetic":"public-only"}` {
		t.Fatal("snapshot bytes changed")
	}
	if cleanup() != nil {
		t.Fatal("cleanup failed")
	}
	if _, e := os.Lstat(prepared.BootstrapFile); !os.IsNotExist(e) {
		t.Fatal("snapshot retained")
	}
}
func TestOnlinePreparationRejectsBeforeFetch(t *testing.T) {
	for _, kind := range []string{"dry-run", "action", "local-file", "checksum-mismatch", "profile-mismatch", "failed-preflight"} {
		t.Run(kind, func(t *testing.T) {
			r, in := onlineFixtureRequest(), onlineFixtureFetch()
			switch kind {
			case "dry-run":
				r.Apply = false
			case "action":
				r.Action = agentinstall.Upgrade
			case "local-file":
				r.BootstrapFile = "/local/bootstrap.json"
			case "checksum-mismatch":
				in.ExpectedSHA256 = strings.Repeat("e", 64)
			case "profile-mismatch":
				in.InsecureHTTPTest = false
			}
			fetches := 0
			gate := func(context.Context, agentinstall.Request) error {
				if kind == "failed-preflight" {
					return errors.New("fixture")
				}
				return nil
			}
			fetch := func(context.Context, bootstrapfetch.Request) ([]byte, error) { fetches++; return []byte("public"), nil }
			prepared, cleanup, e := prepareOnlineBootstrap(context.Background(), r, in, gate, fetch)
			defer cleanup()
			if e == nil || fetches != 0 || prepared != r {
				t.Fatal("invalid request fetched or staged")
			}
		})
	}
}
func TestOnlinePreparationCancellationAndBadFetchDoNotStage(t *testing.T) {
	for _, kind := range []string{"failed", "empty", "oversize", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, in := onlineFixtureRequest(), onlineFixtureFetch()
			fetch := func(context.Context, bootstrapfetch.Request) ([]byte, error) {
				switch kind {
				case "failed":
					return nil, errors.New("fixture")
				case "empty":
					return nil, nil
				case "oversize":
					return make([]byte, bootstrapfetch.MaxBootstrapBytes+1), nil
				default:
					cancel()
					return []byte("public"), nil
				}
			}
			prepared, cleanup, e := prepareOnlineBootstrap(ctx, r, in, func(context.Context, agentinstall.Request) error { return nil }, fetch)
			defer cleanup()
			if e == nil || prepared != r {
				t.Fatal("bad fetch staged snapshot")
			}
		})
	}
}
