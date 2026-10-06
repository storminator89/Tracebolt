//go:build linux

package agentinstall

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"localrmm/internal/enrollmentclient"
)

func TestReadAdminNativePreflightRejectsOlderBootstrapWithoutEffects(t *testing.T) {
	for _, profile := range []string{"managed-operations-v1", "managed-operations-v2", "managed-operations-v3"} {
		t.Run(profile, func(t *testing.T) {
			request, backend, events := installerHostFixture(t)
			var public enrollmentclient.Bootstrap
			raw, err := os.ReadFile(request.BootstrapFile)
			if err != nil || json.Unmarshal(raw, &public) != nil {
				t.Fatal("fixture")
			}
			public.CollectionProfile = profile
			raw, _ = json.Marshal(public)
			if os.WriteFile(request.BootstrapFile, raw, 0600) != nil {
				t.Fatal("fixture write")
			}
			request.BootstrapSHA256 = sum(raw)
			request.RequireCompleteProfile = true
			request.ExpectedAgentOrigin = public.AgentOrigin
			facts, err := backend.Inspect(context.Background(), request)
			if (err == nil) != (profile == "managed-operations-v3") {
				t.Fatalf("profile preflight: %s, %v", profile, err)
			}
			if err == nil && (facts.CollectionProfile != profile || facts.AgentOrigin != public.AgentOrigin) {
				t.Fatal("complete bootstrap not bound to plan")
			}
			request.ExpectedAgentOrigin = "https://different.example:8444"
			if _, err := backend.Inspect(context.Background(), request); err == nil {
				t.Fatal("different unapproved ingress accepted")
			}
			if len(*events) != 0 {
				t.Fatal("preflight performed host effect")
			}
			if _, err := os.Lstat(backend.host.path(controlDirectory)); !os.IsNotExist(err) {
				t.Fatal("preflight created installer state")
			}
		})
	}
}
