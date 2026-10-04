package agentinstall

import (
	"context"
	"strings"
	"testing"
)

func TestOnlineBootstrapPreparationRejectsIncompleteContract(t *testing.T) {
	// Invalid shape fails before inspecting root/systemd/TTY or opening artifacts.
	r := Request{Action: Install, Apply: true, AgentBinary: "/fixture/lan-agent", EnrollBinary: "/fixture/enroll-agent", SourceArchive: "/fixture/source.tar", AgentSHA256: strings.Repeat("a", 64), EnrollSHA256: strings.Repeat("b", 64), SourceSHA256: strings.Repeat("c", 64), BootstrapSHA256: strings.Repeat("d", 64)}
	for _, kind := range []string{"dry-run", "action", "bootstrap", "hash", "relative"} {
		t.Run(kind, func(t *testing.T) {
			bad := r
			switch kind {
			case "dry-run":
				bad.Apply = false
			case "action":
				bad.Action = Restart
			case "bootstrap":
				bad.BootstrapFile = "/already/local.json"
			case "hash":
				bad.BootstrapSHA256 = "invalid"
			case "relative":
				bad.AgentBinary = "./lan-agent"
			}
			if ValidateOnlineBootstrapPreparation(context.Background(), bad) == nil {
				t.Fatal("invalid online input accepted")
			}
		})
	}
	if ValidateOnlineBootstrapPreparation(nil, r) == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ValidateOnlineBootstrapPreparation(ctx, r) == nil {
		t.Fatal("canceled context accepted")
	}
}
