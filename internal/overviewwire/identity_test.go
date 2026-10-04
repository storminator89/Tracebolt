package overviewwire

import (
	"localrmm/internal/inventorywire"
	"strings"
	"testing"
)

func TestGenerationIDBindsDeviceAndIndependentSequence(t *testing.T) {
	agent := "agent_" + strings.Repeat("1", 32)
	a, err := GenerationID(agent, "processes", 1)
	if err != nil || len(a) != 39 || !strings.HasPrefix(a, "sample_") {
		t.Fatal("valid binding rejected")
	}
	again, _ := GenerationID(agent, "processes", 1)
	next, _ := GenerationID(agent, "processes", 2)
	other, _ := GenerationID("agent_"+strings.Repeat("2", 32), "processes", 1)
	if a != again || a == next || a == other || next == other {
		t.Fatal("generation binding is not separated")
	}
	for _, bad := range []uint64{0, MaxSequence + 1, ^uint64(0)} {
		if got, err := GenerationID(agent, "processes", bad); err == nil || got != "" {
			t.Fatal("invalid sequence accepted")
		}
	}
	if got, err := GenerationID("body-selected-invalid", "processes", 1); err == nil || got != "" {
		t.Fatal("invalid identity accepted")
	}
}

func TestSectionAndLegacyDomainSeparation(t *testing.T) {
	agent := "agent_" + strings.Repeat("1", 32)
	process, _ := GenerationID(agent, "processes", 1)
	volume, _ := GenerationID(agent, "volumes", 1)
	legacy, _ := inventorywire.GenerationID(agent, 1)
	if process == legacy || volume == legacy {
		t.Fatal("legacy generation domain collided")
	}
	if process == volume {
		t.Fatal("section identity collided")
	}
	for _, section := range []string{"", "packages", "Processes", "volumes\x00processes"} {
		if got, e := GenerationID(agent, section, 1); e == nil || got != "" {
			t.Fatal("invalid section accepted")
		}
	}
}
