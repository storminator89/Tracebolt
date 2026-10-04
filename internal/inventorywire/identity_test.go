package inventorywire

import (
	"strings"
	"testing"
)

func TestGenerationIDBindsDeviceAndIndependentSequence(t *testing.T) {
	agent := "agent_" + strings.Repeat("1", 32)
	a, err := GenerationID(agent, 1)
	if err != nil || len(a) != 39 || !strings.HasPrefix(a, "sample_") {
		t.Fatal("valid binding rejected")
	}
	again, _ := GenerationID(agent, 1)
	next, _ := GenerationID(agent, 2)
	other, _ := GenerationID("agent_"+strings.Repeat("2", 32), 1)
	if a != again || a == next || a == other || next == other {
		t.Fatal("generation binding is not separated")
	}
	for _, bad := range []uint64{0, MaxSequence + 1, ^uint64(0)} {
		if got, err := GenerationID(agent, bad); err == nil || got != "" {
			t.Fatal("invalid sequence accepted")
		}
	}
	if got, err := GenerationID("body-selected-invalid", 1); err == nil || got != "" {
		t.Fatal("invalid identity accepted")
	}
}
