package overviewstate

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestValidatedPackWorkRemainsDetached(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "staged", true: "reopened"}[restart], func(t *testing.T) {
			s, dir := newFixture(t)
			a := reserve(t, s)
			manifest, chunks := payloads(t, a, 129)
			if e := s.Stage(context.Background(), a, manifest, chunks); e != nil {
				t.Fatal(e)
			}
			// Staging owns its bytes independently of the supplied payloads.
			manifest[0], chunks[0][0] = 'x', 'x'
			if restart {
				s = reopen(t, s, dir)
			}
			first := next(t, s)
			firstBody := first.Body()
			for _, operation := range []string{"begin", "append", "append", "finalize"} {
				w := next(t, s)
				if w.Operation != operation {
					t.Fatal("unexpected operation")
				}
				again := next(t, s)
				if !sameWork(w, again) {
					t.Fatal("retained work changed")
				}
				body := w.Body()
				body[0] = 'x'
				again.Operation, again.Section = "failure", "volumes"
				again.Sequence, again.Ordinal = 99, 99
				again.GenerationID, again.ManifestHash, again.Digest = "changed", "changed", "changed"
				if !sameWork(w, next(t, s)) {
					t.Fatal("caller mutation changed retained work")
				}
				ack := receipt(t, w)
				if e := s.Acknowledge(again, ack); !errors.Is(e, ErrAcknowledgment) {
					t.Fatal("changed metadata acknowledged", e)
				}
				if e := s.Acknowledge(w, ack); e != nil {
					t.Fatal(e)
				}
			}
			if _, pending, e := s.NextWork(); e != nil || pending || !bytes.Equal(firstBody, first.Body()) {
				t.Fatal("retirement changed detached work", e)
			}
		})
	}
}

func TestValidatedPackCursorReusesWork(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "staged", true: "reopened"}[restart], func(t *testing.T) {
			s, dir := newFixture(t)
			stageFixture(t, s, 129)
			if restart {
				s = reopen(t, s, dir)
			}
			begin := next(t, s)
			if e := s.Acknowledge(begin, receipt(t, begin)); e != nil {
				t.Fatal(e)
			}
			w := next(t, s)
			if w.Operation != "append" || w.body != next(t, s).body {
				t.Fatal("validated work was rebuilt")
			}
		})
	}
}
