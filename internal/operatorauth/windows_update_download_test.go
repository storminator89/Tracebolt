package operatorauth

import (
	"context"
	"errors"
	"testing"
)

func TestWindowsUpdateDownloadIsIndependentExplicitGrant(t *testing.T) {
	if capabilityBit(WindowsUpdateDownload) != 8192 {
		t.Fatal("download grant bit changed")
	}
	for _, grant := range []Capability{WindowsUpdateInstall, WindowsUpdateSchedule, WindowsUpdateDownload} {
		c := namedConfig()
		c.Operators[0].Capabilities = []Capability{Read, grant}
		m, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		s := namedLogin(t, m)
		for _, target := range []Capability{WindowsUpdateInstall, WindowsUpdateSchedule, WindowsUpdateDownload} {
			release, err := s.BeginCapability(context.Background(), target)
			if target == grant {
				if err != nil {
					t.Fatal(err)
				}
				release()
			} else if !errors.Is(err, ErrForbidden) {
				t.Fatal("grant implied another operation", grant, target, err)
			}
			if m.ActorHasCapability(s.ActorID(), target) != (target == grant) {
				t.Fatal("live actor grant crossed purposes")
			}
		}
		caps := s.Capabilities()
		if len(caps) != 2 || caps[1] != grant {
			t.Fatal("display omitted explicit grant", caps)
		}
		m.Logout(s.Token)
		if _, err = s.BeginCapability(context.Background(), grant); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("revoked session retained grant")
		}
	}
	c := namedConfig()
	c.Operators[0].Capabilities = []Capability{WindowsUpdateDownload}
	if _, err := New(c); !errors.Is(err, ErrConfiguration) {
		t.Fatal("download implied read")
	}
	c.Operators[0].Capabilities = []Capability{Read, WindowsUpdateDownload, WindowsUpdateDownload}
	if _, err := New(c); !errors.Is(err, ErrConfiguration) {
		t.Fatal("duplicate download accepted")
	}
}
