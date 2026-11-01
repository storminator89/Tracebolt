package operatorauth

import (
	"context"
	"errors"
	"testing"
)

func TestCustomerReadIsIndependentExplicitGrant(t *testing.T) {
	if capabilityBit(ReadCustomers) != 32768 {
		t.Fatal("customer-read grant must not alias an existing capability")
	}
	other := []Capability{Read, PlanUpdates, ExecuteUpdates, RestartService, ManageAlarms, ManageApplicationChecks, WindowsServiceControl, WindowsUpdateInstall, WindowsUpdateSchedule, WindowsSoftwareInstall, WindowsManagedMSIDeliver, WindowsManagedMSIInstall, WindowsManagedMSISchedule, WindowsUpdateDownload, ManageSessions}
	c := namedConfig()
	c.Operators[0].Capabilities = other
	m, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	s := namedLogin(t, m)
	if _, err := s.BeginCapability(context.Background(), ReadCustomers); !errors.Is(err, ErrForbidden) || m.ActorHasCapability(s.ActorID(), ReadCustomers) {
		t.Fatal("existing grants implied customer reads")
	}
	c.Operators[0].Capabilities = []Capability{Read, ReadCustomers}
	m, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	s = namedLogin(t, m)
	for _, cap := range append(other, ReadCustomers) {
		release, err := s.BeginCapability(context.Background(), cap)
		if cap == Read || cap == ReadCustomers {
			if err != nil {
				t.Fatal("explicit read grant denied", cap, err)
			}
			release()
		} else if !errors.Is(err, ErrForbidden) {
			t.Fatal("customer read implied unrelated authority", cap, err)
		}
	}
	caps := s.Capabilities()
	if len(caps) != 2 || caps[0] != Read || caps[1] != ReadCustomers {
		t.Fatal("customer read display metadata changed")
	}
	caps[1] = ManageSessions
	if _, err := s.BeginCapability(context.Background(), ManageSessions); !errors.Is(err, ErrForbidden) {
		t.Fatal("display snapshot manufactured authority")
	}
	m.Logout(s.Token)
	if _, err := s.BeginCapability(context.Background(), ReadCustomers); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("revoked session retained customer reads")
	}
	for _, caps := range [][]Capability{{ReadCustomers}, {Read, ReadCustomers, ReadCustomers}} {
		c.Operators[0].Capabilities = caps
		if _, err := New(c); !errors.Is(err, ErrConfiguration) {
			t.Fatal("missing read or duplicate customer grant accepted")
		}
	}
}
