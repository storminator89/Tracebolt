package api

import (
	"context"
	"errors"
	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
	"net/http/httptest"
	"testing"
)

func TestManagedFleetReadRechecksPinnedCapabilityAfterWait(t *testing.T) {
	for _, cap := range []operatorauth.Capability{operatorauth.WindowsManagedMSIDeliver, operatorauth.WindowsManagedMSIInstall} {
		t.Run(string(cap), func(t *testing.T) {
			auth, e := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, cap}}}})
			if e != nil {
				t.Fatal(e)
			}
			session, e := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
			if e != nil {
				t.Fatal(e)
			}
			h := &operatorHandler{auth: auth}
			r := httptest.NewRequest("GET", "https://manager.invalid/api/windows-managed-msi/artifact", nil)
			r = r.WithContext(context.WithValue(r.Context(), operatorRequestKey{}, operatorRequest{session: session, origin: "https://manager.invalid", active: func() bool { return true }}))
			pinned := h.managedMSIReadCapability(namedActorID)
			if pinned != cap {
				t.Fatal("wrong read permission")
			}
			ctx := h.managedMSIContext(r, pinned)
			if e = msi.CheckFinal(ctx); e != nil {
				t.Fatal(e)
			}
			// Model permission removal while the protected SQLite/spool read is waiting.
			// The old session remains live so only the pinned capability check can refuse.
			h.auth, e = operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}}})
			if e != nil {
				t.Fatal(e)
			}
			if e = msi.CheckFinal(ctx); !errors.Is(e, msi.ErrAuthority) {
				t.Fatal("late capability removal released fleet data", e)
			}
		})
	}
}
func TestManagedFleetArtifactRoutesAreFixed(t *testing.T) {
	for _, suffix := range []string{"", "/reserve", "/upload", "/complete", "/reserve-reusable", "/retire"} {
		r := httptest.NewRequest("GET", "https://manager.invalid/api/windows-managed-msi/artifact"+suffix, nil)
		if _, ok := windowsManagedMSIArtifactRoute(r); !ok {
			t.Fatal(suffix)
		}
	}
	for _, suffix := range []string{"/download", "/remove", "/replace", "/install", "/../upload", "//upload", "/path/name.msi"} {
		r := httptest.NewRequest("GET", "https://manager.invalid/api/windows-managed-msi/artifact"+suffix, nil)
		if _, ok := windowsManagedMSIArtifactRoute(r); ok {
			t.Fatal(suffix)
		}
	}
}
