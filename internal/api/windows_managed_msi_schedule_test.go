package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
)

func TestManagedMSIScheduleFinalFenceRequiresBothCapabilities(t *testing.T) {
	for _, operation := range []string{"schedule", "cancel-schedule"} {
		t.Run(operation, func(t *testing.T) {
			makeAuth := func(caps []operatorauth.Capability) *operatorauth.Manager {
				t.Helper()
				auth, err := operatorauth.New(operatorauth.Config{Operators: []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: caps}}})
				if err != nil {
					t.Fatal(err)
				}
				return auth
			}
			both := []operatorauth.Capability{operatorauth.Read, operatorauth.WindowsManagedMSIInstall, operatorauth.WindowsManagedMSISchedule}
			auth := makeAuth(both)
			session, err := auth.LoginNamed(context.Background(), "127.0.0.1", "reader", operatorFixturePassword)
			if err != nil {
				t.Fatal(err)
			}
			active := true
			h := &operatorHandler{auth: auth}
			request := httptest.NewRequest("POST", "https://manager.invalid/api/devices/"+namedDeviceID+"/windows-managed-msi/"+operation, nil)
			request = request.WithContext(context.WithValue(request.Context(), operatorRequestKey{}, operatorRequest{session: session, origin: "https://manager.invalid", active: func() bool { return active }}))
			ctx := h.managedMSIContext(request, operatorauth.WindowsManagedMSIInstall)
			if err = msi.CheckFinal(ctx); err != nil {
				t.Fatal(err)
			}
			for _, cap := range []operatorauth.Capability{operatorauth.WindowsManagedMSIInstall, operatorauth.WindowsManagedMSISchedule, operatorauth.WindowsUpdateSchedule, operatorauth.WindowsSoftwareInstall} {
				h.auth = makeAuth([]operatorauth.Capability{operatorauth.Read, cap})
				if err = msi.CheckFinal(ctx); !errors.Is(err, msi.ErrAuthority) {
					t.Fatal("one capability or another domain promoted", cap, err)
				}
			}
			h.auth = auth
			active = false
			if err = msi.CheckFinal(ctx); !errors.Is(err, msi.ErrAuthority) {
				t.Fatal("ended session admitted", err)
			}
		})
	}
}

// In-process object decoding only. No listener, browser, manager or host action.
func TestManagedMSIScheduleExactBody(t *testing.T) {
	q := msi.ScheduleRequest{ArtifactID: msi.Digest([]byte("artifact")), BindingDigest: msi.Digest([]byte("binding")), TransferID: "transfer_" + strings.Repeat("a", 32), JobSequence: 1, ReadinessDigest: msi.Digest([]byte("ready")), StartAt: 2000000000, EndAt: 2000000060, PackageReviewAccepted: true, TermsAccepted: true, ServiceRiskAccepted: true, SynchronousActionsAccepted: true, ScheduleAccepted: true}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	fields := []string{"artifactId", "artifactRetiredCount", "bindingDigest", "transferId", "jobSequence", "readinessDigest", "startAt", "endAt", "packageReviewAccepted", "termsAccepted", "serviceRiskAccepted", "synchronousActionsAccepted", "scheduleAccepted"}
	for name, body := range map[string]string{
		"valid":            string(raw),
		"batch":            strings.TrimSuffix(string(raw), "}") + `,"batch":{"worklistId":"x"}}`,
		"actor":            strings.TrimSuffix(string(raw), "}") + `,"actorId":"` + namedActorID + `"}`,
		"duplicate":        strings.TrimSuffix(string(raw), "}") + `,"scheduleAccepted":true}`,
		"number-sequence":  strings.Replace(string(raw), `"jobSequence":"1"`, `"jobSequence":1`, 1),
		"missing-approval": strings.Replace(string(raw), `,"scheduleAccepted":true`, "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "https://manager.invalid/", strings.NewReader(body))
			var decoded msi.ScheduleRequest
			ok := readObject(httptest.NewRecorder(), request, 4096, fields, &decoded)
			if ok != (name == "valid") {
				t.Fatal("strict schedule decoding", name, ok)
			}
			if ok && decoded.Validate() != nil {
				t.Fatal("valid request rejected")
			}
		})
	}
}
