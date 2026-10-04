package api

import (
	"localrmm/internal/enrollmentcrypto"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCollectionInvitationAcknowledgementIsProfileBound(t *testing.T) {
	const base = `"requestId":"request_00000000000000000000000000000001","platform":"linux"`
	for _, tc := range []struct {
		name, profile, body string
		success             bool
	}{
		{"basic unchanged", enrollmentcrypto.CollectionProfile, `{` + base + `}`, true},
		{"basic cannot opt in", enrollmentcrypto.CollectionProfile, `{` + base + `,"collectionAcknowledged":true}`, false},
		{"managed explicit", enrollmentcrypto.CollectionProfileOperational, `{` + base + `,"collectionAcknowledged":true}`, true},
		{"managed absent", enrollmentcrypto.CollectionProfileOperational, `{` + base + `}`, false},
		{"managed false", enrollmentcrypto.CollectionProfileOperational, `{` + base + `,"collectionAcknowledged":false}`, false},
		{"managed null", enrollmentcrypto.CollectionProfileOperational, `{` + base + `,"collectionAcknowledged":null}`, false},
		{"managed string", enrollmentcrypto.CollectionProfileOperational, `{` + base + `,"collectionAcknowledged":"true"}`, false},
		{"managed duplicate", enrollmentcrypto.CollectionProfileOperational, `{` + base + `,"collectionAcknowledged":true,"collectionAcknowledged":false}`, false},
		{"body profile cannot select", enrollmentcrypto.CollectionProfileOperational, `{` + base + `,"collectionAcknowledged":true,"collectionProfile":"basic-readonly-v1"}`, false},
		{"unknown binding", "", `{` + base + `}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/enrollment/invitations", strings.NewReader(tc.body))
			_, ok := readInvitationInput(w, r, tc.profile)
			if ok != tc.success {
				t.Fatal("profile-bound acknowledgement mismatch")
			}
		})
	}
}
