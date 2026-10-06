package socketowner

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type fixtureProtectedReader struct {
	objects  [objectCount]protectedObject
	replaced fixedObject
	override bool
	missing  fixedObject
}

func (r *fixtureProtectedReader) Read(id fixedObject) (protectedObject, error) {
	if id == r.missing {
		return protectedObject{}, ErrRejected
	}
	return r.objects[id], nil
}
func (r *fixtureProtectedReader) Recheck(id fixedObject, _ protectedObject) error {
	if id == r.replaced {
		return ErrChanged
	}
	return nil
}
func (r *fixtureProtectedReader) NoOverrides() error {
	if r.override {
		return ErrRejected
	}
	return nil
}
func fixtureProtectedAuthority() *fixtureProtectedReader {
	p := fixturePolicy()
	pb, _ := EncodePolicy(p)
	r := &fixtureProtectedReader{replaced: objectCount, missing: objectCount}
	for i := fixedObject(0); i < objectCount; i++ {
		body := []byte(fmt.Sprintf("invented fixed artifact %d", i))
		r.objects[i] = protectedObject{Body: body, Digest: digest(body), Revision: digest([]byte(fmt.Sprintf("inode fixture %d", i)))}
	}
	r.objects[policyObject].Body = pb
	r.objects[policyObject].Digest = digest(pb)
	d := Deployment{deploymentVersion, deploymentProfile, ClientContract, digest(pb), r.objects[helperObject].Digest, r.objects[agentObject].Digest, r.objects[helperUnitObject].Digest, r.objects[agentUnitObject].Digest, r.objects[socketUnitObject].Digest}
	b, _ := json.Marshal(d)
	r.objects[deploymentObject].Body = b
	r.objects[deploymentObject].Digest = digest(b)
	for i := policyObject; i <= deploymentObject; i++ {
		r.objects[i].GID = p.HelperGID
	}
	return r
}
func TestProtectedAuthorityRequiresVersionedActivatedClientContract(t *testing.T) {
	r := fixtureProtectedAuthority()
	a, err := loadNativeAuthority(r)
	if err != nil || !a.ProtectedPolicyVerified || !a.ProtectedGrantBindingVerified || !hash(a.Revision) {
		t.Fatal("v2 fixture rejected", err)
	}
	for _, change := range []func(*Deployment){
		func(d *Deployment) {
			d.Version = "tracebolt.socket-owner-deployment.v1"
			d.Profile = "systemd-pid1-local-ptrace-v1"
		},
		func(d *Deployment) { d.ClientContract = "" },
		func(d *Deployment) { d.ClientContract = "unreviewed-client" },
		func(d *Deployment) { d.Profile = "systemd-pid1-local-ptrace-v1" },
		func(d *Deployment) { d.PolicyDigest = strings.Repeat("e", 64) },
	} {
		r := fixtureProtectedAuthority()
		var d Deployment
		if json.Unmarshal(r.objects[deploymentObject].Body, &d) != nil {
			t.Fatal("fixture")
		}
		change(&d)
		r.objects[deploymentObject].Body, _ = json.Marshal(d)
		r.objects[deploymentObject].Digest = digest(r.objects[deploymentObject].Body)
		if _, err := loadNativeAuthority(r); err == nil {
			t.Fatal("old or unbound deployment accepted")
		}
	}
	// Old exact schema lacks the new explicit clientContract field and must fail.
	r = fixtureProtectedAuthority()
	var fields map[string]any
	json.Unmarshal(r.objects[deploymentObject].Body, &fields)
	delete(fields, "clientContract")
	r.objects[deploymentObject].Body, _ = json.Marshal(fields)
	if _, err := loadNativeAuthority(r); err == nil {
		t.Fatal("missing contract admitted")
	}
}
func TestProtectedAuthorityRejectsMutation(t *testing.T) {
	cases := map[string]func(*fixtureProtectedReader){
		"missing":        func(r *fixtureProtectedReader) { r.missing = policyObject },
		"replacement":    func(r *fixtureProtectedReader) { r.replaced = policyObject },
		"override":       func(r *fixtureProtectedReader) { r.override = true },
		"record group":   func(r *fixtureProtectedReader) { r.objects[policyObject].GID = 0 },
		"artifact group": func(r *fixtureProtectedReader) { r.objects[helperObject].GID = 1201 },
		"changed binary": func(r *fixtureProtectedReader) { r.objects[agentObject].Digest = strings.Repeat("f", 64) },
		"disabled": func(r *fixtureProtectedReader) {
			p := fixturePolicy()
			p.Enabled = false
			b, _ := EncodePolicy(p)
			r.objects[policyObject].Body = b
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := fixtureProtectedAuthority()
			change(r)
			if _, e := loadNativeAuthority(r); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}
func TestRevisionIncludesProtectedObjects(t *testing.T) {
	r := fixtureProtectedAuthority()
	a, e := loadNativeAuthority(r)
	if e != nil {
		t.Fatal(e)
	}
	r.objects[policyObject].Revision = digest([]byte("new inode, unchanged identity bytes"))
	b, e := loadNativeAuthority(r)
	if e != nil || a.Revision == b.Revision {
		t.Fatal("lost object revision")
	}
}
