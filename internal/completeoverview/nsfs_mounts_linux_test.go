//go:build linux

package completeoverview

import (
	"context"
	"strings"
	"testing"
)

func TestNSFSMountRootIdentityStillFencesCoherence(t *testing.T) {
	before, err := ParseMountInfo(context.Background(), strings.NewReader(nsfsMountFixture))
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseMountInfo(context.Background(), strings.NewReader(strings.Replace(nsfsMountFixture, "4026533001", "4026533002", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if !sameMounts(before, before) || sameMounts(before, after) {
		t.Fatal("namespace handle change lost from coherence check")
	}
}
