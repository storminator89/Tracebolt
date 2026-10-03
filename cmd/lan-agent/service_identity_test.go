//go:build linux

package main

import (
	"os"
	"strconv"
	"testing"
)

func TestServiceIdentityFailsClosed(t *testing.T) {
	for _, s := range []string{"", "0:0", "1", "1:2:3", "+1:2", "01:2", "4294967296:1", "1:4294967295", "-1:1"} {
		if serviceIdentity(s) {
			t.Fatal("invalid service identity accepted")
		}
	}
	expected := strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid())
	groups, e := os.Getgroups()
	if e != nil {
		return
	}
	allowed := os.Geteuid() > 0 && os.Getegid() > 0
	for _, g := range groups {
		if g != os.Getegid() {
			allowed = false
		}
	}
	if serviceIdentity(expected) != allowed {
		t.Fatal("effective identity contract disagreed")
	}
}
