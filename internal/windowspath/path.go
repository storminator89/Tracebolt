// Package windowspath defines the component-only path contract used by Windows
// executable verification and the separately approved native acceptance driver.
// It neither grants access nor treats a descriptor scan as effective token proof.
package windowspath

import (
	"errors"
	"strings"
)

var ErrPath = errors.New("Windows path binding rejected")

// DirectoryAccess contains FILE_LIST_DIRECTORY. Unlike metadata-only handles,
// this participates in Windows delete-sharing checks. No request shares delete.
const DirectoryAccess uint32 = 0x001200a1
const DirectoryShare uint32 = 3 // FILE_SHARE_READ | FILE_SHARE_WRITE

func Component(s string) bool {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, `\/:~"`) || strings.HasSuffix(s, ".") || strings.HasSuffix(s, " ") {
		return false
	}
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
func Canonical(p string) bool {
	if len(p) < 3 || len(p) > 240 || p[0] < 'A' || p[0] > 'Z' || p[1:3] != `:\` {
		return false
	}
	if len(p) == 3 {
		return true
	}
	for _, c := range strings.Split(p[3:], `\`) {
		if !Component(c) {
			return false
		}
	}
	return true
}

// CreatedBinding makes the lifetime order explicit and injectable: validate the
// held parent, create exactly once, retain the returned object, then revalidate
// both bindings. Even a post-create refusal retains the object for owned cleanup;
// it must never cause an absolute-path reopen, adoption, or retry elsewhere.
func CreatedBinding(checkParent func() error, create func() error, retain func(), checkChild func() error) error {
	if checkParent == nil || create == nil || retain == nil || checkChild == nil {
		return ErrPath
	}
	if err := checkParent(); err != nil {
		return err
	}
	if err := create(); err != nil {
		return err
	}
	retain()
	if err := checkParent(); err != nil {
		return err
	}
	return checkChild()
}
