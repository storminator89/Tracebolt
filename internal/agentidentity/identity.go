package agentidentity

import (
	"os"
	"strconv"
	"strings"
)

func Validate(expected string) bool {
	parts := strings.Split(expected, ":")
	if len(parts) != 2 {
		return false
	}
	uid, e1 := strconv.Atoi(parts[0])
	gid, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || uid <= 0 || gid <= 0 || uint64(uid) >= 1<<32-1 || uint64(gid) >= 1<<32-1 || strconv.Itoa(uid) != parts[0] || strconv.Itoa(gid) != parts[1] || !serviceProcessIDs(uid, gid) {
		return false
	}
	groups, e := os.Getgroups()
	if e != nil {
		return false
	}
	for _, g := range groups {
		if g != gid {
			return false
		}
	}
	return true
}
