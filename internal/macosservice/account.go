package macosservice

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
)

const maxAccountOutput = 1024

type accountReader func(context.Context, []string) ([]byte, error)

// Only these exact local read queries are allowed. Neither requested IDs nor
// any host/config value can select an executable, DS node, account or attribute.
func inspectDedicatedAccount(ctx context.Context, uid, gid int, read accountReader) bool {
	if ctx == nil || ctx.Err() != nil || uid <= 0 || gid <= 0 || read == nil {
		return false
	}
	user, err := read(ctx, []string{"/Local/Default", "-read", "/Users/" + Account, "UniqueID", "PrimaryGroupID"})
	if err != nil || !accountRecordMatches(user, map[string]int{"UniqueID": uid, "PrimaryGroupID": gid}) {
		return false
	}
	group, err := read(ctx, []string{"/Local/Default", "-read", "/Groups/" + Account, "PrimaryGroupID"})
	return err == nil && accountRecordMatches(group, map[string]int{"PrimaryGroupID": gid}) && ctx.Err() == nil
}
func accountRecordMatches(raw []byte, expected map[string]int) bool {
	if len(raw) < 1 || len(raw) > maxAccountOutput || raw[len(raw)-1] != '\n' {
		return false
	}
	lines := strings.Split(string(raw[:len(raw)-1]), "\n")
	if len(lines) != len(expected) {
		return false
	}
	seen := map[string]bool{}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, ": ")
		want, exists := expected[key]
		if !ok || !exists || seen[key] || value != strconv.Itoa(want) {
			return false
		}
		seen[key] = true
	}
	return true
}

// Native execution independently rejects every argument vector except these two.
func validAccountQuery(args []string) bool {
	return slices.Equal(args, []string{"/Local/Default", "-read", "/Users/" + Account, "UniqueID", "PrimaryGroupID"}) || slices.Equal(args, []string{"/Local/Default", "-read", "/Groups/" + Account, "PrimaryGroupID"})
}

type boundedAccountOutput struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (w *boundedAccountOutput) Write(p []byte) (int, error) {
	if w.exceeded || len(p) > w.limit-w.buffer.Len() {
		w.exceeded = true
		return 0, errors.New("bounded local account output exceeded")
	}
	return w.buffer.Write(p)
}
