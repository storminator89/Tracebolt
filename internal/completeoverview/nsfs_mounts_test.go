package completeoverview

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Synthetic kernel-format records; no host namespace operation.
// Linux v6.12 fs/nsfs.c: nsfs_show_path writes %s:[%lu] as mountinfo root.
const nsfsMountFixture = "1 9 8:1 / / rw - ext4 /dev/fixture rw\n2 9 0:4 net:[4026533001] /run/docker/netns/fixture rw - nsfs nsfs rw\n"

func TestNSFSMountRootKeepsCompleteGeneration(t *testing.T) {
	s := runFixture(t, &fixtureProvider{mountData: nsfsMountFixture})
	if s.Volumes.Meta.Coverage != Complete {
		t.Fatalf("valid nsfs record poisoned generation: coverage=%s reason=%s", s.Volumes.Meta.Coverage, s.Volumes.Meta.Reason)
	}
	mounts, err := ParseMountInfo(context.Background(), strings.NewReader(nsfsMountFixture))
	if err != nil {
		t.Fatalf("valid nsfs kernel root rejected: %v", err)
	}
	if len(mounts) != 2 || mounts[1].Root != "net:[4026533001]" {
		t.Fatal("transient root identity lost")
	}
	if s.Volumes.Meta.Coverage != Complete || len(s.Volumes.Items) != 2 || s.Volumes.Meta.FieldCoverage.Observed != 1 || s.Volumes.Meta.FieldCoverage.NotApplicable != 1 {
		t.Fatalf("valid nsfs record poisoned enumeration: %+v", s.Volumes.Meta)
	}
	v := s.Volumes.Items[1]
	if v.Filesystem != "nsfs" || v.Kind != "virtual" || v.Measurement.Status != NotApplicable || v.TotalBytes != nil {
		t.Fatal("nsfs must remain unmeasured")
	}
	wire, err := json.Marshal(s)
	if err != nil || strings.Contains(string(wire), "4026533001") {
		t.Fatal("transient namespace root disclosed")
	}
}

func TestNSFSMountRootGrammarAndPathBoundaries(t *testing.T) {
	for _, name := range []string{"net", "mnt", "pid", "user", "uts", "ipc", "cgroup", "time"} {
		root := name + ":[4026533001]"
		mounts, err := ParseMountInfo(context.Background(), strings.NewReader("2 9 0:4 "+root+" /run/fixture rw - nsfs nsfs rw\n"))
		if err != nil || len(mounts) != 1 || mounts[0].Root != root {
			t.Fatalf("kernel namespace kind rejected: %s", name)
		}
	}
	for _, root := range []string{"net:[0]", "net:[01]", "net:[-1]", "net:[+1]", "net:[18446744073709551616]", "net:[]", "net:[42]tail", "other:[42]", "net:[42]/child", "net:[42]\\012", "relative", "../relative"} {
		if _, err := ParseMountInfo(context.Background(), strings.NewReader("2 9 0:4 "+root+" /run/fixture rw - nsfs nsfs rw\n")); err == nil {
			t.Fatalf("malformed root accepted: %q", root)
		}
	}
	for _, fs := range []string{"ext4", "proc", "tmpfs", "mystery"} {
		if _, err := ParseMountInfo(context.Background(), strings.NewReader("2 9 0:4 net:[42] /run/fixture rw - "+fs+" none rw\n")); err == nil {
			t.Fatalf("namespace root accepted for %s", fs)
		}
	}
	for _, point := range []string{"net:[42]", "relative", "/run/../fixture", "/run//fixture", "/run/fixture\\012"} {
		if _, err := ParseMountInfo(context.Background(), strings.NewReader("2 9 0:4 net:[42] "+point+" rw - nsfs nsfs rw\n")); err == nil {
			t.Fatalf("unsafe mount point accepted: %q", point)
		}
	}
}
