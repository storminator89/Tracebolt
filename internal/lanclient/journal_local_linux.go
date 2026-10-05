//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
	"localrmm/internal/agentidentity"
	"localrmm/internal/journalactivation"
	"localrmm/internal/journalgenerationstate"
	"localrmm/internal/journalhelper"
	"localrmm/internal/journalpolicy"
)

func journalAgentIdentity() (uint32, uint32, bool) {
	uid, gid := os.Geteuid(), os.Getegid()
	if !agentidentity.Validate(strconv.Itoa(uid) + ":" + strconv.Itoa(gid)) {
		return 0, 0, false
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if unix.Capget(&header, &caps[0]) != nil || caps != [2]unix.CapUserData{} {
		return 0, 0, false
	}
	return uint32(uid), uint32(gid), true
}
func journalRootDirectory(parts []string) (*os.File, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errJournalDenied
	}
	f := os.NewFile(uintptr(fd), "journal-protected-directory")
	safe := func() bool {
		var st unix.Stat_t
		return unix.Fstat(int(f.Fd()), &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && st.Mode&0022 == 0 && st.Mode&(unix.S_ISUID|unix.S_ISGID) == 0
	}
	if !safe() {
		f.Close()
		return nil, errJournalDenied
	}
	for _, part := range parts {
		next, err := unix.Openat(int(f.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		f.Close()
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil, errJournalDisabled
			}
			return nil, errJournalDenied
		}
		f = os.NewFile(uintptr(next), "journal-protected-directory")
		if !safe() {
			f.Close()
			return nil, errJournalDenied
		}
	}
	return f, nil
}
func journalSame(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func loadJournalLocal(m Material) (journalLocal, error) {
	uid, gid, ok := journalAgentIdentity()
	if !ok {
		return journalLocal{}, errJournalDenied
	}
	return readJournalLocal(m, uid, gid)
}
func readJournalLocal(m Material, uid, gid uint32) (journalLocal, error) {
	return readJournalLocalPolicyMode(m, uid, gid, false, false)
}

// Administrative inspection may describe a disabled policy; it never enables it.
func readJournalLocalMode(m Material, uid, gid uint32, pending bool) (journalLocal, error) {
	return readJournalLocalPolicyMode(m, uid, gid, pending, true)
}
func readJournalLocalPolicyMode(m Material, uid, gid uint32, pending, inspect bool) (journalLocal, error) {
	dir, e := journalRootDirectory([]string{"etc", "tracebolt"})
	if e != nil {
		return journalLocal{}, e
	}
	defer dir.Close()
	activation, present, activationRevision, ae := journalactivation.Read()
	if ae != nil || !journalactivation.Gate(activation, present, pending) {
		return journalLocal{}, errJournalDenied
	}
	fd, e := unix.Openat(int(dir.Fd()), "journal-client-policy.json", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return journalLocal{}, errJournalDisabled
	}
	if e != nil {
		return journalLocal{}, errJournalDenied
	}
	f := os.NewFile(uintptr(fd), "journal-client-policy")
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Gid != gid || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0640 || before.Nlink != 1 || before.Size < 1 || before.Size > journalpolicy.MaxPolicyBytes {
		return journalLocal{}, errJournalDenied
	}
	raw, e := io.ReadAll(io.LimitReader(f, journalpolicy.MaxPolicyBytes+1))
	if e != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(int(dir.Fd()), "journal-client-policy.json", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !journalSame(before, after) || !journalSame(after, named) {
		return journalLocal{}, errJournalDenied
	}
	fresh, e := journalRootDirectory([]string{"etc", "tracebolt"})
	if e != nil {
		return journalLocal{}, errJournalDenied
	}
	defer fresh.Close()
	var oldDir, newDir unix.Stat_t
	if unix.Fstat(int(dir.Fd()), &oldDir) != nil || unix.Fstat(int(fresh.Fd()), &newDir) != nil || !journalSame(oldDir, newDir) {
		return journalLocal{}, errJournalDenied
	}
	deploymentRaw, ds, e := journalProtectedFile(dir, "journal-client-helper.json", journalhelper.MaxDeploymentBytes, gid)
	if e != nil {
		return journalLocal{}, errJournalDenied
	}
	var dep journalhelper.Deployment
	if json.Unmarshal(deploymentRaw, &dep) != nil {
		return journalLocal{}, errJournalDenied
	}
	canonical, _ := json.Marshal(dep)
	validID := func(id uint32) bool { return id > 0 && id != ^uint32(0) }
	if !bytes.Equal(deploymentRaw, canonical) || (dep.SchemaVersion != journalhelper.DeploymentVersion && dep.SchemaVersion != journalhelper.DeploymentVersionV2) || dep.AgentUID != uid || dep.AgentGID != gid || !validID(dep.HelperUID) || !validID(dep.HelperGID) || !validID(dep.JournalGID) || dep.HelperUID == uid || dep.HelperGID == gid || dep.HelperGID == dep.JournalGID || dep.JournalGID == gid {
		return journalLocal{}, errJournalDenied
	}
	if unix.Fstatat(int(dir.Fd()), "journal-client-policy.json", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !journalSame(after, named) {
		return journalLocal{}, errJournalDenied
	}
	p, e := journalpolicy.Decode(raw)
	if e != nil || p.SenderBinding != m.binding || p.ManagerOrigin != m.config.ManagerOrigin || p.TransportProfile != m.config.Profile || p.CollectionProfile != m.config.CollectionProfile || p.AgentUID != uid || p.HelperUID != dep.HelperUID {
		return journalLocal{}, errJournalDenied
	}
	generation, ge := journalpolicy.PolicyGeneration(p)
	if ge != nil {
		return journalLocal{}, errJournalDenied
	}
	if p.SchemaVersion == journalpolicy.Version {
		if present || dep.SchemaVersion != journalhelper.DeploymentVersion || dep.PolicyGenerationRequired {
			return journalLocal{}, errJournalDenied
		}
		// A surviving private migration floor forbids restoring legacy authority even
		// if root policy/deployment files were accidentally rolled back together.
		if _, err := os.Lstat(journalGenerationDirectory(m.config)); !errors.Is(err, os.ErrNotExist) {
			return journalLocal{}, errJournalDenied
		}

	} else {
		if !present || dep.SchemaVersion != journalhelper.DeploymentVersionV2 || !dep.PolicyGenerationRequired || activation.SenderBinding != m.binding || activation.DeviceID != m.config.AgentID || activation.CertificateHash != journalLeaf(m) || activation.PolicyGeneration != generation || !journalactivation.Gate(activation, present, pending) {
			return journalLocal{}, errJournalDenied
		}
		if !pending {
			state, err := journalgenerationstate.Open(context.Background(), journalGenerationDirectory(m.config))
			if err != nil {
				return journalLocal{}, errJournalDenied
			}
			record, err := state.Record()
			closeErr := state.Close()
			if err != nil || closeErr != nil || record.SenderBinding != m.binding || record.DeviceID != m.config.AgentID || record.CertificateHash != journalLeaf(m) || record.PolicyGeneration != generation {
				return journalLocal{}, errJournalDenied
			}
		}
	}
	if !p.Enabled && !inspect {
		return journalLocal{}, errJournalDisabled
	}
	lastDir, e := journalRootDirectory([]string{"etc", "tracebolt"})
	if e != nil {
		return journalLocal{}, errJournalDenied
	}
	defer lastDir.Close()
	if unix.Fstat(int(dir.Fd()), &oldDir) != nil || unix.Fstat(int(lastDir.Fd()), &newDir) != nil || !journalSame(oldDir, newDir) || unix.Fstatat(int(dir.Fd()), "journal-client-helper.json", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !journalSame(ds, named) {
		return journalLocal{}, errJournalDenied
	}
	// Revision includes protected file identity, not just its text. Replacing an
	// identical policy intentionally revokes already captured in-memory bodies.
	metadata, _ := json.Marshal(struct {
		Dev, Ino       uint64
		UID, GID, Mode uint32
		Mtime, Ctime   unix.Timespec
	}{uint64(after.Dev), uint64(after.Ino), after.Uid, after.Gid, after.Mode, after.Mtim, after.Ctim})
	h := sha256.New()
	h.Write(raw)
	h.Write([]byte{0})
	h.Write(metadata)
	h.Write(deploymentRaw)
	dsRaw, _ := json.Marshal(struct {
		Dev, Ino       uint64
		UID, GID, Mode uint32
		Mtime, Ctime   unix.Timespec
	}{uint64(ds.Dev), uint64(ds.Ino), ds.Uid, ds.Gid, ds.Mode, ds.Mtim, ds.Ctim})
	h.Write(dsRaw)
	again, presentAgain, activationAgain, err := journalactivation.Read()
	if err != nil || presentAgain != present || again != activation || activationAgain != activationRevision {
		return journalLocal{}, errJournalDenied
	}
	h.Write([]byte(activationRevision))
	return journalLocal{policy: p, revision: hex.EncodeToString(h.Sum(nil)), deployment: dep, generation: generation, activationPhase: activation.Phase}, nil
}

func journalProtectedFile(dir *os.File, name string, max int, gid uint32) ([]byte, unix.Stat_t, error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, unix.Stat_t{}, errJournalDenied
	}
	f := os.NewFile(uintptr(fd), "journal-client-metadata")
	defer f.Close()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Uid != 0 || before.Gid != gid || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0640 || before.Nlink != 1 || before.Size < 1 || before.Size > int64(max) {
		return nil, before, errJournalDenied
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Fstatat(int(dir.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !journalSame(before, after) || !journalSame(after, named) {
		return nil, before, errJournalDenied
	}
	return raw, after, nil
}
