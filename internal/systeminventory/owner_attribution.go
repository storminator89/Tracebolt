package systeminventory

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
)

// ownerSource is an internal fixture seam, not an API for caller-selected paths.
// The Linux adapter alone owns pinned procfs descriptors and no-follow reads.
// Resolvers return only socket identity, never non-socket link text or fdinfo.
type ownerEntries interface {
	Readdirnames(int) ([]string, error)
	Close() error
}
type ownerFDs interface {
	ownerEntries
	// A recognized but malformed socket link returns true with ErrInvalidSource;
	// OS lookup failures return false with a fixed SourceError.
	socketInode(string) (uint64, bool, error)
}
type ownerProcess interface {
	openFDs() (ownerFDs, error)
	openComm() (io.ReadCloser, error)
	Close() error
}
type ownerSource interface {
	openProcesses() (ownerEntries, error)
	openProcess(uint32) (ownerProcess, error)
}

// attributeOwners preserves the bounded, non-atomic best-effort scan. A denied
// or exited process can hide another owner, so its scan reason remains global.
func attributeOwners(ctx context.Context, inodes []uint64, source ownerSource) (map[uint64]AttributionResult, error) {
	if len(inodes) > MaxSocketRows {
		return nil, ErrItemLimit
	}
	wanted := make(map[uint64]bool, len(inodes))
	out := make(map[uint64]AttributionResult, len(inodes))
	for _, inode := range inodes {
		if inode > 0 {
			wanted[inode] = true
			out[inode] = AttributionResult{Owners: []Owner{}, Attribution: Attribution{AttributionUnavailable, ReasonNoMatch}}
		}
	}
	// Reopen the directory descriptor for independent enumeration offset.
	proc, e := source.openProcesses()
	if e != nil {
		return nil, e
	}
	defer proc.Close()
	global := ReasonNone
	processes, entries, totalFD := 0, 0, 0
loop:
	for {
		if ctx.Err() != nil {
			global = ReasonTimeout
			break
		}
		batch, e := proc.Readdirnames(128)
		if e != nil && e != io.EOF {
			global = ReasonReadFailed
			break
		}
		for _, name := range batch {
			entries++
			if entries > MaxDirectoryEntries {
				global = ReasonWorkLimit
				break loop
			}
			pid, ok := numericPID(name)
			if !ok {
				continue
			}
			processes++
			if processes > MaxProcessEntries {
				global = ReasonWorkLimit
				break loop
			}
			reason := attributeOwnerPID(ctx, source, pid, wanted, out, &totalFD)
			if reason != ReasonNone {
				global = preferAttributionReason(global, reason)
			}
			if reason == ReasonTimeout || totalFD >= MaxTotalFDEntries {
				if reason != ReasonTimeout {
					global = ReasonWorkLimit
				}
				break loop
			}
		}
		if e == io.EOF {
			break
		}
	}
	for inode, a := range out {
		if global != ReasonNone {
			a.Attribution = Attribution{AttributionPartial, global}
		} else if len(a.Owners) > 0 && a.Attribution.Reason == ReasonNoMatch {
			a.Attribution = Attribution{AttributionObserved, ReasonNone}
		}
		out[inode] = a
	}
	return out, nil
}
func numericPID(s string) (uint32, bool) {
	if len(s) == 0 || s[0] == '0' {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, e := strconv.ParseUint(s, 10, 31)
	return uint32(n), e == nil && n > 0
}
func attributeOwnerPID(ctx context.Context, source ownerSource, pid uint32, wanted map[uint64]bool, out map[uint64]AttributionResult, total *int) Reason {
	if ctx.Err() != nil {
		return ReasonTimeout
	}
	process, e := source.openProcess(pid)
	if e != nil {
		return attributionReason(e)
	}
	defer process.Close()
	fds, e := process.openFDs()
	if e != nil {
		return attributionReason(e)
	}
	defer fds.Close()
	matched := map[uint64]bool{}
	reason := ReasonNone
	count := 0
loop:
	for {
		if ctx.Err() != nil {
			reason = ReasonTimeout
			break
		}
		batch, e := fds.Readdirnames(128)
		if e != nil && e != io.EOF {
			reason = ReasonReadFailed
			break
		}
		for _, name := range batch {
			count++
			*total++
			if count > MaxFDEntriesPerProcess || *total > MaxTotalFDEntries {
				reason = ReasonWorkLimit
				break loop
			}
			if _, err := strconv.ParseUint(name, 10, 31); err != nil {
				reason = ReasonInvalidSource
				continue
			}
			inode, socket, e := fds.socketInode(name)
			if e != nil {
				if socket && errors.Is(e, ErrInvalidSource) {
					// Preserve the native link parser's existing malformed-socket
					// precedence, distinct from an OS readlink failure.
					reason = ReasonInvalidSource
				} else {
					reason = preferAttributionReason(reason, attributionReason(e))
				}
				continue
			}
			if !socket {
				continue
			}
			if wanted[inode] {
				matched[inode] = true
			}
		}
		if e == io.EOF {
			break
		}
	}
	if len(matched) == 0 {
		return reason
	}
	var processName *string
	nameReason := ReasonNone
	comm, e := process.openComm()
	if e != nil {
		nameReason = attributionReason(e)
	} else {
		b, err := io.ReadAll(io.LimitReader(&contextReader{ctx, comm}, MaxProcessNameBytes+2))
		ce := comm.Close()
		if err == nil {
			err = ce
		}
		if err != nil {
			nameReason = attributionReason(err)
		} else {
			s := strings.TrimSuffix(string(b), "\n")
			if !validProcessName(s) {
				nameReason = ReasonInvalidSource
			} else {
				processName = &s
			}
		}
	}
	for inode := range matched {
		a := out[inode]
		if len(a.Owners) >= MaxOwnersPerSocket {
			a.Attribution = Attribution{AttributionPartial, ReasonOwnerLimit}
		} else {
			a.Owners = append(a.Owners, Owner{pid, processName, nameReason})
			if nameReason != ReasonNone {
				a.Attribution = Attribution{AttributionPartial, nameReason}
			}
		}
		out[inode] = a
	}
	return reason
}
func attributionReason(e error) Reason {
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	r := failureReason(e)
	if r == ReasonSourceMissing {
		return ReasonProcessGone
	}
	if !validAttributionFailure(r) {
		return ReasonReadFailed
	}
	return r
}
func preferAttributionReason(old, next Reason) Reason {
	if old == ReasonNone || next == ReasonTimeout || next == ReasonWorkLimit || next == ReasonPermissionDenied {
		return next
	}
	return old
}
