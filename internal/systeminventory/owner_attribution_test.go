package systeminventory

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type ownerFixtureEntries struct {
	names          []string
	offset, closes int
	err            error
	partialError   bool
}

func (d *ownerFixtureEntries) Readdirnames(n int) ([]string, error) {
	if d.err != nil {
		if d.partialError {
			return d.names, d.err
		}
		return nil, d.err
	}
	end := d.offset + n
	if end > len(d.names) {
		end = len(d.names)
	}
	out := d.names[d.offset:end]
	d.offset = end
	if end == len(d.names) {
		return out, io.EOF
	}
	return out, nil
}
func (d *ownerFixtureEntries) Close() error { d.closes++; return nil }

type ownerFixtureFDs struct {
	ownerFixtureEntries
	inodes map[string]uint64
	errors map[string]error
	calls  int
	fdinfo map[string]string
	mount  uint64
}

func (f *ownerFixtureFDs) socketInode(name string) (uint64, bool, error) {
	f.calls++
	if f.fdinfo != nil {
		return parseSocketFDInfo(context.Background(), strings.NewReader(f.fdinfo[name]), f.mount)
	}
	if err := f.errors[name]; err != nil {
		_, framedSocket := f.inodes[name]
		return 0, framedSocket, err
	}
	inode, ok := f.inodes[name]
	return inode, ok, nil
}

type ownerFixtureProcess struct {
	fds                *ownerFixtureFDs
	fdErr, nameErr     error
	name               string
	closes, nameCloses int
}

func (p *ownerFixtureProcess) openFDs() (ownerFDs, error) {
	if p.fdErr != nil {
		return nil, p.fdErr
	}
	p.fds.offset = 0
	return p.fds, nil
}
func (p *ownerFixtureProcess) openComm() (io.ReadCloser, error) {
	if p.nameErr != nil {
		return nil, p.nameErr
	}
	return &ownerFixtureComm{Reader: strings.NewReader(p.name), process: p}, nil
}
func (p *ownerFixtureProcess) Close() error { p.closes++; return nil }

type ownerFixtureComm struct {
	io.Reader
	process *ownerFixtureProcess
}

func (c *ownerFixtureComm) Close() error { c.process.nameCloses++; return nil }

type ownerFixtureSource struct {
	entries       *ownerFixtureEntries
	processes     map[uint32]*ownerFixtureProcess
	fallback      *ownerFixtureProcess
	errors        map[uint32]error
	openErr       error
	opens         int
	onOpenProcess func()
}

func (s *ownerFixtureSource) openProcesses() (ownerEntries, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	return s.entries, nil
}
func (s *ownerFixtureSource) openProcess(pid uint32) (ownerProcess, error) {
	s.opens++
	if s.onOpenProcess != nil {
		s.onOpenProcess()
	}
	if err := s.errors[pid]; err != nil {
		return nil, err
	}
	if p := s.processes[pid]; p != nil {
		return p, nil
	}
	return s.fallback, nil
}
func ownerProcessFixture(name string, fds map[string]uint64) *ownerFixtureProcess {
	names := []string{}
	for fd := range fds {
		names = append(names, fd)
	}
	return &ownerFixtureProcess{name: name + "\n", fds: &ownerFixtureFDs{ownerFixtureEntries: ownerFixtureEntries{names: names}, inodes: fds}}
}
func ownerSourceFixture(pids ...uint32) *ownerFixtureSource {
	s := &ownerFixtureSource{entries: &ownerFixtureEntries{}, processes: map[uint32]*ownerFixtureProcess{}, errors: map[uint32]error{}}
	for _, pid := range pids {
		s.entries.names = append(s.entries.names, strconv.FormatUint(uint64(pid), 10))
		s.processes[pid] = ownerProcessFixture("fixture", map[string]uint64{"1": 123})
	}
	return s
}

func TestOwnerSeamSharedOwnersAndPerPIDDescriptorDeduplication(t *testing.T) {
	s := ownerSourceFixture(10, 20)
	s.processes[10] = ownerProcessFixture("first", map[string]uint64{"1": 123, "2": 123, "3": 456})
	s.processes[20] = ownerProcessFixture("second", map[string]uint64{"1": 123})
	out, err := attributeOwners(context.Background(), []uint64{123, 789}, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := out[123]; got.Attribution != (Attribution{AttributionObserved, ReasonNone}) || len(got.Owners) != 2 || got.Owners[0].PID != 10 || got.Owners[1].PID != 20 || *got.Owners[0].ProcessName != "first" {
		t.Fatalf("owners=%+v", got)
	}
	if got := out[789]; got.Attribution != (Attribution{AttributionUnavailable, ReasonNoMatch}) || len(got.Owners) != 0 {
		t.Fatalf("missing=%+v", got)
	}
	if _, ok := out[456]; ok {
		t.Fatal("unrequested inode retained")
	}
	if s.entries.closes != 1 {
		t.Fatal("PID enumeration not closed")
	}
	for _, p := range s.processes {
		if p.closes != 1 || p.fds.closes != 1 || p.nameCloses != 1 {
			t.Fatal("process resource leak")
		}
	}
}

func TestOwnerSeamDeniedExitedAndFieldFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		alter      func(*ownerFixtureSource)
		reason     Reason
		ownerCount int
	}{
		{"denied PID", func(s *ownerFixtureSource) { s.errors[20] = SourceError{ReasonPermissionDenied} }, ReasonPermissionDenied, 1},
		{"exited PID", func(s *ownerFixtureSource) { s.errors[20] = SourceError{ReasonSourceMissing} }, ReasonProcessGone, 1},
		{"denied FDs", func(s *ownerFixtureSource) { s.processes[20].fdErr = SourceError{ReasonPermissionDenied} }, ReasonPermissionDenied, 1},
		{"FD link failed", func(s *ownerFixtureSource) {
			s.processes[20].fds.errors = map[string]error{"1": SourceError{ReasonReadFailed}}
		}, ReasonReadFailed, 1},
		{"name denied", func(s *ownerFixtureSource) { s.processes[20].nameErr = SourceError{ReasonPermissionDenied} }, ReasonPermissionDenied, 2},
		{"name exited", func(s *ownerFixtureSource) { s.processes[20].nameErr = SourceError{ReasonSourceMissing} }, ReasonProcessGone, 2},
		{"name invalid", func(s *ownerFixtureSource) { s.processes[20].name = "unsafe/name\n" }, ReasonInvalidSource, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := ownerSourceFixture(10, 20)
			tc.alter(s)
			out, err := attributeOwners(context.Background(), []uint64{123, 789}, s)
			if err != nil || out[123].Attribution != (Attribution{AttributionPartial, tc.reason}) || len(out[123].Owners) != tc.ownerCount {
				t.Fatalf("out=%+v err=%v", out, err)
			}
			if tc.ownerCount == 2 {
				o := out[123].Owners[1]
				if o.ProcessName != nil || o.NameReason != tc.reason {
					t.Fatalf("field failure=%+v", o)
				}
				if out[789].Attribution.Reason != ReasonNoMatch {
					t.Fatal("name failure leaked globally")
				}
			} else if out[789].Attribution != (Attribution{AttributionPartial, tc.reason}) {
				t.Fatal("global uncertainty lost")
			}
			if s.entries.closes != 1 {
				t.Fatal("PID enumeration leaked")
			}
			for pid, p := range s.processes {
				if s.errors[pid] == nil && p.closes != 1 {
					t.Fatal("process handle leaked")
				}
				if s.errors[pid] == nil && p.fdErr == nil && p.fds.closes != 1 {
					t.Fatal("FD handle leaked")
				}
			}
		})
	}
}

func TestOwnerSeamOwnerAndFDLimits(t *testing.T) {
	for _, count := range []int{MaxOwnersPerSocket, MaxOwnersPerSocket + 1} {
		s := ownerSourceFixture()
		for n := 1; n <= count; n++ {
			s.entries.names = append(s.entries.names, strconv.Itoa(n))
			s.processes[uint32(n)] = ownerProcessFixture("fixture", map[string]uint64{"1": 123})
		}
		out, err := attributeOwners(context.Background(), []uint64{123}, s)
		if err != nil {
			t.Fatal(err)
		}
		if len(out[123].Owners) != MaxOwnersPerSocket {
			t.Fatal("owner cap")
		}
		expected := Attribution{AttributionObserved, ReasonNone}
		if count > MaxOwnersPerSocket {
			expected = Attribution{AttributionPartial, ReasonOwnerLimit}
		}
		if out[123].Attribution != expected {
			t.Fatal(out[123].Attribution)
		}
	}
	for _, count := range []int{MaxFDEntriesPerProcess, MaxFDEntriesPerProcess + 1} {
		s := ownerSourceFixture(1)
		p := s.processes[1]
		p.fds.names = nil
		p.fds.inodes = map[string]uint64{}
		for n := 0; n < count; n++ {
			fd := strconv.Itoa(n)
			p.fds.names = append(p.fds.names, fd)
			p.fds.inodes[fd] = 123
		}
		out, err := attributeOwners(context.Background(), []uint64{123}, s)
		if err != nil {
			t.Fatal(err)
		}
		expected := Attribution{AttributionObserved, ReasonNone}
		if count > MaxFDEntriesPerProcess {
			expected = Attribution{AttributionPartial, ReasonWorkLimit}
		}
		if out[123].Attribution != expected || len(out[123].Owners) != 1 || p.fds.calls != MaxFDEntriesPerProcess {
			t.Fatalf("FD boundary count=%d result=%+v calls=%d", count, out[123], p.fds.calls)
		}
	}
}

func TestOwnerSeamPIDDirectoryAndTotalFDLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		count   int
		numeric bool
		reason  Reason
	}{
		{"exact PID", MaxProcessEntries, true, ReasonNoMatch}, {"excess PID", MaxProcessEntries + 1, true, ReasonWorkLimit},
		{"exact directory", MaxDirectoryEntries, false, ReasonNoMatch}, {"excess directory", MaxDirectoryEntries + 1, false, ReasonWorkLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := ownerSourceFixture()
			s.fallback = ownerProcessFixture("fixture", nil)
			for n := 0; n < tc.count; n++ {
				name := "ignored-" + strconv.Itoa(n)
				if tc.numeric {
					name = strconv.Itoa(n + 1)
				}
				s.entries.names = append(s.entries.names, name)
			}
			out, err := attributeOwners(context.Background(), []uint64{123}, s)
			if err != nil || out[123].Attribution.Reason != tc.reason {
				t.Fatalf("out=%+v err=%v", out, err)
			}
			if tc.numeric && s.opens != min(tc.count, MaxProcessEntries) {
				t.Fatal("PID work bound changed")
			}
		})
	}
	s := ownerSourceFixture()
	s.fallback = ownerProcessFixture("fixture", nil)
	for n := 0; n < MaxFDEntriesPerProcess; n++ {
		s.fallback.fds.names = append(s.fallback.fds.names, strconv.Itoa(n))
	}
	for n := 1; n <= MaxTotalFDEntries/MaxFDEntriesPerProcess+1; n++ {
		s.entries.names = append(s.entries.names, strconv.Itoa(n))
	}
	out, err := attributeOwners(context.Background(), []uint64{123}, s)
	if err != nil || out[123].Attribution != (Attribution{AttributionPartial, ReasonWorkLimit}) || s.opens != MaxTotalFDEntries/MaxFDEntriesPerProcess {
		t.Fatalf("total FD limit out=%+v opens=%d err=%v", out, s.opens, err)
	}
}

func TestOwnerSeamCancellationAndReadFailuresCloseResources(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := ownerSourceFixture(1)
	out, err := attributeOwners(ctx, []uint64{123}, s)
	if err != nil || out[123].Attribution != (Attribution{AttributionPartial, ReasonTimeout}) || s.opens != 0 || s.entries.closes != 1 {
		t.Fatalf("cancel out=%+v err=%v", out, err)
	}
	for _, stage := range []string{"PID listing", "FD listing"} {
		s = ownerSourceFixture(1)
		if stage == "PID listing" {
			s.entries.err = fmt.Errorf("private fixture pathname")
		} else {
			s.processes[1].fds.err = fmt.Errorf("private fixture pathname")
		}
		out, err = attributeOwners(context.Background(), []uint64{123}, s)
		if err != nil || out[123].Attribution.Reason != ReasonReadFailed || s.entries.closes != 1 {
			t.Fatal(stage, out, err)
		}
		if stage == "FD listing" && (s.processes[1].closes != 1 || s.processes[1].fds.closes != 1) {
			t.Fatal("FD failure leaked")
		}
	}
	s = ownerSourceFixture(1)
	s.processes[1].fds.names = []string{"../fd"}
	out, err = attributeOwners(context.Background(), []uint64{123}, s)
	if err != nil || out[123].Attribution.Reason != ReasonInvalidSource || s.processes[1].fds.calls != 0 {
		t.Fatal("unsafe FD entry used")
	}
	s = ownerSourceFixture(1)
	if _, err = attributeOwners(context.Background(), make([]uint64, MaxSocketRows+1), s); err != ErrItemLimit || s.opens != 0 {
		t.Fatal("socket bound")
	}
	if got := preferAttributionReason(ReasonPermissionDenied, ReasonProcessGone); got != ReasonPermissionDenied {
		t.Fatal("precedence changed")
	}
	if !reflect.DeepEqual(out[123].Owners, []Owner{}) {
		t.Fatal("unexpected metadata")
	}
}

// This adapter exists only in fixtures. The production provider still reads FD links.
func TestOwnerSeamFDInfoRequiresMountAndWantedInode(t *testing.T) {
	s := ownerSourceFixture(1)
	p := s.processes[1]
	p.fds.names = []string{"1", "2", "3"}
	p.fds.mount = 9
	p.fds.fdinfo = map[string]string{
		"1": strings.Replace(socketFDInfo, "mnt_id:\t9", "mnt_id:\t10", 1),
		"2": strings.Replace(socketFDInfo, "ino:\t123", "ino:\t456", 1),
		"3": socketFDInfo,
	}
	out, err := attributeOwners(context.Background(), []uint64{123}, s)
	if err != nil || len(out) != 1 || len(out[123].Owners) != 1 || p.fds.calls != 3 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	p.fds.names = []string{"1", "2"}
	s.entries.offset = 0
	out, err = attributeOwners(context.Background(), []uint64{123}, s)
	if err != nil || len(out[123].Owners) != 0 || out[123].Attribution.Reason != ReasonNoMatch {
		t.Fatal("inode-only or unwanted-inode match")
	}
}

func TestOwnerSeamMalformedSocketPreservesNativeReasonPrecedence(t *testing.T) {
	s := ownerSourceFixture(1)
	f := s.processes[1].fds
	f.names = []string{"1", "2"}
	f.inodes = map[string]uint64{"2": 0}
	f.errors = map[string]error{"1": SourceError{ReasonPermissionDenied}, "2": ErrInvalidSource}
	out, err := attributeOwners(context.Background(), []uint64{123}, s)
	if err != nil || out[123].Attribution.Reason != ReasonInvalidSource {
		t.Fatal("native malformed-socket precedence changed")
	}
}

func TestOwnerSeamTotalFDOneBelowLimit(t *testing.T) {
	s := ownerSourceFixture()
	s.fallback = ownerProcessFixture("fixture", nil)
	for n := 0; n < MaxFDEntriesPerProcess; n++ {
		s.fallback.fds.names = append(s.fallback.fds.names, strconv.Itoa(n))
	}
	count := MaxTotalFDEntries / MaxFDEntriesPerProcess
	for n := 1; n <= count; n++ {
		s.entries.names = append(s.entries.names, strconv.Itoa(n))
	}
	last := ownerProcessFixture("fixture", nil)
	last.fds.names = append([]string(nil), s.fallback.fds.names[:MaxFDEntriesPerProcess-1]...)
	s.processes[uint32(count)] = last
	out, err := attributeOwners(context.Background(), []uint64{123}, s)
	if err != nil || out[123].Attribution != (Attribution{AttributionUnavailable, ReasonNoMatch}) || s.opens != count {
		t.Fatalf("below total limit out=%+v err=%v", out, err)
	}
}

func TestOwnerSeamPartialEnumerationErrorNeverAdmitsPrefix(t *testing.T) {
	for _, stage := range []string{"PID", "FD"} {
		s := ownerSourceFixture(1)
		d := s.entries
		if stage == "FD" {
			d = &s.processes[1].fds.ownerFixtureEntries
		}
		d.err = fmt.Errorf("private source failure")
		d.partialError = true
		out, err := attributeOwners(context.Background(), []uint64{123}, s)
		if err != nil || len(out[123].Owners) != 0 || out[123].Attribution.Reason != ReasonReadFailed {
			t.Fatalf("stage=%s out=%+v err=%v", stage, out, err)
		}
		if s.entries.closes != 1 || stage == "FD" && (s.processes[1].closes != 1 || s.processes[1].fds.closes != 1) {
			t.Fatal("partial-read resource leak")
		}
	}
}

func TestOwnerSeamCancellationAfterOpeningProcessClosesDescriptors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := ownerSourceFixture(1)
	s.onOpenProcess = cancel
	out, err := attributeOwners(ctx, []uint64{123}, s)
	p := s.processes[1]
	if err != nil || out[123].Attribution.Reason != ReasonTimeout || len(out[123].Owners) != 0 || s.entries.closes != 1 || p.closes != 1 || p.fds.closes != 1 || p.nameCloses != 0 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}
