package windowsstate

import (
	"encoding/binary"
	"strings"
	"testing"
)

const testSID = "S-1-5-80-1-2-3-4-5"

func optionsFixture() Options {
	return Options{RuntimeSID: testSID, Names: []string{"state.json"}, Directories: []string{"telemetry"}, LockName: "store.lock", TempName: "store.tmp", MaxBytes: 1024}
}
func TestPathPolicyFixtures(t *testing.T) {
	for _, path := range []string{`C:\ProgramData\Tracebolt`, `D:\Protected state\enrollment`} {
		if _, e := splitPath(path); e != nil {
			t.Fatalf("canonical path rejected: %s", path)
		}
	}
	for _, path := range []string{"", `C:\`, `c:\safe`, `C:relative`, `relative`, `\rooted`, `\\server\share`, `\\?\C:\safe`, `\\.\C:\safe`, `C:/safe`, `C:\safe\..\state`, `C:\safe\.\state`, `C:\safe\\state`, `C:\safe\state:secret`, `C:\safe\name.`, `C:\safe\name `, `C:\safe\CON`, `C:\safe\aux.json`, `C:\safe\COM1.cfg`, `C:\safe\LPT9`, `C:\PROGRA~1\state`, `C:\%USERPROFILE%\state`, `C:\Straße\state`, `C:\safe\bad\`, "C:\\safe\\a\x00b"} {
		if _, e := splitPath(path); e == nil {
			t.Errorf("unsafe path accepted: %q", path)
		}
	}
}
func TestOptionsPolicyFixtures(t *testing.T) {
	o := optionsFixture()
	if e := validateOptions(o); e != nil {
		t.Fatal(e)
	}
	tests := []func(*Options){func(o *Options) { o.RuntimeSID = "S-1-5-19" }, func(o *Options) { o.RuntimeSID = administratorsSID }, func(o *Options) { o.RuntimeSID = "S-1-5-80-0-0-0-0-0" }, func(o *Options) { o.RuntimeSID = "S-1-5-80-01-2-3-4-5" }, func(o *Options) { o.RuntimeSID = "S-1-5-80-4294967296-2-3-4-5" }, func(o *Options) { o.InstallerOnly = true }, func(o *Options) { o.MaxBytes = 0 }, func(o *Options) { o.MaxBytes = maxFileBytes + 1 }, func(o *Options) { o.Names = nil }, func(o *Options) { o.Names = []string{"Store.JSON"} }, func(o *Options) { o.Names = []string{"state.json", "state.json"} }, func(o *Options) { o.TempName = o.LockName }, func(o *Options) { o.Directories = []string{"state.json"} }, func(o *Options) { o.LockName = "../lock" }, func(o *Options) { o.Names = []string{"con.txt"} }, func(o *Options) { o.Names = []string{"data:stream"} }}
	for i, change := range tests {
		o = optionsFixture()
		change(&o)
		if e := validateOptions(o); e == nil {
			t.Errorf("invalid options fixture %d accepted", i)
		}
	}
	o = optionsFixture()
	o.InstallerOnly = true
	o.RuntimeSID = ""
	if e := validateOptions(o); e != nil {
		t.Fatal("explicit installer policy rejected")
	}
}
func policyFixture() securityPolicy {
	return securityPolicy{owner: administratorsSID, protected: true, present: true, entries: []accessEntry{{sid: systemSID, mask: fileAllAccess}, {sid: administratorsSID, mask: fileAllAccess}, {sid: testSID, mask: fileAllAccess}}}
}
func TestACLPolicyFixtures(t *testing.T) {
	for _, owner := range []string{systemSID, administratorsSID, testSID} {
		p := policyFixture()
		p.owner = owner
		if e := validateSecurity(p, testSID, false); e != nil {
			t.Fatal("trusted owner rejected")
		}
	}
	tests := []func(*securityPolicy){func(p *securityPolicy) { p.owner = "S-1-5-19" }, func(p *securityPolicy) { p.owner = "S-1-5-21-1-2-3-4" }, func(p *securityPolicy) { p.protected = false }, func(p *securityPolicy) { p.present = false }, func(p *securityPolicy) { p.defaulted = true }, func(p *securityPolicy) { p.entries = nil }, func(p *securityPolicy) { p.entries[2].sid = "S-1-1-0" }, func(p *securityPolicy) { p.entries[2].flags = 0x10 }, func(p *securityPolicy) { p.entries[2].flags = 8 }, func(p *securityPolicy) { p.entries[2].kind = 1 }, func(p *securityPolicy) { p.entries[2].kind = 5 }, func(p *securityPolicy) { p.entries[2].kind = 9 }, func(p *securityPolicy) { p.entries[2].mask = 0x10000000 }, func(p *securityPolicy) { p.entries[2].mask = 0x120089 }, func(p *securityPolicy) { p.entries[2].sid = systemSID }, func(p *securityPolicy) { p.entries = append(p.entries, accessEntry{sid: "S-1-5-19", mask: 0x120089}) }}
	for i, change := range tests {
		p := policyFixture()
		change(&p)
		if e := validateSecurity(p, testSID, false); e == nil {
			t.Errorf("unsafe ACL %d accepted", i)
		}
	}
	p := policyFixture()
	p.entries = p.entries[:2]
	if e := validateSecurity(p, "", true); e != nil {
		t.Fatal(e)
	}
	if e := validateSecurity(p, testSID, false); e == nil {
		t.Fatal("installer schema widened to runtime")
	}
}
func fixtureSID(last uint32) []byte {
	b := make([]byte, 12)
	b[0] = 1
	b[1] = 1
	b[7] = 5
	binary.LittleEndian.PutUint32(b[8:], last)
	return b
}
func descriptorFixture() []byte {
	owner := fixtureSID(18)
	aceSID := fixtureSID(18)
	ace := make([]byte, 8+len(aceSID))
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], fileAllAccess)
	copy(ace[8:], aceSID)
	b := make([]byte, 20+len(owner)+8+len(ace))
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:4], 0x9004)
	binary.LittleEndian.PutUint32(b[4:8], 20)
	binary.LittleEndian.PutUint32(b[16:20], 32)
	copy(b[20:], owner)
	b[32] = 2
	binary.LittleEndian.PutUint16(b[34:36], uint16(8+len(ace)))
	binary.LittleEndian.PutUint16(b[36:38], 1)
	copy(b[40:], ace)
	return b
}
func TestDescriptorParserFixtures(t *testing.T) {
	b := descriptorFixture()
	p, e := parseDescriptor(b)
	if e != nil || p.owner != systemSID || len(p.entries) != 1 || p.entries[0].sid != systemSID {
		t.Fatal("valid descriptor parser fixture failed")
	}
	for i := 0; i < len(b); i++ {
		if _, e := parseDescriptor(b[:i]); e == nil {
			t.Errorf("truncated descriptor %d accepted", i)
		}
	}
	mutations := []func([]byte){func(b []byte) { b[0] = 2 }, func(b []byte) { b[3] &= 0x7f }, func(b []byte) { binary.LittleEndian.PutUint32(b[4:8], 0xffffffff) }, func(b []byte) { binary.LittleEndian.PutUint32(b[16:20], 0xffffffff) }, func(b []byte) { b[32] = 4 }, func(b []byte) { b[36] = 255 }, func(b []byte) { b[42] = 255 }, func(b []byte) { b[49] = 16 }}
	for i, change := range mutations {
		x := append([]byte{}, b...)
		change(x)
		if _, e := parseDescriptor(x); e == nil {
			t.Errorf("malformed descriptor %d accepted", i)
		}
	}
}
func directoryFixture(name string) []byte {
	b := make([]byte, 104+len(name)*2)
	binary.LittleEndian.PutUint32(b[60:64], uint32(len(name)*2))
	for i, c := range name {
		binary.LittleEndian.PutUint16(b[104+2*i:], uint16(c))
	}
	return b
}
func TestDirectoryParserFixtures(t *testing.T) {
	b := directoryFixture("state.json")
	names, e := parseDirectoryBuffer(b)
	if e != nil || len(names) != 1 || names[0] != "state.json" {
		t.Fatal("valid directory fixture rejected")
	}
	for _, name := range []string{"../state", "data:stream", "STATE.JSON", "con", "", "x\x00z"} {
		if _, e := parseDirectoryBuffer(directoryFixture(name)); e == nil {
			t.Errorf("unsafe directory entry accepted: %q", name)
		}
	}
	for i := 0; i < len(b); i++ {
		if _, e := parseDirectoryBuffer(b[:i]); e == nil {
			t.Errorf("truncated directory %d accepted", i)
		}
	}
	for _, next := range []uint32{1, 8, 103, 105, 0xffffffff} {
		x := append([]byte{}, b...)
		binary.LittleEndian.PutUint32(x[:4], next)
		if _, e := parseDirectoryBuffer(x); e == nil {
			t.Errorf("invalid next offset %d accepted", next)
		}
	}
}
func TestDefaultStreamFixtures(t *testing.T) {
	b := make([]byte, 38)
	binary.LittleEndian.PutUint32(b[4:8], 14)
	for i, c := range "::$DATA" {
		binary.LittleEndian.PutUint16(b[24+2*i:], uint16(c))
	}
	if e := validateDefaultStream(b); e != nil {
		t.Fatal(e)
	}
	b[0] = 1
	if validateDefaultStream(b) == nil {
		t.Fatal("extra stream accepted")
	}
	b[0] = 0
	b[26] = 'x'
	if validateDefaultStream(b) == nil {
		t.Fatal("nondefault stream accepted")
	}
}
func FuzzDescriptorParser(f *testing.F) {
	f.Add(descriptorFixture())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseDescriptor(b) })
}
func FuzzDirectoryParser(f *testing.F) {
	f.Add(directoryFixture("state.json"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseDirectoryBuffer(b) })
}
func TestErrorsNeverEchoInput(t *testing.T) {
	secret := "fixture-secret-do-not-echo"
	_, e := splitPath(secret)
	if e == nil || strings.Contains(e.Error(), secret) {
		t.Fatal("input leaked")
	}
}
