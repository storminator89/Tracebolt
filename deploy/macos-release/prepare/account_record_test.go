package main

import "testing"

func TestExactPartialDirectoryRecordRejectsAdoption(t *testing.T) {
	const name = "_traceboltagent"
	valid := "RecordName: _traceboltagent\nUniqueID: 502\n"
	if err := exactPartialRecord(valid, name, map[string]string{"UniqueID": "502"}, "PrimaryGroupID"); err != nil {
		t.Fatalf("exact partial record rejected: %v", err)
	}
	for label, text := range map[string]string{
		"unexpected attribute":       "RecordName: _traceboltagent\nUniqueID: 502\nGeneratedUID: preexisting-identity\n",
		"credential material":        "RecordName: _traceboltagent\nUniqueID: 502\nShadowHashData: preexisting-secret\n",
		"continued value":            "RecordName: _traceboltagent\nUniqueID: 502\n continued\n",
		"duplicate attribute":        "RecordName: _traceboltagent\nUniqueID: 502\nUniqueID: 502\n",
		"next field already present": "RecordName: _traceboltagent\nUniqueID: 502\nPrimaryGroupID: 502\n",
		"missing newline":            "RecordName: _traceboltagent\nUniqueID: 502",
	} {
		t.Run(label, func(t *testing.T) {
			if err := exactPartialRecord(text, name, map[string]string{"UniqueID": "502"}, "PrimaryGroupID"); err == nil {
				t.Fatal("ambiguous or preexisting record accepted")
			}
		})
	}
}
