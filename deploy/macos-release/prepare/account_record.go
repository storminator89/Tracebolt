package main

import "strings"

// A newly created Directory Service record may contain only its fixed name and
// attributes this helper itself just wrote. Unknown/default/continued fields
// fail closed until independently validated on the selected native macOS.
func exactPartialRecord(text, name string, expected map[string]string, next string) error {
	if text == "" || !strings.HasSuffix(text, "\n") {
		return errRejected
	}
	seen := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return errRejected
		}
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errRejected
		}
		if _, present := seen[parts[0]]; present {
			return errRejected
		}
		seen[parts[0]] = parts[1]
	}
	if len(seen) != len(expected)+1 || seen["RecordName"] != name {
		return errRejected
	}
	for key, value := range expected {
		if key == "RecordName" || seen[key] != value {
			return errRejected
		}
	}
	if next != "" {
		if _, present := seen[next]; present {
			return errRejected
		}
	}
	return nil
}
