package macosservice

import "strings"

// Fixed names and paths are not shell syntax. The only variable is the canonical
// numeric identity already accepted by Plan. UserName/GroupName select the
// dedicated account and the process verifies all numeric IDs before private reads.
// InitGroups=false prevents launchd from adding supplementary account groups.
// Do not infer Linux sandboxing or a bounded restart budget from this plist:
// launchd's ThrottleInterval only spaces retries; KeepAlive may retry indefinitely.
func plistForIdentity(id string) string {
	return strings.Replace(plistTemplate, "SERVICE_IDENTITY", id, 1)
}

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.tracebolt.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Library/Application Support/TraceboltAgent/macos-agent</string>
    <string>--config</string>
    <string>/Library/Application Support/TraceboltAgent/state/enrollment/agent.json</string>
    <string>--foreground</string>
    <string>--interval</string><string>30s</string>
    <string>--service-identity</string><string>SERVICE_IDENTITY</string>
  </array>
  <key>UserName</key><string>_traceboltagent</string>
  <key>GroupName</key><string>_traceboltagent</string>
  <key>InitGroups</key><false/>
  <key>WorkingDirectory</key><string>/Library/Application Support/TraceboltAgent/state</string>
  <key>Umask</key><integer>63</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ExitTimeOut</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
`
