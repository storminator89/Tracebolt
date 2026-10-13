//go:build !darwin || !tracebolt_endpoint_native

// The executable is intentionally inert. Runtime source below is unreachable
// until a separately reviewed exact native gate is added. No flag/env unlocks it.
package main

import "os"

const blockedResult = `{"schemaVersion":"tracebolt.macos-endpoint-fixture.v1","status":"blocked","reason":"native_execution_gate_unavailable","simulatedManager":true,"runtimeStarted":false}`

func main() { _, _ = os.Stdout.WriteString(blockedResult + "\n") }
