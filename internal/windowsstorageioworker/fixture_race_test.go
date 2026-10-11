//go:build race

package windowsstorageioworker

import "time"

// Race children inherit only the production sanitized environment, not GORACE.
// https://go.dev/doc/articles/race_detector documents atexit_sleep_ms=1000.
const raceFixtureExitDelay = time.Second
