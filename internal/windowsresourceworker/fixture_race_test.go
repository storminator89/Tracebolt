//go:build race

package windowsresourceworker

import "time"

// Race children inherit only the production sanitized environment, not GORACE.
// https://go.dev/doc/articles/race_detector#Options documents atexit_sleep_ms=1000.
const raceFixtureExitDelay = time.Second
