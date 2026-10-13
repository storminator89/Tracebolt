package enrollmentstate

import "testing"

func TestObservationPlatformMapsOnlyDarwin(t *testing.T) {
	for _, input := range []string{"darwin", "linux", "windows", "macos", "Darwin", "", "freebsd"} {
		want := input
		if input == "darwin" {
			want = "macos"
		}
		if ObservationPlatform(input) != want {
			t.Fatal("platform alias widened", input)
		}
	}
}
