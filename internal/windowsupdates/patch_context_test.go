package windowsupdates

import (
	"math"
	"testing"
	"time"
)

func TestPatchDateUTCAndBounds(t *testing.T) {
	got, e := patchDate(25569.5)
	if e != nil || !got.Equal(time.Date(1970, 1, 1, 12, 0, 0, 0, time.UTC)) || got.Location() != time.UTC {
		t.Fatal(got, e)
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), 25568, 2958466} {
		if _, e := patchDate(v); e == nil {
			t.Fatal(v)
		}
	}
}
