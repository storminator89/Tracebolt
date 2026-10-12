package windowspackage

import "testing"

func TestSynchronousCustomActionEligibility(t *testing.T) {
	for _, value := range []int32{1, 2, 5, 6, 17, 18, 34, 51, 65, 1025, 3073} {
		if !synchronousCustomActionType(value) {
			t.Fatalf("synchronous type %d rejected", value)
		}
	}
	for _, value := range []int32{-2147483648, -1, 129, 130, 193, 194, 1153, 3265, 65536} {
		if synchronousCustomActionType(value) {
			t.Fatalf("asynchronous/invalid type %d accepted", value)
		}
	}
}
