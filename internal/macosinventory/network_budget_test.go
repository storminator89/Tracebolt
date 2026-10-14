package macosinventory

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestNetworkDoesNotStartACommandAfterSharedCancellation(t *testing.T) {
	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		n, err := commandSources(func(context.Context, fixedCommand) ([]byte, error) {
			calls++
			return nil, errors.New("unexpected command")
		}).Network(ctx)
		if err != nil || calls != 0 || n.IPv4.Reason != ErrBudget.Error() ||
			n.IPv6.Reason != ErrBudget.Error() || !validInterfaces(n.IPv4, IPv4Source, false) ||
			!validInterfaces(n.IPv6, IPv6Source, true) {
			t.Fatalf("canceled source invoked a command or forged a result: calls=%d, err=%v, network=%#v", calls, err, n)
		}
	})

	t.Run("canceled after IPv4", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := []fixedCommand{}
		n, err := commandSources(func(_ context.Context, which fixedCommand) ([]byte, error) {
			calls = append(calls, which)
			if which != ipv4Command {
				return nil, errors.New("unexpected IPv6 command")
			}
			cancel()
			return []byte(ipv4Fixture), nil
		}).Network(ctx)
		wantIPv4, parseErr := ParseInterfaces([]byte(ipv4Fixture), false)
		if parseErr != nil || err != nil || !reflect.DeepEqual(calls, []fixedCommand{ipv4Command}) ||
			!reflect.DeepEqual(n.IPv4, wantIPv4) || n.IPv6.Reason != ErrBudget.Error() ||
			len(n.IPv6.Rows) != 0 {
			t.Fatalf("lost completed family or started canceled sibling: calls=%v, err=%v, network=%#v", calls, err, n)
		}
	})
}

func TestNetworkCommandTimeoutDoesNotEraseOtherFamily(t *testing.T) {
	calls := []fixedCommand{}
	n, err := commandSources(func(ctx context.Context, which fixedCommand) ([]byte, error) {
		calls = append(calls, which)
		if which == ipv4Command {
			// One command's timeout does not mean the shared provider deadline
			// has elapsed. The other family remains eligible for a read.
			return nil, ErrBudget
		}
		return fixtures(ctx, which)
	}).Network(context.Background())
	wantIPv6, parseErr := ParseInterfaces([]byte(ipv6Fixture), true)
	if parseErr != nil || err != nil || !reflect.DeepEqual(calls, []fixedCommand{ipv4Command, ipv6Command}) ||
		n.IPv4.Reason != ErrBudget.Error() || !reflect.DeepEqual(n.IPv6, wantIPv6) {
		t.Fatalf("one family failure erased the sibling: calls=%v, err=%v, network=%#v", calls, err, n)
	}
}
