package windowsmutationfence

import (
	"context"
	"testing"
	"time"
)

func TestFinalAuthorityPublicationDoesNotWaitForConcurrentStatus(t *testing.T) {
	f, r, now := testSetup(t)
	s := testSession(t, f, r, CachedWUA, now)
	c := mustReserve(t, s, testOwner(CachedWUA, 1))
	if e := s.Dispatch(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	statusDone := make(chan error, 1)
	startDone := make(chan error, 1)
	go func() {
		startDone <- s.CheckStart(context.Background(), c, func() error {
			// Final domain authority has been checked. A concurrent status call now owns
			// the session mutex and is delayed by storage. Start publication must not
			// wait behind it, letting already-checked start authority expire silently.
			f.afterOpen = func() { f.afterOpen = nil; close(entered); <-release }
			go func() { _, e := s.Status(context.Background()); statusDone <- e }()
			<-entered
			return nil
		})
	}()
	select {
	case e := <-startDone:
		close(release)
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		now.Add(120)
		close(release)
		<-startDone
		<-statusDone
		t.Fatal("CheckStart waited for a session mutex after the final authority callback")
	}
	if e := <-statusDone; e != nil {
		t.Fatal(e)
	}
	if _, e := c.Completion(testDigest("native-return-after-publication"), "completed", now.Load()); e != nil {
		t.Fatal(e)
	}
}
