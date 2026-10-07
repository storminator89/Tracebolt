package windowsconsole

import (
	"context"
	"errors"
	"testing"
	"time"
)

var fixtureFailure = errors.New("private native or callback diagnostic must not escape")

type fixtureConsole struct {
	current       uint32
	records       []inputRecord
	modeCalls     int
	setCalls      int
	discardCalls  int
	readCalls     int
	closeCalls    int
	failMode      int
	wrongMode     int
	failSet       int
	failDiscard   int
	failRead      int
	failClose     bool
	onRead        func(int)
	endlessEvents bool
	sets          []uint32
}

func newFixtureConsole() *fixtureConsole {
	return &fixtureConsole{current: processedInput | lineInput | echoInput | quickEdit | extendedFlags | virtualInput | 0x18,
		records: fixtureRecords()}
}

func (f *fixtureConsole) mode() (uint32, error) {
	f.modeCalls++
	if f.modeCalls == f.failMode {
		return 0, fixtureFailure
	}
	if f.modeCalls == f.wrongMode {
		return f.current ^ echoInput, nil
	}
	return f.current, nil
}

func (f *fixtureConsole) setMode(mode uint32) error {
	f.setCalls++
	f.sets = append(f.sets, mode)
	// Simulate a failed call that may already have changed external state.
	f.current = mode
	if f.setCalls == f.failSet {
		return fixtureFailure
	}
	return nil
}

func (f *fixtureConsole) readRecord() (inputRecord, bool, error) {
	f.readCalls++
	if f.onRead != nil {
		f.onRead(f.readCalls)
	}
	if f.readCalls == f.failRead {
		return key('B', 5), true, fixtureFailure
	}
	if len(f.records) != 0 {
		record := f.records[0]
		f.records = f.records[1:]
		return record, true, nil
	}
	if f.endlessEvents {
		return inputRecord{eventType: 2}, true, nil
	}
	return inputRecord{}, false, nil
}

func (f *fixtureConsole) discard() error {
	f.discardCalls++
	if f.discardCalls == f.failDiscard {
		return fixtureFailure
	}
	return nil
}

func (f *fixtureConsole) close() error {
	f.closeCalls++
	if f.failClose {
		return fixtureFailure
	}
	return nil
}

func runFixture(ctx context.Context, f *fixtureConsole, prompt func() error) ([]byte, error) {
	return readWithConsole(ctx, prompt, func() (console, error) { return f, nil })
}

func TestReadFixtureRestoresAndCloses(t *testing.T) {
	for _, extended := range []bool{false, true} {
		f := newFixtureConsole()
		if !extended {
			f.current &^= extendedFlags
		}
		original := f.current
		called := 0
		secret, err := runFixture(context.Background(), f, func() error {
			called++
			if f.current != hiddenMode(original) || f.discardCalls != 1 || f.readCalls != 0 {
				t.Fatal("prompt ran before verified hidden mode and type-ahead discard")
			}
			return nil
		})
		if err != nil || len(secret) != invitationLength || called != 1 {
			t.Fatal("valid console fixture failed")
		}
		clear(secret)
		if f.current != original || f.closeCalls != 1 || f.discardCalls != 2 || f.modeCalls != 3 {
			t.Fatal("console cleanup incomplete")
		}
		if len(f.sets) < 2 || f.sets[1]&extendedFlags == 0 || f.sets[1]&quickEdit == 0 {
			t.Fatal("Quick Edit restoration omitted required extended flag")
		}
	}
}

func TestReadFixtureSanitizesEveryFailure(t *testing.T) {
	cases := []struct {
		name   string
		change func(*fixtureConsole)
	}{
		{"initial mode", func(f *fixtureConsole) { f.failMode = 1 }},
		{"disable mode", func(f *fixtureConsole) { f.failSet = 1 }},
		{"verify hidden mode", func(f *fixtureConsole) { f.failMode = 2 }},
		{"echo still enabled", func(f *fixtureConsole) { f.wrongMode = 2 }},
		{"initial discard", func(f *fixtureConsole) { f.failDiscard = 1 }},
		{"read failure", func(f *fixtureConsole) { f.failRead = 2 }},
		{"invalid input", func(f *fixtureConsole) { f.records = []inputRecord{key('A', 42), key('!', 1)} }},
		{"exit discard", func(f *fixtureConsole) { f.failDiscard = 2 }},
		{"restore mode", func(f *fixtureConsole) { f.failSet = 2 }},
		{"restore original extended flag", func(f *fixtureConsole) { f.current &^= extendedFlags; f.failSet = 3 }},
		{"verify restored mode", func(f *fixtureConsole) { f.failMode = 3 }},
		{"restored mode differs", func(f *fixtureConsole) { f.wrongMode = 3 }},
		{"close failure", func(f *fixtureConsole) { f.failClose = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixtureConsole()
			tc.change(f)
			original := f.current
			secret, err := runFixture(context.Background(), f, func() error { return nil })
			if secret != nil || err != ErrInput || err.Error() != "hidden console invitation input unavailable or invalid" {
				t.Fatal("failure exposed secret or diagnostic")
			}
			if f.closeCalls != 1 {
				t.Fatal("failure did not close console")
			}
			if f.failMode != 1 && (f.current != original || f.setCalls < 2) {
				t.Fatal("failure omitted mode restoration")
			}
		})
	}
}

func TestReadFixturePromptFailureAndPanicRestore(t *testing.T) {
	for _, panicPrompt := range []bool{false, true} {
		f := newFixtureConsole()
		original := f.current
		func() {
			defer func() {
				value := recover()
				if panicPrompt && value != fixtureFailure || !panicPrompt && value != nil {
					t.Fatal("unexpected callback panic behavior")
				}
			}()
			secret, err := runFixture(context.Background(), f, func() error {
				if panicPrompt {
					panic(fixtureFailure)
				}
				return fixtureFailure
			})
			if secret != nil || err != ErrInput {
				t.Fatal("prompt failure exposed material")
			}
		}()
		if f.current != original || f.closeCalls != 1 || f.readCalls != 0 || f.discardCalls != 2 {
			t.Fatal("prompt failure omitted cleanup")
		}
	}
}

func TestReadFixtureCancellationWithoutCharacters(t *testing.T) {
	for _, events := range []bool{false, true} {
		f := newFixtureConsole()
		f.records = nil
		f.endlessEvents = events
		original := f.current
		ctx, cancel := context.WithCancel(context.Background())
		f.onRead = func(reads int) {
			if reads == 3 {
				cancel()
			}
		}
		start := time.Now()
		secret, err := runFixture(ctx, f, func() error { return nil })
		cancel()
		if err != ErrInput || secret != nil || f.readCalls != 3 || time.Since(start) > time.Second {
			t.Fatal("cancellation was not bounded")
		}
		if f.current != original || f.closeCalls != 1 || f.discardCalls != 2 {
			t.Fatal("cancellation omitted cleanup")
		}
	}
}

func TestReadFixtureDeadlineAndCancellationAtCompletion(t *testing.T) {
	f := newFixtureConsole()
	f.records = nil
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	secret, err := runFixture(ctx, f, func() error { return nil })
	if err != ErrInput || secret != nil || f.closeCalls != 1 {
		t.Fatal("deadline did not fail closed")
	}
	f = newFixtureConsole()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	f.onRead = func(reads int) {
		if reads == 2 {
			cancel()
		}
	}
	secret, err = runFixture(ctx, f, func() error { return nil })
	if err != ErrInput || secret != nil || f.closeCalls != 1 {
		t.Fatal("cancellation at completion returned material")
	}
}

func TestReadRejectsBeforeOpening(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		secret, err := readWithConsole(ctx, func() error { t.Fatal("unexpected prompt"); return nil },
			func() (console, error) { t.Fatal("unexpected console open"); return nil, nil })
		if secret != nil || err != ErrInput {
			t.Fatal("invalid context accepted")
		}
	}
	secret, err := readWithConsole(context.Background(), nil,
		func() (console, error) { t.Fatal("unexpected console open"); return nil, nil })
	if secret != nil || err != ErrInput {
		t.Fatal("nil prompt accepted")
	}
	secret, err = readWithConsole(context.Background(), func() error { t.Fatal("unexpected prompt"); return nil },
		func() (console, error) { return nil, fixtureFailure })
	if secret != nil || err != ErrInput {
		t.Fatal("open failure exposed native diagnostic")
	}
}

func TestPublicInputValidationDoesNotOpenConsole(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		secret, err := ReadInvitation(ctx, func() error { t.Fatal("unexpected prompt"); return nil })
		if secret != nil || err != ErrInput {
			t.Fatal("invalid public context accepted")
		}
	}
	secret, err := ReadInvitation(context.Background(), nil)
	if secret != nil || err != ErrInput {
		t.Fatal("nil public prompt accepted")
	}
}

func TestConsoleSerializationWaitIsCancellable(t *testing.T) {
	// Occupy only the in-memory gate. The timed-out call cannot reach any
	// native API, on Windows or on the portable fixture runner.
	consoleGate <- struct{}{}
	defer func() { <-consoleGate }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	secret, err := ReadInvitation(ctx, func() error { t.Fatal("unexpected prompt"); return nil })
	if secret != nil || err != ErrInput {
		t.Fatal("serialized call ignored cancellation")
	}
}
