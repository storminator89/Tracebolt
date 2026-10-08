package windowsconsole

// Category identifies only the failed operation. It never contains a native
// error, console mode, prompt text, input record or invitation material.
type Category uint8

const (
	CategoryUnknown Category = iota
	CategoryInvalid
	CategoryUnsupported
	CategoryResolve
	CategoryOpen
	CategoryType
	CategoryModeRead
	CategoryModeSet
	CategoryModeVerify
	CategoryDiscard
	CategoryPrompt
	CategoryRead
	CategoryDecode
	CategoryContext
	CategoryCleanupDiscard
	CategoryRestoreSet
	CategoryRestoreVerify
	CategoryClose
)

// inputFailure retains no underlying native or callback error. The only
// unwrapped value is the historical public sentinel.
type inputFailure struct{ category Category }

func (inputFailure) Error() string { return ErrInput.Error() }
func (inputFailure) Unwrap() error { return ErrInput }

func failure(category Category) error { return inputFailure{category: category} }

// CategoryOf returns a closed category, including for wrapped failures. Unknown
// errors, nil and the historical bare ErrInput return CategoryUnknown. It never
// invokes Error, As or Is. Traversal is bounded, and a panicking unwrapper fails
// closed rather than exposing its value or preventing cleanup diagnostics.
func CategoryOf(err error) (result Category) {
	defer func() {
		if recover() != nil {
			result = CategoryUnknown
		}
	}()
	var pending [64]error
	pending[0] = err
	for head, tail := 0, 1; head < tail; head++ {
		current := pending[head]
		pending[head] = nil
		if input, ok := current.(inputFailure); ok {
			switch input.category {
			case CategoryInvalid, CategoryUnsupported, CategoryResolve, CategoryOpen, CategoryType,
				CategoryModeRead, CategoryModeSet, CategoryModeVerify, CategoryDiscard, CategoryPrompt,
				CategoryRead, CategoryDecode, CategoryContext, CategoryCleanupDiscard,
				CategoryRestoreSet, CategoryRestoreVerify, CategoryClose:
				return input.category
			default:
				return CategoryUnknown
			}
		}
		if tail == len(pending) {
			continue
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() error }:
			pending[tail] = wrapped.Unwrap()
			tail++
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			tail += copy(pending[tail:], children)
		}
	}
	return CategoryUnknown
}

// Diagnostic returns one finite public category name. It is safe to include in
// a closed diagnostic protocol; it never returns text supplied by an error.
func Diagnostic(err error) string {
	switch CategoryOf(err) {
	case CategoryInvalid:
		return "invalid"
	case CategoryUnsupported:
		return "unsupported"
	case CategoryResolve:
		return "resolve"
	case CategoryOpen:
		return "open"
	case CategoryType:
		return "type"
	case CategoryModeRead:
		return "mode_read"
	case CategoryModeSet:
		return "mode_set"
	case CategoryModeVerify:
		return "mode_verify"
	case CategoryDiscard:
		return "discard"
	case CategoryPrompt:
		return "prompt"
	case CategoryRead:
		return "read"
	case CategoryDecode:
		return "decode"
	case CategoryContext:
		return "context"
	case CategoryCleanupDiscard:
		return "cleanup_discard"
	case CategoryRestoreSet:
		return "restore_set"
	case CategoryRestoreVerify:
		return "restore_verify"
	case CategoryClose:
		return "close"
	default:
		return "unknown"
	}
}
