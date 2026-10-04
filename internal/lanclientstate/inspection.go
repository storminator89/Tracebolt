package lanclientstate

// InspectionLease retains the existing sender ownership lock without exposing
// state mutation methods. Acquiring it never initializes missing state or
// cleans crash temporaries. Call Close when local inspection/configuration ends.
type InspectionLease struct{ state *State }

func AcquireInspection(dir, binding string) (*InspectionLease, error) {
	state, e := open(dir, binding, false, false)
	if e != nil {
		return nil, e
	}
	return &InspectionLease{state: state}, nil
}
func (l *InspectionLease) Close() error {
	if l == nil {
		return nil
	}
	return l.state.Close()
}
