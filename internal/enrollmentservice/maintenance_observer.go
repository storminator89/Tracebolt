package enrollmentservice

// MaintenanceObserver observes existing manager-owned work only. It never
// receives source content or creates an endpoint grant, job or retry authority.
// Callbacks are trusted in-process dependencies, never request configuration.
type MaintenanceObserver struct {
	Started   func()
	Completed func(error)
}

func (o MaintenanceObserver) start() {
	if o.Started != nil {
		o.Started()
	}
}
func (o MaintenanceObserver) complete(err error) {
	if o.Completed != nil {
		o.Completed(err)
	}
}
