//go:build !windows

package native

import (
	"context"
	"localrmm/internal/enrollmentclient"
)

func (d *Driver) preflight(context.Context) error              { return d.fail(ReasonUnsupported) }
func (d *Driver) provision(context.Context, Guard) error       { return d.fail(ReasonUnsupported) }
func (d *Driver) prepare(context.Context, Guard, []byte) error { return d.fail(ReasonUnsupported) }
func (d *Driver) claim(context.Context, Guard, func(context.Context) ([]byte, error), func(enrollmentclient.TrustDisplay) error) error {
	return d.fail(ReasonUnsupported)
}
func (d *Driver) start(context.Context, Guard) error     { return d.fail(ReasonUnsupported) }
func (d *Driver) inspectToken(context.Context) error     { return d.fail(ReasonUnsupported) }
func (d *Driver) status(context.Context) error           { return d.fail(ReasonUnsupported) }
func (d *Driver) stateContinuity(context.Context) error  { return d.fail(ReasonUnsupported) }
func ProbeContextValid() bool                            { return false }
func (d *Driver) probe(context.Context, Guard) error     { return d.fail(ReasonUnsupported) }
func (d *Driver) stop(context.Context, Guard) error      { return d.fail(ReasonUnsupported) }
func (d *Driver) uninstall(context.Context, Guard) error { return d.fail(ReasonUnsupported) }
func (d *Driver) cleanup(context.Context, Guard) error   { return d.fail(ReasonUnsupported) }
func runProbeRuntime(context.Context) error              { return ErrAcceptance }

func (d *Driver) cleanupStop(context.Context, Guard) error { return d.fail(ReasonUnsupported) }

func (d *Driver) releasePrerequisiteHandles() {}
