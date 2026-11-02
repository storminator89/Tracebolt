//go:build !linux

package operatorfactorcustody

import (
	"context"
	"localrmm/internal/operatorfactorclient"
)

func PlanFor(Options) (*Plan, error) { return nil, ErrUnsupported }
func (*Plan) Stage(context.Context, operatorfactorclient.Account) (Result, error) {
	return Result{}, ErrUnsupported
}
