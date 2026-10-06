package agentinstall

import (
	"context"
	"errors"
	"reflect"
	"time"
)

var ErrOperation = errors.New("installation transaction failed; inspect its safe stage and retained-state result")

type Operation string

const (
	OpPrepare           Operation = "prepare_account_and_paths"
	OpStage             Operation = "stage_verified_artifacts"
	OpEnroll            Operation = "enroll_as_dedicated_account"
	OpStop              Operation = "stop_owned_service"
	OpValidate          Operation = "validate_existing_guided_state"
	OpResetRestartState Operation = "reset_owned_service_restart_state"
	OpPublish           Operation = "publish_owned_binaries_and_unit"
	OpStart             Operation = "start_owned_service"
	OpDisable           Operation = "disable_owned_service"
	OpRemove            Operation = "remove_owned_installation_files"
)

// Backend is a trusted local platform adapter. Inspect must be read-only and
// must not run a child as root to bypass private-state or terminal restrictions.
// Begin acquires the exclusive installer lock and starts a durable journal.
// A failed Begin must release its lock and preserve or reconcile every journal
// artifact it created; Execute cannot recover an unreturned transaction handle.
// No HTTP or bootstrap input supplies a Backend or preflight facts.
type Backend interface {
	Inspect(context.Context, Request) (HostFacts, error)
	Begin(context.Context, Request, Plan) (Transaction, error)
}

// Transaction records a durable intent BEFORE each operation and a completion
// record afterward. Its platform implementation must refuse foreign resources,
// bind changes to the current journal, and reconcile uncertain results before
// rollback. Root/account/private-state creation is never implicit in dry-run.
type Transaction interface {
	Inspect(context.Context, Request) (HostFacts, error)
	Before(context.Context, Operation) error
	Apply(context.Context, Operation, Request) error
	Done(context.Context, Operation) error
	Commit(context.Context) error
	// Rollback restores/removes only journal-owned changes from this attempt.
	// It must retain all identity/counter data and the dedicated account. It may
	// not adopt, chmod, delete or reset an unrelated resource to recover.
	// A Commit error may be uncertain: reconcile a durable commit marker before
	// undoing anything, and never roll back an already committed installation.
	Rollback(context.Context) error
	Close() error
}
type Result struct {
	Plan               Plan      `json:"plan"`
	Committed          bool      `json:"committed"`
	ServiceLeftStopped bool      `json:"serviceLeftStopped,omitempty"`
	RolledBack         bool      `json:"rolledBack"`
	IdentityRetained   bool      `json:"identityRetained"`
	FailureStage       Operation `json:"failureStage,omitempty"`
}

// preflightFailure carries only a fixed checkpoint; the original error identity
// remains available to local callers and is never copied into the public Result.
type preflightFailure struct {
	stage Operation
	cause error
}

func (e *preflightFailure) Error() string { return e.cause.Error() }
func (e *preflightFailure) Unwrap() error { return e.cause }
func checkpointFailureStage(err error, fallback Operation) Operation {
	var detail *preflightFailure
	if errors.As(err, &detail) && detail != nil {
		return inspectionFailureStage(detail.stage)
	}
	return inspectionFailureStage(fallback)
}

// inspectionFailureStage never exposes backend error text or dynamic host values.
func inspectionFailureStage(stage Operation) Operation {
	switch stage {
	case "preflight_inspect", "preflight_systemd", "preflight_terminal", "preflight_systemctl_tool", "preflight_useradd_tool", "preflight_nologin_tool", "preflight_opt_directory", "preflight_etc_directory", "preflight_state_directory", "preflight_unit_directory", "preflight_unit_status", "preflight_account", "preflight_installation_state", "preflight_ownership_state", "preflight_fresh_paths", "preflight_bootstrap", "preflight_complete_profile", "preflight_artifacts", "preflight_plan", "preflight_begin", "preflight_reinspect", "preflight_replan", "preflight_unit_command", "preflight_unit_members", "preflight_unit_pid", "preflight_unit_absence", "preflight_manifest_absence", "preflight_begin_request", "preflight_begin_control", "preflight_begin_lock", "preflight_begin_journal", "preflight_begin_entropy", "preflight_begin_ownership", "preflight_begin_unit", "preflight_begin_artifacts", "preflight_begin_bootstrap", "preflight_begin_save":
		return stage
	default:
		return "preflight_inspect"
	}
}

func nilHandle(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

// Execute is a bounded orchestration seam. It is not a permission grant: callers
// still need explicit apply authority, root/systemd preflight and the real trusted
// adapter. Tests use an in-memory adapter and never install accounts/services.
func Execute(ctx context.Context, r Request, backend Backend) (Result, error) {
	out := Result{IdentityRetained: true}
	if ctx == nil || nilHandle(backend) {
		return out, ErrPreflight
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	facts, e := backend.Inspect(ctx, r)
	if e != nil {
		out.FailureStage = checkpointFailureStage(e, facts.inspectionStage)
		return out, ErrPreflight
	}
	plan, e := BuildPlan(r, facts)
	if e != nil {
		out.FailureStage = "preflight_plan"
		return out, e
	}
	out.Plan = plan
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if !r.Apply {
		return out, nil
	}
	tx, e := backend.Begin(ctx, r, plan)
	if e != nil || nilHandle(tx) {
		out.FailureStage = checkpointFailureStage(e, "preflight_begin")
		return out, ErrState
	}
	defer tx.Close()
	rollback := func() (Result, error) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		out.RolledBack = tx.Rollback(cleanup) == nil
		return out, ErrOperation
	}
	facts, e = tx.Inspect(ctx, r)
	if e != nil {
		out.FailureStage = checkpointFailureStage(e, facts.inspectionStage)
		if out.FailureStage == "preflight_inspect" {
			out.FailureStage = "preflight_reinspect"
		}
		return rollback()
	}
	fresh, e := BuildPlan(r, facts)
	if e != nil || fresh.DryRun {
		out.FailureStage = "preflight_replan"
		return rollback()
	}
	operations := []Operation{}
	switch r.Action {
	case Install:
		operations = []Operation{OpPrepare, OpStage, OpEnroll, OpValidate, OpPublish, OpStart}
	case Upgrade:
		operations = []Operation{OpStage, OpStop, OpValidate, OpPublish, OpStart}
		if r.UpgradeCoordinatorFD != 0 {
			operations = []Operation{OpStage, OpStop, OpValidate, OpPublish}
		}
	case Restart:
		operations = []Operation{OpStop, OpValidate, OpResetRestartState, OpStart}
	case Uninstall:
		operations = []Operation{OpStop, OpDisable, OpRemove}
	default:
		return rollback()
	}
	for _, op := range operations {
		out.FailureStage = op
		if ctx.Err() != nil {
			return rollback()
		}
		if tx.Before(ctx, op) != nil {
			return rollback()
		}
		if ctx.Err() != nil {
			return rollback()
		}
		if tx.Apply(ctx, op, r) != nil {
			return rollback()
		}
		if tx.Done(ctx, op) != nil {
			return rollback()
		}
	}
	out.FailureStage = "commit"
	if ctx.Err() != nil || tx.Commit(ctx) != nil {
		return rollback()
	}
	out.Committed = true
	out.ServiceLeftStopped = r.UpgradeCoordinatorFD != 0
	out.FailureStage = ""
	return out, nil
}
