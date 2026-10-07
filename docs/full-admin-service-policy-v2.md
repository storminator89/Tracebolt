# Full-admin ordinary system services: source candidate

This is a new root-local grant, `tracebolt.action-helper-policy.v2`, with the
explicit scope `control-existing-root-trusted-system-services`. It must be
created by a fresh, expressly approved full-admin setup. Existing v1 policies,
read-admin identities and static target-review packets are not promoted. The
policy retains the manager/key/incarnation, nonroot agent UID/GID, transport,
maximum original permit lifetime and clock-skew bindings. `targets` is an empty
array; `scope` names the new authority. No per-service target JSON is required.
The root policy digest is stable across service configuration changes; each
service's current inspection digest is separately bound to its preview.

V2 trusts the administrator's existing systemd authority. Ordinary root-run
services, dynamically linked executables and root-controlled scripts are
supported. It does not analyze arbitrary scripts or sandbox their behavior.
The control-plane exclusions do not establish that arbitrary root-run code
cannot indirectly affect Tracebolt. SSH, networking, VPN, firewall and Docker
names are not categorically blocked. Concrete unsupported configuration or
relationship semantics can still exclude such a service, such as socket
activation, aliases, templates or an oversized propagation graph.

## Exact inspection and action contract

The trusted Linux adapter uses fixed system-mode `systemctl list-unit-files`
and `show` invocations. It accepts only an exact canonical, loaded `.service`
ID with a sole matching `Names` entry, persistent or supported root-controlled
runtime configuration, no pending daemon reload, and no generated/transient
unit. User units, aliases and templates are rejected. It reads the effective
fixed property projection and protected fragment/drop-in bytes; all path
components and symlinks must remain root-controlled and nonwritable by other
identities. Both the requested and resolved direct Exec paths are checked.
Executable identity is bound without requiring static ELF or collecting the
contents of shared libraries or arbitrary script inputs.

The relevant transaction closure is bounded to 64 units. Start requirements,
conflicts, and inverse Requires/Requisite/BindsTo/PartOf plus explicit stop
propagation are inspected. An already-active prerequisite is bound without
recursively treating all its inverse dependents as restart targets. Root-owned
target/mount/slice prerequisites are supported when their semantics fit; unit
kinds and relationship spellings outside this model fail closed. Unsupported
automatic OnFailure/OnSuccess/trigger/uphold actions, alternate execution roots,
special stop behavior and transitional states are rejected. Relationship order
is canonicalized, and transient Exec process status is excluded from the stable
configuration digest. The authoritative relationship semantics are described in
[systemd's unit documentation](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml).

The protected IDs are `tracebolt.service`, `localrmm.service`, and IDs beginning
`tracebolt-` or `localrmm-`. Direct resolved Exec paths under
`/opt/tracebolt-agent` or beginning `/usr/libexec/tracebolt-`, and relevant
propagation reaching the protected control plane, are rejected. Symlink chains
are checked through protected ancestors; an alias to a protected execution path
cannot hide it.

The canonical digest commits to the requested unit, relevant effective
configuration and graph roles, fragment/drop-in content, executable/path
identities, and the fixed systemctl identity. A second inspection pass catches
changes during collection. The helper recomputes before durable admission,
after consume-once admission, and after the durable dispatch marker. Original
expiry, current root authority and incarnation are rechecked. There is no
atomic lock against another root administrator changing systemd after the final
check; this is an existing-host-authority trust model.

The sole action remains:

```
/usr/bin/systemctl --system --no-ask-password --no-pager --job-mode=fail try-restart -- UNIT
```

No arbitrary action, executable, environment, arguments or backend enters IPC.
The shared service/package fence is mandatory for v2. A duplicate reads the
original status; an uncertain dispatch retains the fence and requires
intervention. No timeout or lost reply authorizes resubmission.

## Versioned integration

- `actionhelper.PolicyVersionV2`, `FullAdminServiceScope` and empty `Targets`
  produce the root policy. The existing canonical setup validator and create-only
  ledger initializer accept this exact new shape.
- `lanclient.ActionClientPolicyVersionV2` also requires the explicit `Scope`,
  matching root policy digest and existing activated sender binding.
- `actionhelper.CapabilitiesVersionV2` includes scope, the exact review notice,
  each service's current digest and bounded affected-service list, and
  `ExcludedServices` with concrete reason codes. At most 256 listed units and
  128 KiB of canonical capability JSON are supported; over-capacity fails closed.
- Helper requests/responses have separate v2 versions for inspection. The old
  8 KiB v1 response bound and v1 capability shape remain unchanged. The client
  invokes `FullAdminCapabilities` only under its v2 local grant.
- `/v4/service-actions/capabilities` uses `EncodeCapabilitiesV2`,
  `DecodeCapabilitiesV2`, and its own 128 KiB body bound. The old endpoint and
  codec retain the old v1 and 16 KiB limits. Peek/claim/result routing is unchanged.
- Action plan, execution permit/signing domain, preview and approval each have
  explicit v2 versions. A v1 verifier cannot admit a v2 permit. The manager
  preview binds its named unit, inspection digest, affected-service list, scope,
  and full risk notice into the operator's exact approval digest.
- `lanclient.CheckFullAdminActionSetupReadiness` uses the versioned helper
  inspection; legacy setup readiness remains v1.

The exact notice is:

> This action trusts the existing root-controlled systemd service configuration
> and its host authority. It may interrupt dependent services, management
> connectivity, or your current session. Existing root-run programs may indirectly
> affect Tracebolt; this grant is not a sandbox.

The manager's full-admin authority provider must independently pin the reported
root policy digest to the approved domain claim. Ingress must route the new
capability endpoint and use its v2 decoder. The operator UI must render the exact
v2 notice and affected-service list in its per-action review. None of those
bindings may be inferred from a legacy service-action grant or manager upgrade.

## Evidence and remaining gates

Automated checks here use inert injected commands, net.Pipe, and ordinary-user
temporary fixture trees. They cover normal root/dynamic service acceptance,
protected resolved paths and graph propagation, unsupported/stale authority,
configuration drift, version/budget isolation, exact named approval and original
expiry, before-consume/final rechecks, consume-once recovery, and uncertain
shared-fence retention. Existing v1 signing conformance vectors remain exact.

This is source-only evidence. No root operation, real systemctl/helper/action,
credential/ACL/account/package operation, native runtime inspection, installation,
network workflow or publication was performed. Final integrated API/installer/UI
checks and a separately authorized disposable native systemd gate remain
required. That gate must exercise representative distribution services and their
actual properties, aliases, dynamic executables, default dependencies,
fragment/drop-in ownership, drift and lost-result behavior before release.
