# Installer restrictive-umask correction

The first real hosted service attempt on source `070159d3f2ef4cec92f74015b5f582980a4cdf63`
failed at the sanitized `install_enroll` stage in
[run37159157926](https://github.com/storminator89/Tracebolt/actions/runs/37159157926).
No raw terminal, journal, telemetry or private-state artifact was uploaded. That
stage alone does not prove the exact failed syscall or how far account setup ran.

A separate inert regression establishes a concrete defect: with umask077,
`Mkdir(0755)` creates mode0700. The install, public-bootstrap and staging
directories could consequently deny traversal to the correctly unprivileged
enrollment child. The subprocess fixture failed before this correction and
passes afterward; it does not create a real account or service.

The fix creates those **new** directories privately and applies mode0755 using
an owner/inode-checked no-follow directory descriptor, then fsyncs it and its
parent. An existing directory or symlink is rejected without permission changes.
Private identity/control directories remain0700. No arbitrary path, inherited
credential, root enrollment fallback or relaxed unit guard is added.

The private PTY helper now returns only a fixed allowlisted installer stage from
the installer's own structured result. The sanitized result can distinguish
installer preflight, preparation, staging, enrollment, local validation,
publication, start and commit failures without copying raw output. The manual
workflow validator must allow the corresponding fixed `installer_*` values.

Local evidence: inert umask077 failure reproduced; corrected race regressions
pass; existing installer security/CLI tests pass; actual three-binary foreground
regression remains a separate check. No repeat privileged execution was performed
locally. A reviewed repeat of the same approved fresh hosted test is needed to
establish whether this resolves the real failure.
