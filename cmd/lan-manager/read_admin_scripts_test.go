//go:build linux

package main

// These scripts are test-only adapters for the separately approved, disposable
// hosted-systemd gate. They do not verify release provenance or activate a pin.
// Ordinary tests only compile them and exercise their pure validation helpers.
const readAdminLauncher = `import os,sys

def require_gate(env, system, uid, euid):
    expected = {'TRACEBOLT_APPROVED_SYSTEMD_TEST':'1',
        'TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST':'1', 'GITHUB_ACTIONS':'true',
        'RUNNER_ENVIRONMENT':'github-hosted', 'RUNNER_OS':'Linux',
        'TRACEBOLT_READ_ADMIN_PROFILE':'tracebolt.linux-read-admin.v2',
        'TRACEBOLT_APPROVED_READ_ADMIN_PTRACE':'true'}
    if any(env.get(k) != v for k,v in expected.items()):
        raise ValueError('acceptance-gate-rejected')
    transport, scenario, source = (env.get(k) for k in
        ('TRACEBOLT_READ_ADMIN_TRANSPORT','TRACEBOLT_READ_ADMIN_SCENARIO','GITHUB_SHA'))
    if (system != 'linux' or type(uid) is not int or type(euid) is not int or uid != 0 or euid != 0 or
        transport not in ('tls','http-test') or
        scenario not in ('complete','cancel-enrollment','retained-journal') or
        type(source) is not str or len(source) != 40 or
        any(c not in '0123456789abcdef' for c in source) or
        env.get('TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE') != source):
        raise ValueError('acceptance-gate-rejected')
    return transport, scenario, source


def failure_result(stage):
    return dict(schemaVersion='tracebolt.read-admin-result.v2',
        readProfile='tracebolt.linux-read-admin.v2', configurationComplete=False,
        canceled=False, installation='not_attempted',
        phases={'inventory':'not_attempted','journal':'not_attempted','socket':'not_attempted'},
        collectionPerformed=False, nativeAcceptance='not-established', failureStage=stage)


def socket_native_operation(operation, scenario, workflow, inventory, s, amendment, socket_setup, templates, release):
    # Native-only. Callers passed the exact reviewed fresh-v2 gate and selected
    # protected source archive. Inert tests never invoke this function.
    import base64, json, stat
    def require(ok):
        if not ok:
            raise ValueError('acceptance-launcher-rejected')
    e = socket_setup.real_effects(s)
    out = dict(schemaVersion='tracebolt.read-admin-socket-native.v1', operation=operation,
        grantEpoch='', policyDigest='', agentPID=0, helperPID=0, agentUID=0, agentGID=0,
        helperUID=0, helperGID=0, revoked=False,
        cleanupConfirmed=False, floorPreserved=False, pendingChecked=False)
    # No marker alone authorizes cleanup. A failed pre-parent installation can
    # only report that helper authority is absent, never guess at its ownership.
    if operation == 'cleanup' and e.absent(workflow.RECEIPT):
        require(all(e.absent(p) for p in (s.CONFIG_DIR, socket_setup.BINARY,
            socket_setup.UNIT_DIR + '/' + socket_setup.SERVICE,
            socket_setup.UNIT_DIR + '/' + socket_setup.SOCKET, socket_setup.RUNTIME)))
        out['cleanupConfirmed'] = True
        return out
    facts = inventory.inspect(s, inventory.real_effects(s), templates, inventory.selected_scopes(True))
    raw = e.read(workflow.RECEIPT, 16384, 0o600)
    bound = inventory.strict_json(raw, 16384)
    require(type(bound) is dict and bound.get('schemaVersion') == 'tracebolt.read-admin-intent.v2' and
        bound.get('readProfile') == workflow.PROFILE and workflow.canonical(bound) == raw and
        bound.get('installation') == facts['manifest'] and bound.get('ownerHash') == facts['ownerHash'] and
        bound.get('configHash') == facts['configHash'] and bound.get('deviceId') == facts['deviceId'] and
        bound.get('managerOrigin') == facts['origin'] and bound.get('agentUid') == facts['uid'] and bound.get('agentGid') == facts['gid'] and
        facts['manifest']['sourceHash'] == release['assets']['tracebolt-' + release['version'] + '-source.tar']['sha256'])
    parent = workflow.digest(raw)
    if operation == 'cleanup':
        # Immutable production ownership proof precedes every helper stop. A
        # partial unproved helper fails cleanup; retain it and discard the VM.
        if not e.absent(socket_setup.COMPLETE):
            receipt = socket_setup.ownership_proof(s, e, templates, facts, parent)
            socket_setup.loaded(e, socket_setup.SERVICE, receipt['helperUid'], receipt['helperGid'], [socket_setup.BINARY], allow_failed=True)
            socket_setup.loaded(e, socket_setup.SOCKET, 0, facts['gid'], [])
            socket_setup.revoke_safety_shutdown(e, ValueError('native-cleanup'), disable_admission=True)
        else:
            require(all(e.absent(p) for p in (socket_setup.BINARY, socket_setup.POLICY, socket_setup.DEPLOYMENT,
                socket_setup.UNIT_DIR + '/' + socket_setup.SERVICE, socket_setup.UNIT_DIR + '/' + socket_setup.SOCKET, socket_setup.RUNTIME)))
            # Stopping the sender is allowed only after actual installer proof.
            require(socket_setup.digest(socket_setup.exact_file(e, socket_setup.AGENT_BINARY, 0o555, 0, limit=128 << 20)) == facts['manifest']['agentHash'])
            socket_setup.loaded(e, socket_setup.AGENT, facts['uid'], facts['gid'], socket_setup.agent_argv(s, templates, facts))
            socket_setup.stop(e, socket_setup.AGENT)
        if not e.absent(s.CONFIG_DIR):
            readback = amendment.real_effects(s, {})
            # Full immutable journal declarations, identities and exact rendered
            # units must validate. Existence of an attempt marker is insufficient.
            amendment.inspect(s, readback, templates)
            for name in (s.SOCKET, s.SERVICE):
                readback.command(['/usr/bin/systemctl', 'stop', name], failure_stage='native-owned-helper-stop')
                state = readback.status(name)
                require(s.owned_unit(state, name, 'inactive') and (name == s.SOCKET or state['MainPID'] == '0'))
            require(e.absent(s.SOCKET_PATH))
        out['cleanupConfirmed'] = True
        return out
    maintenance = workflow.real_maintenance(s, inventory, socket_setup, templates, release)
    require(maintenance.inspect() == bound)
    receipt = socket_setup.proof(s, e, templates, facts, parent)
    socket_setup.runtime_configuration(e, facts, receipt)
    out.update(grantEpoch=receipt['policy']['epoch'], policyDigest=receipt['policySHA256'],
        agentUID=facts['uid'], agentGID=facts['gid'], helperUID=receipt['helperUid'], helperGID=receipt['helperGid'])
    if operation == 'inspect-socket':
        agent = socket_setup.loaded(e, socket_setup.AGENT, facts['uid'], facts['gid'], socket_setup.agent_argv(s, templates, facts), active='active')
        helper = socket_setup.loaded(e, socket_setup.SERVICE, receipt['helperUid'], receipt['helperGid'], [socket_setup.BINARY], active='active')
        out.update(agentPID=int(agent['MainPID']), helperPID=int(helper['MainPID']))
        return out
    require(operation == 'revoke-socket' and scenario == 'complete')
    original_factory = socket_setup.real_effects
    evidence = {}
    def private_state():
        # Fixed new-install state; root inspection never exposes body bytes.
        path = '/var/lib/tracebolt-agent/enrollment/telemetry/system/system-state.json'
        parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for part in path.split('/')[1:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
                os.close(parent_fd); parent_fd = next_fd
                info = os.fstat(parent_fd)
                require(info.st_uid in (0, facts['uid']) and not stat.S_IMODE(info.st_mode) & 0o022)
            fd = os.open('system-state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == facts['uid'] and
                    info.st_gid == facts['gid'] and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 2 << 20)
                raw = stream.read((2 << 20) + 1)
                require(len(raw) == info.st_size)
            return s.strict_json(raw, ('version','binding','lastSequence','pending'))
        finally:
            os.close(parent_fd)
    def checked_effects(module):
        effect = original_factory(module)
        original_consent = effect.consent
        def consent(mode, selected, body=None):
            if mode != 'disable':
                return original_consent(mode, selected, body)
            before = private_state()
            result = original_consent(mode, selected, body)
            after = private_state()
            require(all(before[k] == after[k] for k in ('version','binding','lastSequence')))
            pending = before['pending']
            tagged = False
            if pending is not None:
                require(type(pending) is dict and set(pending) == {'sequence','digest','body'})
                frame_raw = base64.b64decode(pending['body'], validate=True)
                require(socket_setup.digest(frame_raw) == pending['digest'])
                frame = s.strict_json(frame_raw)
                tagged = frame.get('schemaVersion') == 'tracebolt.agent-system-inventory.v4' and type(frame.get('socketOwnerProvenance')) is dict
            require(after['pending'] is None if tagged else after['pending'] == pending)
            require(s.strict_json(result)['taggedPendingDiscarded'] is tagged)
            evidence.update(floorPreserved=True, pendingChecked=True)
            return result
        effect.consent = consent
        return effect
    socket_setup.real_effects = checked_effects
    try:
        maintenance = workflow.real_maintenance(s, inventory, socket_setup, templates, release)
        result = workflow.run_revoke(maintenance, lambda phrase: phrase == 'REVOKE SOCKET OWNERS', lambda _: None)
    finally:
        socket_setup.real_effects = original_factory
    require(result.get('revoked') is True and not result.get('stopUnconfirmed') and evidence == dict(floorPreserved=True, pendingChecked=True))
    socket_setup.proof(s, e, templates, facts, parent, disabled=True)
    socket_setup.runtime_configuration(e, facts, receipt, enabled=False)
    helper = e.status(socket_setup.SERVICE)
    require(socket_setup.owned(helper, socket_setup.SERVICE, 'inactive') and helper['MainPID'] == '0')
    e.drain(socket_setup.SERVICE)
    require(not e.absent(socket_setup.REVOKE_STARTED) and not e.absent(socket_setup.REVOKE_COMPLETE))
    out.update(revoked=True, **evidence)
    return out


def main(argv=None):
    # Nothing below this gate, including configuration/source/host reads, is
    # reachable without every explicit hosted-runner approval and source bound.
    try:
        transport, scenario, source_commit = require_gate(os.environ, sys.platform, os.getuid(), os.geteuid())
    except ValueError:
        import json
        print(json.dumps(failure_result('acceptance-gate-rejected')), flush=True)
        return 1
    import hashlib,json,re,signal,stat,tarfile,types
    from pathlib import Path

    def require(ok):
        if not ok:
            raise ValueError('acceptance-launcher-rejected')

    def unique(pairs):
        out = {}
        for key,value in pairs:
            require(key not in out)
            out[key] = value
        return out

    def no_constant(_):
        raise ValueError('acceptance-launcher-rejected')

    def directory_fd(path, private=False):
        require(type(path) is str and path.startswith('/') and '\x00' not in path and
            str(Path(path)) == path and all(p not in ('.','..') for p in path.split('/')[1:]))
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for part in path.split('/')[1:]:
                new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd); fd = new
                st = os.fstat(fd)
                require(st.st_uid == 0 and (not stat.S_IMODE(st.st_mode) & 0o022 or
                    stat.S_IMODE(st.st_mode) & stat.S_ISVTX))
            st = os.fstat(fd)
            require(not private or stat.S_IMODE(st.st_mode) == 0o700)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def protected_file(parent, name, mode, limit, expected=None):
        require(type(name) is str and name not in ('','.','..') and '/' not in name)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_gid == 0 and
                before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == mode and 0 < before.st_size <= limit)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                if expected is None:
                    data = stream.read(limit + 1)
                    require(len(data) == before.st_size)
                else:
                    require(before.st_size == expected['size'] and
                        hashlib.file_digest(stream, 'sha256').hexdigest() == expected['sha256'])
                    data = None
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            require(all(getattr(before,k) == getattr(after,k) == getattr(current,k) for k in fields))
            os.lseek(fd, 0, os.SEEK_SET)
            return fd, data, before
        except BaseException:
            os.close(fd)
            raise

    try:
        argv = sys.argv[1:] if argv is None else argv
        require(len(argv) == 1 and type(argv[0]) is str)
        config = Path(argv[0])
        parent = directory_fd(str(config.parent))
        try:
            fd, raw, _ = protected_file(parent, config.name, 0o600, 131072)
            os.close(fd)
        finally:
            os.close(parent)
        cfg = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=no_constant)
        require(type(cfg) is dict and set(cfg) == {'directory','manifest','arguments','scenario','operation'} and cfg['scenario'] == scenario)
        manifest, arguments = cfg['manifest'], cfg['arguments']
        operation = cfg['operation']
        require(operation in ('install','inspect-socket','revoke-socket','cleanup'))
        version = 'v0.0.0-read-admin-acceptance'
        require(type(manifest) is dict and set(manifest) == {'version','sourceCommit','assets'} and
            manifest['version'] == version and manifest['sourceCommit'] == source_commit)
        roles = ('agent-service','enroll-agent','lan-agent','socket-owner-reader')
        names = [f'tracebolt-{version}-linux-amd64-{role}' for role in roles]
        source_name = f'tracebolt-{version}-source.tar'
        assets = manifest['assets']
        require(type(assets) is dict and set(assets) == set(names + [source_name]))
        for name,item in assets.items():
            limit = 256 * 1024 * 1024 if name == source_name else 128 * 1024 * 1024
            require(type(item) is dict and set(item) == {'size','sha256'} and type(item['size']) is int and
                0 < item['size'] <= limit and type(item['sha256']) is str and
                re.fullmatch(r'[0-9a-f]{64}', item['sha256']) and item['sha256'] != '0' * 64)
        require(type(arguments) is list and 0 < len(arguments) <= 32 and
            all(type(v) is str and '\x00' not in v for v in arguments) and
            sum(len(v) for v in arguments) <= 100000)
        stage = directory_fd(cfg['directory'], private=True)
        try:
            for name in names:
                fd, _, _ = protected_file(stage, name, 0o500, 128 * 1024 * 1024, assets[name])
                os.close(fd)
            fd, _, before = protected_file(stage, source_name, 0o600, 256 * 1024 * 1024, assets[source_name])
            with os.fdopen(fd, 'rb') as stream:
                bootstrap = None
                seen = set()
                with tarfile.open(fileobj=stream, mode='r:') as archive:
                    for member in archive:
                        require(member.name not in seen and len(seen) < 10000)
                        seen.add(member.name)
                        if member.name != 'deploy/release/linux-bootstrap.py':
                            continue
                        require(member.isreg() and not member.issparse() and 0 < member.size <= 131072)
                        extracted = archive.extractfile(member)
                        require(extracted is not None)
                        with extracted:
                            bootstrap = extracted.read(131073)
                        require(len(bootstrap) == member.size)
                after = os.fstat(stream.fileno())
                current = os.stat(source_name, dir_fd=stage, follow_symlinks=False)
                fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
                require(all(getattr(before,k) == getattr(after,k) == getattr(current,k) for k in fields))
                require(bootstrap is not None)
        finally:
            os.close(stage)
        # This is selected local-source acceptance, never signed-release proof.
        # Do not set RELEASE_PIN, create an attestation, or call prepare_release.
        b = types.ModuleType('tracebolt_acceptance_bootstrap')
        b.__file__ = '/selected-source/deploy/release/linux-bootstrap.py'
        exec(compile(bootstrap, b.__file__, 'exec'), b.__dict__)
        args = b.parse_args(arguments)
        require(args.apply and args.read_admin and args.action == 'install' and not args.resume and
            args.insecure_http_test == (transport == 'http-test'))
        directory = Path(cfg['directory'])
        if operation == 'install':
            b.inspect_terminal()
        arch = b.inspect_host()
        require(arch == 'amd64')
        workflow, inventory, setup, amendment, journal_guide, socket_setup, templates = b.read_admin_sources(directory, manifest)
        require(workflow.PROFILE == 'tracebolt.linux-read-admin.v2' and workflow.PHASES == ('inventory','journal','socket'))
        if operation != 'install':
            result = socket_native_operation(operation, scenario, workflow, inventory, setup, amendment, socket_setup, templates, manifest)
            print(json.dumps(result), flush=True)
            return 0
        plan = workflow.make_plan(args, manifest, arch)
        helper = directory / f'tracebolt-{version}-linux-amd64-socket-owner-reader'
        artifact = dict(manifest['assets'][helper.name], path=str(helper))
        adapter = workflow.real_adapter(setup, inventory, amendment, journal_guide, socket_setup, templates, plan, artifact)
        if scenario == 'retained-journal':
            configure = adapter.configure
            def retain_before_journal(phase, bound, *, verify_only):
                if phase == 'journal' and not verify_only:
                    raise workflow.Rejected('acceptance-injected-before-journal')
                return configure(phase, bound, verify_only=verify_only)
            adapter.configure = retain_before_journal
        def interrupted(_signum, _frame):
            raise setup.Rejected('interrupted')
        previous = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
        try:
            result = workflow.run(plan, adapter,
                lambda: b.run_installer(b.installer_command(args, directory, manifest, arch)),
                inventory.confirm_terminal, inventory.emit_terminal, resume=args.resume_read_admin)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
        print(json.dumps(result, indent=2), flush=True)
        return 0 if result['configurationComplete'] is True or result['canceled'] is True else 1
    except (Exception, SystemExit):
        # Never expose untrusted exception text, paths, source or private state.
        print(json.dumps(failure_result('acceptance-launcher-rejected')), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
`

// The invitation exists only in the Go parent's private stdin pipe and the
// child's hidden terminal. Captured bytes are bounded, private, and never logged.
const readAdminPTY = `import json,os,pty,re,select,signal,sys,termios,time

MAX_CAPTURE = 131072
INSTALLER_STAGES = frozenset(('preflight','prepare_account_and_paths','stage_verified_artifacts',
    'enroll_as_dedicated_account','validate_existing_guided_state','publish_owned_binaries_and_unit',
    'start_owned_service','commit'))
FAILURES = frozenset(('install-or-device-approval-incomplete','acceptance-injected-before-journal',
    'uncertain-inventory-phase-retained','uncertain-journal-phase-retained','interrupted',
    'read-admin-phase-incomplete','acceptance-gate-rejected','acceptance-launcher-rejected',
    'acceptance-driver-rejected','acceptance-deadline-exceeded','acceptance-capture-exceeded',
    'read-admin-result-unavailable','read-admin-result-invalid','existing-installation-use-upgrade-or-recovery',
    'existing-journal-state-retained','owned-read-admin-receipt-required','read-admin-receipt-mismatch',
    'phase-receipt-mismatch','phase-start-receipt-missing','phase-receipt-changed',
    'installation-changed','installation-changed-after-inventory','installation-changed-after-journal',
    'installed-release-or-bootstrap-changed','approved-installation-changed',
    'readback-agent-not-stopped','readback-resume-identity-changed','readback-resume-unconfirmed',
    'broad-journal-not-ready'))


def require_gate(env, system, uid, euid):
    expected = {'TRACEBOLT_APPROVED_SYSTEMD_TEST':'1',
        'TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST':'1', 'GITHUB_ACTIONS':'true',
        'RUNNER_ENVIRONMENT':'github-hosted', 'RUNNER_OS':'Linux',
        'TRACEBOLT_READ_ADMIN_PROFILE':'tracebolt.linux-read-admin.v2',
        'TRACEBOLT_APPROVED_READ_ADMIN_PTRACE':'true'}
    if any(env.get(k) != v for k,v in expected.items()):
        raise ValueError('acceptance-gate-rejected')
    transport, scenario, source = (env.get(k) for k in
        ('TRACEBOLT_READ_ADMIN_TRANSPORT','TRACEBOLT_READ_ADMIN_SCENARIO','GITHUB_SHA'))
    if (system != 'linux' or type(uid) is not int or type(euid) is not int or uid != 0 or euid != 0 or
        transport not in ('tls','http-test') or
        scenario not in ('complete','cancel-enrollment','retained-journal') or
        type(source) is not str or len(source) != 40 or
        any(c not in '0123456789abcdef' for c in source) or
        env.get('TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE') != source):
        raise ValueError('acceptance-gate-rejected')
    return transport, scenario, source


def unique_object(pairs):
    out = {}
    for key,value in pairs:
        if key in out:
            raise ValueError('read-admin-result-invalid')
        out[key] = value
    return out


def no_constant(_):
    raise ValueError('read-admin-result-invalid')


def terminal_objects(raw):
    # Decode only complete line-start JSON objects, advancing over their whole
    # span so a nested result cannot masquerade as the coordinator root result.
    text = raw.decode('utf-8')
    decoder = json.JSONDecoder(object_pairs_hook=unique_object, parse_constant=no_constant)
    objects, offset = [], 0
    while offset < len(text):
        end = text.find('\n', offset)
        end = len(text) if end < 0 else end + 1
        start = offset
        while start < end and text[start] in ' \t\r':
            start += 1
        if start < end and text[start] == '{':
            try:
                value, consumed = decoder.raw_decode(text, start)
            except ValueError:
                if 'tracebolt.read-admin-result.v2' in text[start:]:
                    raise ValueError('read-admin-result-invalid') from None
            else:
                if type(value) is dict:
                    objects.append(value)
                next_line = text.find('\n', consumed)
                tail = text[consumed:] if next_line < 0 else text[consumed:next_line]
                if tail.strip():
                    raise ValueError('read-admin-result-invalid')
                offset = len(text) if next_line < 0 else next_line + 1
                continue
        offset = end
    return objects


def parse_result(raw):
    result = dict(readAdminComplete=False, readAdminCanceled=False,
        readAdminFailure='read-admin-result-unavailable', readAdminPhasesComplete=False)
    if type(raw) is not bytes or len(raw) > MAX_CAPTURE:
        result['readAdminFailure'] = 'read-admin-result-invalid'
        return result
    try:
        roots = [v for v in terminal_objects(raw) if v.get('schemaVersion') == 'tracebolt.read-admin-result.v2']
        if not roots:
            return result
        if len(roots) != 1:
            raise ValueError()
        value = roots[0]
        phases = value.get('phases')
        if (value.get('readProfile') != 'tracebolt.linux-read-admin.v2' or
            type(value.get('configurationComplete')) is not bool or type(value.get('canceled')) is not bool or
            value.get('collectionPerformed') is not False or value.get('nativeAcceptance') != 'not-established' or
            value.get('installation') not in ('not_attempted','uncertain','committed','existing_owned_installation') or
            type(phases) is not dict or set(phases) != {'inventory','journal','socket'} or
            any(type(v) is not str or v not in ('not_attempted','uncertain','verification_pending',
                'configured_confirmed','verified_existing') for v in phases.values())):
            raise ValueError()
        complete, canceled = value['configurationComplete'], value['canceled']
        phases_complete = all(v in ('configured_confirmed','verified_existing') for v in phases.values())
        failure = value.get('failureStage')
        if complete:
            if canceled or not phases_complete or 'failureStage' in value or value['installation'] not in ('committed','existing_owned_installation'):
                raise ValueError()
        elif canceled:
            if 'failureStage' in value or value['installation'] != 'not_attempted' or any(v != 'not_attempted' for v in phases.values()):
                raise ValueError()
        elif type(failure) is not str or not failure:
            raise ValueError()
        result.update(readAdminComplete=complete, readAdminCanceled=canceled,
            readAdminFailure='' if complete or canceled else failure if failure in FAILURES else 'read-admin-phase-incomplete',
            readAdminPhasesComplete=phases_complete)
    except (ValueError, UnicodeError, RecursionError):
        result['readAdminFailure'] = 'read-admin-result-invalid'
    return result


def exit_event(raw, status, secret, approvals, failure=''):
    event = dict(phase='exit', exitCode=status, secretEcho=secret.encode() in raw if secret else False,
        ready=b'Enrollment handoff is ready.' in raw,
        httpWarning=b'UNENCRYPTED HTTP TEST' in raw or b'WARNING: disposable HTTP test only.' in raw,
        installerStage='', installerRolledBack=False, installerIdentityRetained=False,
        scopeApprovals=approvals, **parse_result(raw))
    try:
        for value in terminal_objects(raw):
            stage = value.get('failureStage','preflight')
            if (value.get('committed') is False and type(value.get('identityRetained')) is bool and
                type(value.get('rolledBack')) is bool and type(value.get('plan')) is dict):
                event['installerRolledBack'] = value['rolledBack']
                event['installerIdentityRetained'] = value['identityRetained']
                if type(stage) is str and stage in INSTALLER_STAGES:
                    event['installerStage'] = stage
    except (ValueError, UnicodeError, RecursionError):
        pass
    if (event['readAdminComplete'] or event['readAdminCanceled']) and (status != 0 or type(approvals) is not int or approvals != 1):
        failure = 'read-admin-result-invalid'
    if failure:
        event.update(readAdminComplete=False, readAdminCanceled=False, readAdminPhasesComplete=False,
            readAdminFailure=failure if failure in FAILURES else 'acceptance-driver-rejected')
    return event


def parse_config(raw, transport):
    if type(raw) is not bytes or len(raw) > 131072 or transport not in ('tls','http-test'):
        raise ValueError()
    cfg = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object, parse_constant=no_constant)
    approval = 'INSTALL READ ADMIN' + (' OVER HTTP' if transport == 'http-test' else '')
    if (type(cfg) is not dict or set(cfg) != {'args','secret','approval','cancelApproval'} or
        type(cfg['args']) is not list or not 1 <= len(cfg['args']) <= 16 or
        any(type(v) is not str or '\x00' in v for v in cfg['args']) or
        not os.path.isabs(cfg['args'][0]) or sum(map(len,cfg['args'])) > 100000 or
        type(cfg['secret']) is not str or (cfg['secret'] != '' and re.fullmatch(r'[A-Za-z0-9_-]{43}',cfg['secret']) is None) or
        cfg['approval'] != approval or type(cfg['cancelApproval']) is not bool):
        raise ValueError()
    return cfg, approval


def main():
    pid, fd, status = None, None, None
    buf, secret, approvals, failure = b'', '', 0, ''
    previous = {}
    reported = False
    try:
        transport, _, _ = require_gate(os.environ, sys.platform, os.getuid(), os.geteuid())
        raw = sys.stdin.buffer.read(131073)
        cfg, approval = parse_config(raw, transport)
        secret = cfg['secret']
        prompt = ('Type ' + approval + ' to confirm, or press Enter to cancel: ').encode('ascii')
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.execv(cfg['args'][0], cfg['args'])
            except BaseException:
                os._exit(126)
        def forward(signum, _frame):
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass
        previous = {s:signal.signal(s,forward) for s in (signal.SIGINT,signal.SIGTERM)}
        sent = False
        deadline = time.monotonic() + 300
        stopping = False
        eof = False
        while True:
            if not stopping and time.monotonic() >= deadline:
                failure = 'acceptance-deadline-exceeded'
            if failure and not stopping:
                forward(signal.SIGTERM, None)
                stopping = True
            ready, _, _ = select.select([] if eof else [fd], [], [], 0.05)
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b''
                if not chunk:
                    eof = True
                elif len(buf) + len(chunk) > MAX_CAPTURE:
                    buf += chunk[:MAX_CAPTURE-len(buf)]
                    failure = 'acceptance-capture-exceeded'
                else:
                    buf += chunk
            if not stopping:
                count = buf.count(prompt)
                if count > 1:
                    failure = 'acceptance-driver-rejected'
                elif count == 1 and approvals == 0:
                    approvals = 1
                    os.write(fd, b'\n' if cfg['cancelApproval'] else approval.encode('ascii') + b'\n')
                invitations = buf.count(b'invitation (hidden):')
                if invitations > 1:
                    failure = 'acceptance-driver-rejected'
                elif invitations == 1 and not sent:
                    echo = bool(termios.tcgetattr(fd)[3] & termios.ECHO)
                    fingerprints = re.findall(rb'Local device SPKI SHA-256: ([0-9a-f]{64})(?![0-9a-f])',buf)
                    comparisons = re.findall(rb'Local 128-bit comparison: ([0-9a-f]{32})(?![0-9a-f])',buf)
                    valid = bool(secret) and approvals == 1 and not cfg['cancelApproval'] and len(fingerprints) == len(comparisons) == 1
                    print(json.dumps(dict(phase='prompt', echoDisabled=not echo, scopeApprovals=approvals,
                        fingerprint=fingerprints[0].decode() if len(fingerprints) == 1 else '',
                        comparison=comparisons[0].decode() if len(comparisons) == 1 else '')), flush=True)
                    if echo or not valid:
                        failure = 'acceptance-driver-rejected'
                    else:
                        os.write(fd, secret.encode('ascii') + b'\n')
                        sent = True
            if status is None:
                done, st = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = os.waitstatus_to_exitcode(st)
            # Drain the final bounded result before reporting the child status.
            if status is not None and (eof or not ready):
                break
        print(json.dumps(exit_event(buf,status,secret,approvals,failure)), flush=True)
        reported = True
        return 0 if not failure else 1
    except (Exception, KeyboardInterrupt):
        failure = 'acceptance-driver-rejected'
        return 1
    finally:
        if pid is not None and pid > 0 and status is None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Ordinary cancellation never force-kills a live installer or resets
            # its state. Reaping may outlast the 300-second interaction budget.
            try:
                _, st = os.waitpid(pid, 0)
                status = os.waitstatus_to_exitcode(st)
            except ChildProcessError:
                status = 1
        if not reported:
            print(json.dumps(exit_event(buf,status if status is not None else 1,secret,approvals,failure)), flush=True)
        for signum,handler in previous.items():
            signal.signal(signum,handler)
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    raise SystemExit(main())
`
