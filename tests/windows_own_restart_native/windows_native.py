"""Windows path/target inspection only until explicit native controller launch.
ACL and target routines copied from the reviewed inert parity helpers. No legacy
lifecycle command, endpoint-binding or stopped-only state helper is imported.
"""
from __future__ import annotations
import ctypes
from ctypes import wintypes as W
from contextlib import contextmanager
import os
from pathlib import Path
import platform
from contract import Rejected, need, digest, read_regular, strict_json, canonical, write_new, trusted_path, private_directory, verify_artifact, validate_native_report
def libraries():
    need(os.name == "nt", "target_mismatch")
    return ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)

@contextmanager
def target_lock():
    _, kernel = libraries()
    kernel.CreateMutexW.argtypes = [W.LPVOID, W.BOOL, W.LPCWSTR]; kernel.CreateMutexW.restype = W.HANDLE
    kernel.ReleaseMutex.argtypes = [W.HANDLE]; kernel.CloseHandle.argtypes = [W.HANDLE]
    handle = kernel.CreateMutexW(None, True, r"Global\TraceboltOwnRestartNativeHarness-v1")
    existed = ctypes.get_last_error() == 183
    if not handle or existed:
        if handle: kernel.CloseHandle(handle)
        raise Rejected("phase_replay")
    try:
        yield
    finally:
        kernel.ReleaseMutex(handle); kernel.CloseHandle(handle)

def current_sid():
    adv, kernel = libraries(); token = W.HANDLE()
    kernel.GetCurrentProcess.restype = W.HANDLE
    adv.OpenProcessToken.argtypes = [W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)]
    adv.GetTokenInformation.argtypes = [W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)]
    need(adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)), "private_path_rejected")
    try:
        size = W.DWORD(); adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        need(0 < size.value <= 65536, "private_path_rejected")
        buf = ctypes.create_string_buffer(size.value)
        need(adv.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)), "private_path_rejected")
        return sid_string(ctypes.cast(buf, ctypes.POINTER(W.LPVOID))[0])
    finally:
        kernel.CloseHandle(token)

def sid_string(sid):
    adv, kernel = libraries(); text = W.LPWSTR()
    adv.ConvertSidToStringSidW.argtypes = [W.LPVOID, ctypes.POINTER(W.LPWSTR)]
    kernel.LocalFree.argtypes = [W.LPVOID]
    need(adv.ConvertSidToStringSidW(sid, ctypes.byref(text)), "private_path_rejected")
    try:
        return text.value
    finally:
        kernel.LocalFree(text)

def acl_grant_safe(sid, mask, trusted, private=False, ancestor=False):
    if sid in trusted:
        return True
    if private:
        return False
    # Ancestors must not permit replacing this protected child via DELETE_CHILD,
    # ownership/DACL modification or generic write/all. Child creation alone in
    # ProgramData does not permit replacing an existing protected directory.
    unsafe = 0x10000000 | 0x40000000 | 0x40000 | 0x80000 | 0x10000 | 0x40
    if not ancestor:
        unsafe |= 0x2 | 0x4 | 0x10 | 0x100
    return mask & unsafe == 0

def require_private_acl(path):
    require_safe_acl(path, private=True)
    for parent in Path(path).parents:
        require_safe_acl(parent, ancestor=True)

def require_safe_acl(path, private=False, ancestor=False, trusted_sids=()):
    adv, kernel = libraries(); sd = W.LPVOID(); owner = W.LPVOID(); dacl = W.LPVOID()
    adv.GetNamedSecurityInfoW.argtypes = [W.LPWSTR, ctypes.c_int, W.DWORD, ctypes.POINTER(W.LPVOID), W.LPVOID, ctypes.POINTER(W.LPVOID), W.LPVOID, ctypes.POINTER(W.LPVOID)]
    adv.GetAce.argtypes = [W.LPVOID, W.DWORD, ctypes.POINTER(W.LPVOID)]
    kernel.LocalFree.argtypes = [W.LPVOID]
    need(adv.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(sd)) == 0, "private_path_rejected")
    try:
        trusted = {current_sid(), "S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", *trusted_sids}
        need(owner and sid_string(owner) in trusted and dacl, "private_path_rejected")
        # ACL header: revision, reserved, ACL size, ACE count, reserved.
        count = ctypes.cast(dacl, ctypes.POINTER(ctypes.c_ushort))[2]
        need(1 <= count <= 64, "private_path_rejected")
        for i in range(count):
            ace = W.LPVOID(); need(adv.GetAce(dacl, i, ctypes.byref(ace)), "private_path_rejected")
            header = ctypes.string_at(ace, 4)
            need(header[0] in {0, 1}, "private_path_rejected")  # reject unfamiliar/object/callback ACEs
            if header[1] & 0x08 and not private:  # private parents also protect inherited child ACLs
                continue
            if header[0] == 0:
                mask = ctypes.cast(ace.value + 4, ctypes.POINTER(W.DWORD))[0]
                need(acl_grant_safe(sid_string(ace.value + 8), mask, trusted, private, ancestor), "private_path_rejected")
    finally:
        if sd:
            kernel.LocalFree(sd)

def windows_directory():
    _, kernel = libraries(); buf = ctypes.create_unicode_buffer(32768)
    kernel.GetWindowsDirectoryW.argtypes = [W.LPWSTR, W.UINT]
    n = kernel.GetWindowsDirectoryW(buf, len(buf)); need(0 < n < len(buf), "target_mismatch")
    return buf.value

def known_folder(guid):
    import uuid
    shell = ctypes.WinDLL("shell32", use_last_error=True); ole = ctypes.WinDLL("ole32")
    raw = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(guid).bytes_le); out = W.LPWSTR()
    shell.SHGetKnownFolderPath.argtypes = [W.LPVOID, W.DWORD, W.HANDLE, ctypes.POINTER(W.LPWSTR)]
    ole.CoTaskMemFree.argtypes = [W.LPVOID]
    need(shell.SHGetKnownFolderPath(ctypes.byref(raw), 0, None, ctypes.byref(out)) == 0, "target_mismatch")
    try:
        return Path(out.value)
    finally:
        ole.CoTaskMemFree(out)

def layout():
    return (known_folder("905e63b6-c1bf-494e-b29c-65b732d3d21a") / "Tracebolt",
            known_folder("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97") / "Tracebolt")

def verify_target(t):
    need(ctypes.sizeof(ctypes.c_void_p) == 8 and os.name == "nt" and platform.machine().lower() in {"amd64", "x86_64"}, "target_mismatch")
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        guid = winreg.QueryValueEx(key, "MachineGuid")[0]
    need(digest(guid.strip().lower().encode()) == t["machineIdSHA256"], "target_mismatch")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        product = winreg.QueryValueEx(key, "ProductName")[0]
        build = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
    need("Windows Server 2025" in product and build == t["osBuild"] and int(build) >= 26100, "target_mismatch")
    need(ctypes.windll.shell32.IsUserAnAdmin() != 0, "secure_handoff_required")
    # Visible interactive desktop is required; do not bypass UAC or a locked session.
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.OpenInputDesktop.argtypes = [W.DWORD, W.BOOL, W.DWORD]; user.OpenInputDesktop.restype = W.HANDLE
    user.CloseDesktop.argtypes = [W.HANDLE]
    desktop = user.OpenInputDesktop(0, False, 0x100)
    need(desktop, "secure_handoff_required"); user.CloseDesktop(desktop)


def controller_plan(p, plan_hash, baseline_hash):
    from datetime import datetime, timezone
    stamp = lambda n: datetime.fromtimestamp(n,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    s,h,a,t = p['selected'],p['sources']['harness'],p['sources']['application'],p['targets']['windows']
    return {'schema':'tracebolt.windows-own-restart-controller-plan.v1','runId':p['runId'],'planSHA256':plan_hash,'browserBaselineSHA256':baseline_hash,
      'approvalId':p['approvals']['ownRestartTwoInvocations'],'interactiveAuthority':True,'twoCLIInvocationsApproved':True,
      'notBefore':stamp(p['notBeforeUnix']),'expiresAt':stamp(p['expiresUnix']),'workspace':t['workspace'],'machineIdSHA256':t['machineIdSHA256'],'osBuild':t['osBuild'],
      'controllerSHA256':p['artifacts']['controller']['sha256'],'controllerSourceCommit':h['commit'],'controllerSourceTree':h['tree'],'controllerSourceInventorySHA256':h['inventorySHA256'],
      'applicationSourceCommit':a['commit'],'applicationSourceTree':a['tree'],'applicationSourceInventorySHA256':a['inventorySHA256'],
      'installedSHA256':p['artifacts']['service']['sha256'],'receiptSHA256':s['receiptSHA256'],'intentSHA256':s['intentSHA256'],
      'deviceId':s['deviceId'],'certificateSHA256':s['certificateSHA256'],'managerInstanceId':p['tls']['managerInstanceId'],
      'agentOrigin':p['tls']['agentOrigin'],'enrollmentOrigin':p['tls']['operatorOrigin'],'publicSHA256':s['publicSHA256']}

def private_pipe():
    """Create an anonymous, process-local private pipe with explicit DACL.
    No persistent permission, credential or system setting is changed.
    """
    import msvcrt
    adv,kernel=libraries();sd=W.LPVOID()
    class Attributes(ctypes.Structure):
        _fields_=[('length',W.DWORD),('descriptor',W.LPVOID),('inherit',W.BOOL)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[W.LPCWSTR,W.DWORD,ctypes.POINTER(W.LPVOID),ctypes.POINTER(W.DWORD)]
    kernel.CreatePipe.argtypes=[ctypes.POINTER(W.HANDLE),ctypes.POINTER(W.HANDLE),ctypes.POINTER(Attributes),W.DWORD]
    kernel.CreatePipe.restype=W.BOOL
    text='D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;'+current_sid()+')'
    need(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,ctypes.byref(sd),None),'private_path_rejected')
    read,write=W.HANDLE(),W.HANDLE()
    try:
        attrs=Attributes(ctypes.sizeof(Attributes),sd,False)
        need(kernel.CreatePipe(ctypes.byref(read),ctypes.byref(write),ctypes.byref(attrs),0),'private_path_rejected')
    finally:kernel.LocalFree(sd)
    r=w=None
    try:
        r=msvcrt.open_osfhandle(read.value,os.O_RDONLY|os.O_BINARY)
        w=msvcrt.open_osfhandle(write.value,os.O_WRONLY|os.O_BINARY)
        return r,w
    except BaseException:
        if r is not None:os.close(r)
        else:kernel.CloseHandle(read)
        if w is not None:os.close(w)
        else:kernel.CloseHandle(write)
        raise

def observe_controller(p,plan_hash,baseline_hash,budget,cancelled,notify):
    import subprocess
    import msvcrt
    from supervisor import drain
    budget.check(); need(not cancelled(), 'unknown_intervention_required')
    for name in ('controller','service'):
        raw = verify_artifact(p['artifacts'][name],128<<20)
        need(raw.startswith(b'MZ'), 'artifact_mismatch')
    expected = layout()[0] / 'tracebolt-windows-service.exe'
    # The controller independently derives and verifies the installed path. The
    # artifact binding must name its actual fixed installation executable too.
    need(Path(p['artifacts']['service']['path']) == expected, 'artifact_mismatch')
    report_r,report_w = private_pipe(); cancel_r,cancel_w = private_pipe()
    proc = None
    try:
        rh,ch = msvcrt.get_osfhandle(report_w),msvcrt.get_osfhandle(cancel_r)
        os.set_handle_inheritable(rh,True); os.set_handle_inheritable(ch,True)
        startup = subprocess.STARTUPINFO(); startup.lpAttributeList = {'handle_list':[rh,ch]}
        env = {'SystemRoot':windows_directory(),'TRACEBOLT_RESTART_PLAN':canonical(controller_plan(p,plan_hash,baseline_hash)).decode('ascii'),
               'TRACEBOLT_RESTART_REPORT_HANDLE':str(rh),'TRACEBOLT_RESTART_CANCEL_HANDLE':str(ch)}
        budget.check(); need(not cancelled(), 'unknown_intervention_required')
        proc = subprocess.Popen([p['artifacts']['controller']['path'],'-test.run=^TestOwnRestartNativeAcceptance$','-test.timeout=0'],
             stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,shell=False,close_fds=True,startupinfo=startup,
             creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        postlaunch_fault=False
        for name,fd in [('report',report_w),('cancel',cancel_r)]:
            try:
                os.close(fd)
                if name=='report':report_w=None
                else:cancel_r=None
            except BaseException:postlaunch_fault=True
        def cancel():
            try: os.write(cancel_w,b'X')
            except OSError: pass
        def inspect_live_report(raw):
            lines=raw.split(b'\n');need(len(lines)<=3 and len(lines[-1])<=32768,'unknown_intervention_required')
            completed=lines[:-1]
            need(len(completed)<=2,'unknown_intervention_required')
            for line in completed:
                row=validate_native_report(strict_json(line,32768),p,plan_hash,baseline_hash)
                need(row['status']!='unknown-intervention-required','unknown_intervention_required')
        outcome = drain(proc,{'stdout':proc.stdout.fileno(),'stderr':proc.stderr.fileno(),'report':report_r},budget,lambda:postlaunch_fault or cancelled(),cancel,notify,inspect_report=inspect_live_report)
        lines = bytes(outcome.report).splitlines()
        need(1 <= len(lines) <= 2, 'unknown_intervention_required')
        rows = [validate_native_report(strict_json(line,32768),p,plan_hash,baseline_hash) for line in lines]
        need(len(rows) == 1 or all(row['status'] == 'unknown-intervention-required' for row in rows), 'unknown_intervention_required')
        need(not outcome.unknown and outcome.returncode == 0 and len(rows) == 1 and rows[0]['status'] == 'passed-native-subset', 'unknown_intervention_required')
        return rows[0]
    finally:
        # No process termination here. drain does not return while it is live.
        for fd in (report_r,report_w,cancel_r,cancel_w):
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
        if proc is not None:
            proc.stdout.close(); proc.stderr.close()
