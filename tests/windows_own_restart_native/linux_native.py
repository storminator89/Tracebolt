"""Observe an already-running pinned Linux manager. Never starts/stops a manager.
/proc inspection binds retained PID/start ticks/UID/executable/config arguments,
and both exact private listeners to that process, throughout browser observation.
"""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import ipaddress
import os
from pathlib import Path
import platform
import re
import select
import socket
import ssl
import subprocess
import time
from urllib.parse import urlsplit
from contract import *

@contextmanager
def target_lock():
    lock = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    try:
        try: lock.bind('\0tracebolt-own-restart-native-harness-v1')
        except OSError: raise Rejected('phase_replay') from None
        yield
    finally: lock.close()

def verify_target(t):
    need(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0, 'target_mismatch')
    machine = read_regular('/etc/machine-id',256).decode('ascii').strip().lower()
    need(digest(machine.encode()) == t['machineIdSHA256'] and platform.release() == t['osBuild'], 'target_mismatch')

def proc_read(path,maximum):
    # proc files report size zero. Fixed /proc/<selected PID> paths only, bounded
    # reads, no exported command line or environment, no arbitrary file adapter.
    with open(path,'rb') as f: raw = f.read(maximum+1)
    need(0 < len(raw) <= maximum, 'manager_changed')
    return raw

def process_stat(raw):
    text = raw.decode('ascii'); end=text.rfind(')')
    need(end > 1 and text[end+1:end+2] == ' ', 'manager_changed')
    rest=text[end+2:].split(); need(len(rest)>=20 and rest[0] not in {'Z','X'}, 'manager_changed')
    return rest[19]

def same_namespaces(pid,link=os.readlink):
    for name in ('net','mnt','user'):
        need(link('/proc/'+str(pid)+'/ns/'+name)==link('/proc/self/ns/'+name),'manager_changed')

def verify_manager_process(p,config):
    m,t = p['managerProcess'],p['targets']['linux']; root=Path('/proc')/str(m['pid'])
    first=process_stat(proc_read(root/'stat',16384)); need(first==m['startTicks'], 'manager_changed')
    status=proc_read(root/'status',65536).decode('ascii')
    match=re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$',status,re.M)
    need(match and all(int(x)==m['uid']==os.geteuid() for x in match.groups()), 'manager_changed')
    expected = p['artifacts']['manager']['path']
    need(os.readlink(root/'exe') == expected, 'manager_changed')
    # Open the pinned /proc executable, not just a replaceable same-name path.
    with open(root/'exe','rb') as f:
        h=hashlib.sha256(); total=0
        while True:
            chunk=f.read(1<<20)
            if not chunk: break
            total+=len(chunk); need(total<=128<<20,'manager_changed'); h.update(chunk)
    need(h.hexdigest()==m['executableSHA256'],'manager_changed')
    args=proc_read(root/'cmdline',8192).split(b'\0')
    expected_args=[expected,'--lan-config',t['lanConfig'],'--enrollment-config',t['enrollmentConfig']]
    need(args == [x.encode() for x in expected_args]+[b''], 'manager_changed')
    for key in ('lanConfig','enrollmentConfig'):
        need(digest(read_regular(trusted_path(t[key]),32768))==m[key+'SHA256'], 'manager_changed')
    # No network namespace/relay substitution: process and observer share netns.
    same_namespaces(m['pid'])
    inodes=set()
    for fd in (root/'fd').iterdir():
        try: target=os.readlink(fd)
        except FileNotFoundError: continue
        match=re.fullmatch(r'socket:\[(\d+)\]',target)
        if match: inodes.add(match[1])
    listeners={}
    for line in proc_read(root/'net/tcp',1<<20).decode('ascii').splitlines()[1:]:
        fields=line.split()
        if len(fields)<10 or fields[3]!='0A': continue
        address,port=fields[1].split(':')
        ip=socket.inet_ntoa(bytes.fromhex(address)[::-1]); listeners.setdefault((ip,int(port,16)),set()).add(fields[9])
    for key in ('operatorListen','agentListen'):
        host,port=config[key].rsplit(':',1)
        need(listeners.get((host,int(port))) and listeners[(host,int(port))] <= inodes,'manager_changed')
    need(process_stat(proc_read(root/'stat',16384))==first,'manager_changed')

def protected(path,secret=False):
    p=trusted_path(path,secret=secret); s=p.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=32768,'private_path_rejected')
    return None if secret else read_regular(p,32768)

def verify_config(p,budget):
    t=p['targets']['linux']; c=strict_json(protected(t['lanConfig']),32768)
    exact(c,('schemaVersion','profile','windowsInventoryEnabled','operatorListen','agentListen','operatorOrigin','agentOrigin','tlsCertificateFile','tlsPrivateKeyFile','agentClientCAFile','operatorAuthFile','stateDirectory','webDirectory'))
    need(c['schemaVersion']=='tracebolt.lan-config.v1' and c['profile']=='tls' and c['windowsInventoryEnabled'] is True)
    need(c['operatorOrigin']==p['tls']['operatorOrigin'] and c['agentOrigin']==p['tls']['agentOrigin'] and c['webDirectory']==t['webRoot'])
    for listener,origin_key in [('operatorListen','operatorOrigin'),('agentListen','agentOrigin')]:
        raw=c[listener]; need(type(raw) is str and raw.count(':')==1)
        host,port=raw.rsplit(':',1); ip=ipaddress.IPv4Address(host)
        need(ip.is_private and not ip.is_loopback and not ip.is_unspecified and not ip.is_link_local)
        u=urlsplit(c[origin_key]); need(int(port)==u.port)
        # DNS preflight is read-only and cannot launch work if it returns late.
        import queue, threading
        q=queue.Queue(maxsize=1)
        def resolve():
            try: q.put({r[4][0] for r in socket.getaddrinfo(u.hostname,u.port,socket.AF_INET,socket.SOCK_STREAM)})
            except Exception: q.put(None)
        thread=threading.Thread(target=resolve,daemon=True);thread.start()
        try: ips=q.get(timeout=5)
        except queue.Empty: raise Rejected('native_observation_unavailable') from None
        budget.check();need(ips=={host})
    need(digest(protected(c['tlsCertificateFile']))==p['tls']['serverCertificateSHA256'],'artifact_mismatch')
    for key in ('tlsPrivateKeyFile','operatorAuthFile'): protected(c[key],True)
    protected(c['agentClientCAFile'])
    state=private_directory(c['stateDirectory']);need(state!=Path(t['workspace']))
    # Reject fresh/empty state. Never initialize, reset, open a writable store or
    # export private state. Existing contents are not acceptance by themselves.
    need(any(state.iterdir()),'native_observation_unavailable')
    e=strict_json(protected(t['enrollmentConfig']),32768)
    need(set(e) <= {'schemaVersion','profile','collectionProfile','instanceId','issuerCertificateFile','issuerPrivateKeyFile','issuerRootFile','expectedIssuerFingerprint','bootstrapServerCAFile'})
    need(e.get('schemaVersion')=='tracebolt.enrollment-config.v2' and e.get('profile')=='tls')
    need(e.get('instanceId')==p['tls']['managerInstanceId'] and e.get('expectedIssuerFingerprint')==p['tls']['issuerFingerprint'])
    protected(e['issuerPrivateKeyFile'],True); protected(e['issuerCertificateFile'])
    need(digest(protected(e['issuerRootFile']))==p['tls']['bootstrapIssuerRootSHA256'] and digest(protected(e['bootstrapServerCAFile']))==p['tls']['bootstrapServerCASHA256'])
    return c

def verify_tls(p,config,budget):
    u=urlsplit(p['tls']['operatorOrigin']);context=ssl.create_default_context()
    pem=protected(config['tlsCertificateFile']).decode('ascii')
    leaf=re.search(r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----',pem)
    need(leaf is not None)
    expected=digest(ssl.PEM_cert_to_DER_cert(leaf[0]))
    with socket.create_connection((u.hostname,u.port),timeout=5) as sock:
        with context.wrap_socket(sock,server_hostname=u.hostname) as tls: need(digest(tls.getpeercert(binary_form=True))==expected,'artifact_mismatch')
    budget.check()

def prepare(p,budget):
    for name in ('manager','node','chromium'):
        raw=verify_artifact(p['artifacts'][name],128<<20) if name=='manager' else verify_executable_header(p['artifacts'][name])
        need(raw[:6]==b'\x7fELF\x02\x01' and raw[18:20]==b'\x3e\x00','artifact_mismatch')
        if name=='manager':
            need(b'path\tlocalrmm/cmd/lan-manager\n' in raw and ('build\tvcs.revision='+p['sources']['manager']['commit']+'\n').encode() in raw and b'build\tvcs.modified=false\n' in raw,'artifact_mismatch')
    t=p['targets']['linux']
    verify_inventory(t['webRoot'],p['artifacts']['webInventory']['path'],p['artifacts']['webInventory']['sha256'],trusted=True)
    verify_inventory(t['browserRoot'],p['artifacts']['browserInventory']['path'],p['artifacts']['browserInventory']['sha256'],dependencies=True,trusted=True)
    config=verify_config(p,budget);verify_manager_process(p,config);verify_tls(p,config,budget)
    return config

def observe_browser(p,plan_hash,budget,cancelled,notify):
    config=prepare(p,budget); t=p['targets']['linux']; w=Path(t['workspace'])
    baseline=w/(p['runId']+'-baseline.json');result=w/(p['runId']+'-browser.json')
    for path in (baseline,result,Path(p['handoff']['linuxCompletion'])):need(not path.exists(),'phase_replay')
    spec={'schema':SCHEMA+'.browser-spec','plan':p,'planSHA256':plan_hash,'bindingSHA256':binding_hash(p),'baselinePath':str(baseline),'resultPath':str(result)}
    env={key:os.environ[key] for key in ('DISPLAY','WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS','LANG') if key in os.environ}
    env.update({'HOME':t['workspace'],'TMPDIR':t['workspace']})
    budget.check();need(not cancelled(),'unknown_intervention_required')
    browser=subprocess.Popen([p['artifacts']['node']['path'],str(Path(t['sourcePaths']['harness']['root'])/'tests/windows_own_restart_native/browser.mjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,env=env)
    unknown=False;reason=None;pending=bytearray();counts={'stdout':0,'stderr':0};sent_digest=False;prompted=False;baseline_hash='';saw_login=False;end=None
    try:
        browser.stdin.write(canonical(spec));browser.stdin.flush()
        for stream in (browser.stdout,browser.stderr):os.set_blocking(stream.fileno(),False)
        while browser.poll() is None or end is None or time.monotonic()-end<0.1:
            try:
                budget.check();need(not cancelled(),'unknown_intervention_required');verify_manager_process(p,config)
            except Exception as e:
                if not unknown:
                    unknown=True;reason=e.reason if isinstance(e,Rejected) else 'manager_changed'
                    # Closing stdin asks only the isolated browser to shut down;
                    # no manager/service/controller signal or action is sent.
                    browser.stdin.close();notify('BROWSER_OBSERVATION_UNKNOWN: no manager or service action taken.')
            for name,stream in [('stdout',browser.stdout),('stderr',browser.stderr)]:
                try:chunk=os.read(stream.fileno(),4096)
                except BlockingIOError:continue
                if not chunk:continue
                counts[name]+=len(chunk)
                if counts[name]>65536:
                    unknown=True;reason='browser_incomplete'
                    if not browser.stdin.closed:browser.stdin.close()
                if name=='stdout' and not unknown:
                    pending.extend(chunk)
                    while b'\n' in pending:
                        line,_,pending=pending.partition(b'\n')
                        if line==b'RESTART_BROWSER_HUMAN_LOGIN' and not saw_login:
                            saw_login=True;notify('Sign in manually in the new isolated Chromium window to the selected existing manager.')
                        elif line.startswith(b'RESTART_BASELINE_SHA256 ') and not prompted:
                            baseline_hash=line.split(b' ',1)[1].decode('ascii');sha(baseline_hash)
                            raw=read_regular(baseline,32768);need(digest(raw)==baseline_hash);validate_baseline(strict_json(raw),p,plan_hash)
                            prompted=True;notify('Baseline SHA256: '+baseline_hash+'\nTransfer only the generated baseline to the approved Windows path. After the Windows observer finishes, transfer its generated completion and paste its SHA256 here:')
                        else:unknown=True;reason='browser_incomplete'
            if prompted and not sent_digest and not unknown:
                ready,_,_=select.select([0],[],[],0)
                if ready:
                    # Only a digest is accepted, never a user-provided PASS or
                    # browser result. The independently generated boundary still
                    # receives full strict validation in the live browser.
                    value=os.read(0,256).strip();need(re.fullmatch(b'[a-f0-9]{64}',value) is not None)
                    browser.stdin.write(value+b'\n');browser.stdin.flush();sent_digest=True
            if browser.poll() is not None:
                if end is None:end=time.monotonic()
            time.sleep(0.25)
        need(not unknown and browser.returncode==0 and baseline_hash,'browser_incomplete')
        verify_manager_process(p,config);budget.check()
        report=validate_browser_result(strict_json(read_regular(result,65536)),p,plan_hash,baseline_hash)
        need(report['status']=='passed-subset','browser_incomplete')
        raw=read_regular(p['handoff']['linuxCompletion'],65536)
        need(digest(raw)==report['completionSHA256'])
        boundary=strict_json(raw); expected=completion(p,plan_hash,baseline_hash,boundary['native']);need(boundary==expected)
        need(report['samples'][0]==validate_baseline(strict_json(read_regular(baseline,32768)),p,plan_hash)['sample'])
        creation=boundary['native']['newProcessCreationFiletime']
        need(advancing(report['samples'][0],report['samples'][1],creation) and advancing(report['samples'][1],report['samples'][2],creation))
        return report
    finally:
        # Any post-launch setup/write/poll/notification failure still observes
        # the isolated browser to verified exit. The shared supervisor tolerates
        # both blocking and nonblocking pipes, so failed set_blocking cannot turn
        # this cleanup into a blocking single-stream read. Never touch manager.
        from supervisor import drain
        try:
            if not browser.stdin.closed:browser.stdin.close()
        except BaseException:pass
        class CleanupBudget:
            def check(self):pass
        drain(browser,{'stdout':browser.stdout.fileno(),'stderr':browser.stderr.fileno()},CleanupBudget(),lambda:True,lambda:None,lambda _:None)
        browser.stdout.close();browser.stderr.close()
