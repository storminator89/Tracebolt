#!/usr/bin/env python3
"""Prepare a hash-pinned guide command after the exact source is published.

--refresh-manifest updates only the five reviewed source entries. --revision
verifies all seven public files equal this checkout before printing one command.
Neither operation runs the guide, changes host policy, or writes Git state.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import sys

SPEC = importlib.util.spec_from_file_location("journal_guide_command_source", Path(__file__).with_name("guide.py"))
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)
ROOT = Path(__file__).resolve().parents[2]

# This fixed bootstrap is present in the reviewed, copied command. Downloaded
# bytes are never executed before both size and SHA-256 match that command.
# A partial destination stays in place. Only a complete hash-verified cache can
# be reused after cancellation; an existing partial destination is not adopted.
BOOTSTRAP = r'''import hashlib,json,os,re,ssl,stat,sys,time,urllib.request
def require(ok):
    if not ok: raise SystemExit("Source verification failed; retain staging. No host permission was changed.")
if sys.platform!="linux" or os.getuid()!=0 or os.geteuid()!=0:
    raise SystemExit("Run this reviewed command deliberately in a root terminal on the intended Linux endpoint. No automatic privilege escalation is performed.")
require(len(sys.argv)==6)
try:
    with open("/dev/tty","r+") as tty:
        if not tty.isatty(): raise OSError()
except OSError:
    raise SystemExit("A local interactive root terminal is required before any source download or staging.") from None
rev,gh,gs,mh,ms=sys.argv[1:]
require(re.fullmatch("[0-9a-f]{40}",rev) and all(re.fullmatch("[0-9a-f]{64}",v) for v in (gh,mh)))
require(gs.isdecimal() and ms.isdecimal() and 0<int(gs)<=131072 and 0<int(ms)<=8192)
flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
def protected(fd):
    s=os.fstat(fd); require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and s.st_mode&0o6022==0)
def mkdir(parent,name):
    os.mkdir(name,0o700,dir_fd=parent)
    fd=os.open(name,flags,dir_fd=parent)
    os.fchown(fd,0,0); os.fchmod(fd,0o700); os.fsync(fd); os.fsync(parent)
    return fd
root=os.open("/",flags); protected(root)
home=os.open("root",flags,dir_fd=root); protected(home)
name="tracebolt-journal-guide-"+rev
try:
    stage=mkdir(home,name); fresh=True
except FileExistsError:
    stage=os.open(name,flags,dir_fd=home); protected(stage); fresh=False
if fresh:
    deploy=mkdir(stage,"deploy"); journal=mkdir(deploy,"journal")
else:
    require(set(os.listdir(stage))=={"deploy"})
    deploy=os.open("deploy",flags,dir_fd=stage); protected(deploy)
    require(set(os.listdir(deploy))=={"journal","systemd"})
    journal=os.open("journal",flags,dir_fd=deploy); protected(journal)
    require(set(os.listdir(journal))=={"guide.py","source-manifest.json","amend.py","setup.py"})
    systemd=os.open("systemd",flags,dir_fd=deploy); protected(systemd)
    require(set(os.listdir(systemd))=={"tracebolt-agent.service.in","tracebolt-journal-reader.service.in","tracebolt-journal-reader.socket.in"})
base="/root/"+name
def read(parent,name,limit):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=limit)
        raw=bytearray()
        while len(raw)<=limit:
            chunk=os.read(fd,min(65536,limit+1-len(raw)))
            if not chunk: break
            raw.extend(chunk)
        pin=lambda s: (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(len(raw)==before.st_size and pin(before)==pin(os.fstat(fd))==pin(os.stat(name,dir_fd=parent,follow_symlinks=False)))
        return bytes(raw)
    finally: os.close(fd)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**kw): raise SystemExit("Source redirect rejected; retain staging.")
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
for filename,h,size in (("guide.py",gh,int(gs)),("source-manifest.json",mh,int(ms))):
    if not fresh:
        raw=read(journal,filename,size)
        require(len(raw)==size and hashlib.sha256(raw).hexdigest()==h)
        continue
    url="https://raw.githubusercontent.com/storminator89/Tracebolt/"+rev+"/deploy/journal/"+filename
    request=urllib.request.Request(url,headers={"Accept-Encoding":"identity"})
    deadline=time.monotonic()+20
    with opener.open(request,timeout=10) as response:
        require(response.status==200 and response.geturl()==url and response.headers.get("Content-Encoding","identity")=="identity")
        raw=bytearray()
        while len(raw)<=size:
            require(time.monotonic()<deadline)
            chunk=response.read1(min(65536,size+1-len(raw)))
            if not chunk: break
            raw.extend(chunk)
    require(len(raw)==size and hashlib.sha256(raw).hexdigest()==h)
    fd=os.open(filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=journal)
    try:
        os.fchown(fd,0,0); os.fchmod(fd,0o600)
        data=memoryview(raw)
        while data:
            n=os.write(fd,data); require(n>0); data=data[n:]
        os.fsync(fd)
    finally: os.close(fd)
    os.fsync(journal)
if not fresh:
    manifest=json.loads(read(journal,"source-manifest.json",int(ms)))
    expected={"deploy/journal/amend.py","deploy/journal/setup.py","deploy/systemd/tracebolt-agent.service.in","deploy/systemd/tracebolt-journal-reader.service.in","deploy/systemd/tracebolt-journal-reader.socket.in"}
    require(set(manifest)=={"schemaVersion","files"} and manifest["schemaVersion"]=="tracebolt.journal-guide-source.v1" and set(manifest["files"])==expected)
    for path,entry in manifest["files"].items():
        require(set(entry)=={"sha256","size"} and type(entry["size"]) is int and 0<entry["size"]<=131072 and re.fullmatch("[0-9a-f]{64}",entry["sha256"]))
        raw=read(journal if path.startswith("deploy/journal/") else systemd,path.rsplit("/",1)[1],entry["size"])
        require(len(raw)==entry["size"] and hashlib.sha256(raw).hexdigest()==entry["sha256"])
for path,fd in (("/",root),("/root",home),(base,stage),(base+"/deploy",deploy),(base+"/deploy/journal",journal)):
    protected(fd); a=os.fstat(fd); b=os.lstat(path)
    require((a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode)==(b.st_dev,b.st_ino,b.st_uid,b.st_gid,b.st_mode))
os.execv("/usr/bin/python3",["/usr/bin/python3","-I",base+"/deploy/journal/guide.py","--revision",rev,"--guide-sha256",gh,"--manifest-sha256",mh])
'''


def make_manifest(read):
    entries = {}
    for relative in g.CORE_FILES:
        raw = read(relative)
        g.require(type(raw) is bytes and 0 < len(raw) <= g.MAX_SOURCE_BYTES, "source-size")
        entries[relative] = dict(sha256=g.sha256(raw), size=len(raw))
    return dict(schemaVersion=g.MANIFEST_VERSION, files=entries)


def command(revision, read, download=g.fetch):
    g.require(g.valid_revision(revision), "immutable-source-revision")
    guide = read(g.GUIDE_FILE)
    manifest_raw = read(g.MANIFEST_FILE)
    manifest = g.source_manifest(manifest_raw)
    g.require(manifest == make_manifest(read), "refresh-reviewed-source-manifest")
    for relative in (g.GUIDE_FILE, g.MANIFEST_FILE, *g.CORE_FILES):
        local = read(relative)
        g.require(download(g.REPOSITORY + revision + "/" + relative, len(local)) == local,
                  "publication-bytes-do-not-match-reviewed-source")
    # repr escapes every newline so the final result is a single shell line.
    invocation = ["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
                  "/usr/bin/python3", "-I", "-c", "exec(" + repr(BOOTSTRAP) + ")", revision,
                  g.sha256(guide), str(len(guide)), g.sha256(manifest_raw), str(len(manifest_raw))]
    return " ".join(shlex.quote(value) for value in invocation)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--refresh-manifest", action="store_true")
    action.add_argument("--revision", help="Full immutable, already published source commit")
    args = parser.parse_args(argv)
    read = lambda relative: (ROOT / relative).read_bytes()
    try:
        if args.refresh_manifest:
            raw = json.dumps(make_manifest(read), indent=2).encode() + b"\n"
            (ROOT / g.MANIFEST_FILE).write_bytes(raw)
            print("Updated five source hashes. Review and publish these bytes before generating the installation command.")
        else:
            print(command(args.revision, read))
        return 0
    except Exception as exc:
        print(str(exc) if isinstance(exc, g.Rejected) else "Publication verification failed; no command generated.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
