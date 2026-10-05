#!/usr/bin/env python3
"""Generate one pinned inventory command after verifying immutable public bytes.

Never runs the guide or changes host configuration. --refresh-manifest changes
only source checksums in this checkout; publication remains a separate action.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import sys

SPEC = importlib.util.spec_from_file_location("inventory_guide_command", Path(__file__).with_name("guide.py"))
g = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(g)
ROOT = Path(__file__).resolve().parents[2]

# No downloaded code executes until exact size/hash match the reviewed command.
# Source runs in memory: no root staging files, partial caches or cleanup steps.
BOOTSTRAP = '''import hashlib,os,re,ssl,sys,time,urllib.request
if sys.platform!="linux" or os.getuid()!=0 or os.geteuid()!=0: raise SystemExit("Use a local root terminal on the intended Linux endpoint.")
f=os.open("/dev/tty",os.O_RDWR|os.O_NOCTTY|os.O_CLOEXEC)
try:
 if not os.isatty(f): raise SystemExit("A local terminal is required.")
finally: os.close(f)
r,h,n,m,option=sys.argv[1:]
if not re.fullmatch("[0-9a-f]{40}",r) or not all(re.fullmatch("[0-9a-f]{64}",v) for v in (h,m)) or not n.isdecimal() or not 0<int(n)<=131072 or option not in ("default","network-identity"): raise SystemExit("Invalid source pins.")
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k): raise SystemExit("Source redirect rejected.")
u="https://raw.githubusercontent.com/storminator89/Tracebolt/"+r+"/deploy/inventory/guide.py"
o=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
d=time.monotonic()+20
with o.open(urllib.request.Request(u,headers={"Accept-Encoding":"identity"}),timeout=10) as p:
 if p.status!=200 or p.geturl()!=u or p.headers.get("Content-Encoding","identity")!="identity": raise SystemExit("Source response rejected.")
 b=bytearray()
 while len(b)<=int(n):
  if time.monotonic()>d: raise SystemExit("Source download timed out.")
  part=p.read1(min(65536,int(n)+1-len(b)))
  if not part: break
  b.extend(part)
if len(b)!=int(n) or hashlib.sha256(b).hexdigest()!=h: raise SystemExit("Source verification failed; agent and consent unchanged.")
sys.argv=["verified-inventory-guide","--revision",r,"--manifest-sha256",m]+(["--include-network-identity"] if option=="network-identity" else [])
exec(compile(bytes(b),"<verified-inventory-guide>","exec"),{"__name__":"__main__"})
'''


def make_manifest(read):
    entries = {}
    for path in g.CORE_FILES:
        raw = read(path)
        g.require(type(raw) is bytes and 0 < len(raw) <= g.MAX_SOURCE, "source-size")
        entries[path] = dict(sha256=g.digest(raw), size=len(raw))
    return dict(schemaVersion="tracebolt.inventory-guide-source.v1", files=entries)


def command(revision, read, download=g.fetch, include_identity=False):
    g.require(g.valid_revision(revision), "immutable-source-revision")
    guide, manifest_raw = read(g.GUIDE_FILE), read(g.MANIFEST_FILE)
    g.require(0 < len(guide) <= g.MAX_SOURCE and g.manifest(manifest_raw) == make_manifest(read),
              "refresh-reviewed-source-manifest")
    for path in (g.GUIDE_FILE, g.MANIFEST_FILE, *g.CORE_FILES):
        raw = read(path)
        g.require(download(g.REPOSITORY + revision + "/" + path, len(raw)) == raw,
                  "public-source-differs-no-command-generated")
    args = ["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
            "/usr/bin/python3", "-I", "-c", "exec(" + repr(BOOTSTRAP) + ")", revision,
            g.digest(guide), str(len(guide)), g.digest(manifest_raw), "network-identity" if include_identity else "default"]
    return " ".join(shlex.quote(value) for value in args)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--refresh-manifest", action="store_true")
    action.add_argument("--revision", help="Full, already published immutable source revision")
    parser.add_argument("--include-network-identity", action="store_true")
    args = parser.parse_args(argv)
    read = lambda path: (ROOT / path).read_bytes()
    try:
        if args.refresh_manifest:
            g.require(not args.include_network_identity, "selection-only-for-generated-command")
            (ROOT / g.MANIFEST_FILE).write_text(json.dumps(make_manifest(read), indent=2) + "\n")
            print("Source hashes updated. Review and publish before generating the command.")
        else:
            print(command(args.revision, read, include_identity=args.include_network_identity))
        return 0
    except Exception as exc:
        print(str(exc) if isinstance(exc, g.Rejected) else "Public source verification failed; no command generated.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
