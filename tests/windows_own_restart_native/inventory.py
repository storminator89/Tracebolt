#!/usr/bin/env python3
"""Source-only exact Git export inventory. Never contacts a target or builds/runs
an application. Outputs must be outside the clean source root and create-only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def main():
    if not sys.flags.isolated or not sys.dont_write_bytecode:raise ValueError()
    p=argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument('--root',required=True);p.add_argument('--inventory',required=True);p.add_argument('--commit-object',required=True)
    args=p.parse_args();root=Path(args.root)
    if not root.is_absolute() or root.resolve()!=root:raise ValueError()
    def git(*args):
        result=subprocess.run(['git','-C',str(root),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True,timeout=30)
        if len(result.stdout)>8<<20:raise ValueError()
        return result.stdout
    if git('status','--porcelain=v1','--untracked-files=all'):raise ValueError()
    commit=git('rev-parse','HEAD').decode().strip();tree=git('rev-parse','HEAD^{tree}').decode().strip();raw_commit=git('cat-file','commit','HEAD')
    rows=[];names=set()
    for raw in git('ls-files','--stage','-z').split(b'\0'):
        if not raw:continue
        info,name=raw.split(b'\t',1);mode,sha,stage=info.decode('ascii').split();name=name.decode('utf8')
        if stage!='0' or mode not in {'100644','100755'} or name in names or any(x in ('','.','..','.git','__pycache__') for x in name.split('/')):raise ValueError()
        path=root/name
        for part in (path,*path.parents):
            if part.is_symlink() or getattr(part.lstat(),'st_file_attributes',0)&0x400:raise ValueError()
        info=path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>64<<20:raise ValueError()
        data=path.read_bytes();actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if actual!=sha:raise ValueError()
        rows.append({'path':name,'sha':sha,'sha256':hashlib.sha256(data).hexdigest(),'mode':mode,'size':len(data)});names.add(name)
    actual=set()
    for parent,dirs,files in os.walk(root):
        dirs[:]=[d for d in dirs if d!='.git']
        for name in files:
            if name!='.git':actual.add((Path(parent)/name).relative_to(root).as_posix())
    if actual!=names:raise ValueError()
    inventory=(json.dumps(rows,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
    for destination,data in ((args.inventory,inventory),(args.commit_object,raw_commit)):
        path=Path(destination)
        if not path.is_absolute() or path.resolve()!=path or path==root or root in path.parents:raise ValueError()
        for part in path.parents:
            if part.is_symlink():raise ValueError()
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    print(json.dumps({'commit':commit,'tree':tree,'inventorySHA256':hashlib.sha256(inventory).hexdigest()},sort_keys=True))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError):raise SystemExit('SOURCE_INVENTORY_REJECTED')
