#!/usr/bin/env bash
# Read a two-file tar on stdin from the authenticated SIEM SSH connection.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || exit 77
python3 -B -c '
import io,os,pathlib,stat,sys,tarfile
root=pathlib.Path("/opt/capstone-prereqs")
if root.is_symlink(): raise SystemExit("unsafe prerequisite directory")
root.mkdir(mode=0o700,parents=True,exist_ok=True)
st=root.stat()
if st.st_uid!=0 or stat.S_IMODE(st.st_mode)&0o022: raise SystemExit("unsafe prerequisite permissions")
names={"exports/wazuh-enrollment-ca.pem":("wazuh-root-ca.pem",0o644),"secrets/enrollment.pass":("wazuh-enrollment.pass",0o600)}
payload=sys.stdin.buffer.read(1024*1024+1)
if len(payload)>1024*1024: raise SystemExit("oversized enrollment bundle")
with tarfile.open(fileobj=io.BytesIO(payload),mode="r:") as archive:
    members=archive.getmembers()
    if len(members)!=2 or {m.name for m in members}!=set(names): raise SystemExit("unexpected enrollment bundle")
    prepared=[]
    for item in members:
        if not item.isfile() or not 0<item.size<=65536: raise SystemExit("invalid enrollment member")
        data=archive.extractfile(item).read()
        name,mode=names[item.name]; dest=root/name
        if dest.is_symlink(): raise SystemExit("unsafe destination")
        if dest.exists():
            if not dest.is_file() or dest.read_bytes()!=data: raise SystemExit("different enrollment material already exists; inspect manually")
            if dest.stat().st_uid!=0 or dest.stat().st_gid!=0 or dest.stat().st_nlink!=1 or stat.S_IMODE(dest.stat().st_mode)!=mode: raise SystemExit("existing enrollment file permissions differ")
        prepared.append((dest,mode,data))
    for dest,mode,data in prepared:
        if dest.exists(): continue
        fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
        with os.fdopen(fd,"wb") as out: out.write(data);out.flush();os.fsync(out.fileno())
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
print("Enrollment CA and credential received; values not printed.")
'
