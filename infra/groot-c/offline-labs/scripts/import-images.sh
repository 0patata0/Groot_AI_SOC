#!/usr/bin/env bash
# Run on the disconnected Docker host. Verify the SHA256SUMS file itself against
# the administrator's separately trusted transfer receipt before invoking this.
# docker load does not need network access; no pull/login/build is performed.
# Usage: sudo bash import-images.sh /approved/offline-images
# Then review/copy cve_list.json to /etc/capstone-offline-labs/ and restart both
# application services. Do not overwrite a catalog with live labs without review.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
[[ $# == 1 ]] || { echo 'usage: import-images.sh DIRECTORY' >&2; exit 2; }
python3 -B - "$1" <<'PY'
from pathlib import Path
import hashlib,json,subprocess,sys
def digest(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
root=Path(sys.argv[1]).resolve();verified=set()
for line in (root/'SHA256SUMS').read_text().splitlines():
 sha,name=line.split('  ',1)
 if len(sha)!=64 or Path(name).name!=name:
  raise ValueError('Invalid transfer checksum entry')
 f=root/name
 if not f.is_file() or f.is_symlink():
  raise ValueError('Regular transfer file required')
 if digest(f)!=sha:
  raise ValueError('Transfer checksum mismatch')
 verified.add(name)
if not {'images.json','cve_list.json'}<=verified:
 raise ValueError('Transfer metadata is missing from checksums')
rows=json.loads((root/'images.json').read_text())
for row in rows:
 name=row['file']
 if name not in verified or not name.endswith('.tar'):
  raise ValueError('Unverified image archive')
 if digest(root/name)!=row['sha256']:
  raise ValueError('Image archive checksum mismatch')
 # An existing tag may not be silently replaced by a different image.
 p=subprocess.run(['docker','--host','unix:///var/run/docker.sock','image','inspect',row['image_tag']],capture_output=True)
 if p.returncode==0 and json.loads(p.stdout)[0]['Id']!=row['image_id']:
  raise ValueError('Local tag conflict')
 subprocess.run(['docker','--host','unix:///var/run/docker.sock','image','load','--input',str(root/name)],check=True)
 actual=json.loads(subprocess.check_output(['docker','--host','unix:///var/run/docker.sock','image','inspect',row['image_tag']]))[0]
 if actual['Id']!=row['image_id']:
  raise ValueError('Loaded image does not match manifest')
print(f'Loaded and verified {len(rows)} local images. No containers started.')
PY
