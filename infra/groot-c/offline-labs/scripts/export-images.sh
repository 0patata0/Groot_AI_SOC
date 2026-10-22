#!/usr/bin/env bash
# Run on the connected preparation Linux host AFTER an administrator has obtained
# and reviewed the required images. This script never performs docker pull.
# Usage: bash export-images.sh /approved/cve_list.json /new/offline-images
# Transfer the entire directory and the reviewed manifest via approved media.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
[[ $# == 2 ]] || { echo 'usage: export-images.sh MANIFEST NEW_DIRECTORY' >&2; exit 2; }
python3 -B - "$1" "$2" <<'PY'
from pathlib import Path
import hashlib,json,subprocess,sys
def digest(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
manifest=Path(sys.argv[1]);out=Path(sys.argv[2]);rows=json.loads(manifest.read_text())
if not isinstance(rows,list) or not rows:
 raise ValueError('A non-empty manifest array is required')
out.mkdir(mode=0o700)  # Existing output directories are not overwritten.
receipts=[]
for i,row in enumerate(rows):
 if row.get('type','managed-http') != 'managed-http':
  continue  # Existing services and CLI labs have separate preparation contracts.
 tag=row['image_tag']
 if not isinstance(tag,str) or not tag or tag.startswith('-'):
  raise ValueError('Invalid image tag')
 image=json.loads(subprocess.check_output(['docker','--host','unix:///var/run/docker.sock','image','inspect',tag]))[0]
 if image['Id']!=row['image_id']:
  raise ValueError('Manifest image ID does not match local image')
 file=out/f'image-{i:03d}.tar'
 subprocess.run(['docker','--host','unix:///var/run/docker.sock','image','save','--output',str(file),tag],check=True)
 sha=digest(file)
 receipts.append({'file':file.name,'sha256':sha,'image_tag':tag,'image_id':image['Id']})
(out/'images.json').write_text(json.dumps(receipts,indent=2)+'\n')
(out/'cve_list.json').write_bytes(manifest.read_bytes())
(out/'SHA256SUMS').write_text(''.join(digest(f)+'  '+f.name+'\n' for f in sorted(out.iterdir()) if f.is_file()))
print(f'Exported {len(receipts)} managed HTTP image archives to {out}')
PY
