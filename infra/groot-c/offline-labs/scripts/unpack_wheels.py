#!/usr/bin/env python3
"""Install pre-verified wheel contents without pip/network. Fresh destination only."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import stat
import sys
import zipfile


def unpack(wheel_dir, inventory_path, destination):
    inventory = json.loads(inventory_path.read_text())
    if destination.exists():
        raise RuntimeError('destination already exists')
    for row in inventory:
        name = row['file']
        if Path(name).name != name or not name.endswith('.whl'):
            raise ValueError('invalid wheel name')
        if hashlib.sha256((wheel_dir / name).read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('wheel checksum mismatch')
    destination.mkdir(mode=0o755)
    written = set()
    for row in inventory:
        with zipfile.ZipFile(wheel_dir / row['file']) as archive:
            for item in archive.infolist():
                path = PurePosixPath(item.filename)
                if path.is_absolute() or '..' in path.parts or stat.S_ISLNK(item.external_attr >> 16):
                    raise ValueError('unsafe wheel entry')
                if any(part.endswith('.data') for part in path.parts):
                    raise ValueError('wheel data scheme needs a reviewed installer')
                target = destination.joinpath(*path.parts)
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if str(path) in written:
                    raise ValueError('overlapping wheel contents')
                written.add(str(path));target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(item));target.chmod(0o644)
    destination.chmod(0o755)
    for directory in destination.rglob('*'):
        if directory.is_dir():
            directory.chmod(0o755)
    print(json.dumps({'installed_wheels': len(inventory), 'destination': str(destination)}))


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: unpack_wheels.py WHEEL_DIRECTORY INVENTORY_JSON NEW_TARGET')
    unpack(*(Path(a) for a in sys.argv[1:]))
