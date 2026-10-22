#!/usr/bin/env python3
"""Read-only common-key check and explicit SSH export/receive protocol.

The application accepts 8..256 Unicode characters, at most 1024 UTF-8 bytes.
No action logs key material. Only explicit export emits raw key bytes to its
SSH pipe; receive stores one terminal LF as the application's file delimiter.
"""
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/opt/capstone-prereqs')
MAX_BYTES = 1024
MAX_FILE_BYTES = MAX_BYTES + 1


class Refused(Exception):
    pass


def need(value, code='unsafe_or_inconsistent_input'):
    if not value:
        raise Refused(code)


def parents_safe(path):
    for parent in (path, *path.parents):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and not info.st_mode & 0o022, 'root_controlled_parent_required')


def safe(path, limit):
    parents_safe(path.parent)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600, 'private_root_file_required')
    need(0 < info.st_size <= limit, 'private_file_size_invalid')


def key(data):
    """Validate an exact key value, without stripping meaningful whitespace."""
    need(isinstance(data, bytes) and len(data) <= MAX_BYTES, 'key_utf8_bytes_exceed_1024')
    try:
        value = data.decode('utf-8')
    except UnicodeError:
        raise Refused('key_invalid_utf8') from None
    need(8 <= len(value) <= 256, 'key_requires_8_to_256_unicode_characters')
    # Path.read_text() in the app applies universal newline conversion. A CR
    # could otherwise authenticate in SIEM but become a different lab key.
    need('\r' not in value, 'key_carriage_return_not_representable')
    return data


def pairs(items):
    result = {}
    for name, value in items:
        need(name not in result, 'duplicate_siem_json_key')
        result[name] = value
    return result


def source_key():
    path = ROOT / 'siem.json'
    safe(path, 16384)
    try:
        config = json.loads(path.read_bytes(), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise Refused('invalid_siem_json') from None
    need(isinstance(config, dict) and type(config.get('schema_version')) is int
         and config['schema_version'] == 1 and config.get('indexer_username') == 'admin',
         'siem_admin_schema_required')
    need(isinstance(config.get('indexer_password'), str), 'siem_admin_password_string_required')
    try:
        data = config['indexer_password'].encode('utf-8')
    except UnicodeError:
        raise Refused('key_invalid_utf8') from None
    return key(data)


def receive(data):
    data = key(data)
    destination = ROOT / 'lab-admin.key'
    if destination.exists() or destination.is_symlink():
        safe(destination, MAX_FILE_BYTES)
        # Accept the previous delimiter-free file and the application-standard
        # optional terminal LF. Never replace a different existing key.
        existing = destination.read_bytes().removesuffix(b'\n')
        need(key(existing) == data, 'existing_common_key_differs')
        return
    parents_safe(ROOT)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        os.fchown(stream.fileno(), 0, 0)
        stream.write(data + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    need(os.geteuid() == 0, 'root_required')
    need(len(args) == 1 and args[0] in ('check', 'export', 'receive'), 'action_must_be_check_export_or_receive')
    if args[0] == 'check':
        source_key()
        print('Common SIEM admin/lab key contract verified; value not displayed.')
    elif args[0] == 'export':
        sys.stdout.buffer.write(source_key())
    else:
        # Read one excess byte so truncation can never install a prefix of a key.
        receive(sys.stdin.buffer.read(MAX_BYTES + 1))
        print('Common SIEM admin/lab exemption key received; value not displayed.')


def cli(argv=None):
    try:
        main(argv)
        return 0
    except Refused as error:
        # Every Refused message above is a fixed code, never input material.
        print('lab key protocol rejected: ' + str(error), file=sys.stderr)
    except (KeyError, OSError, TypeError, ValueError):
        print('lab key protocol rejected: invalid_or_unavailable_private_input', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(cli())
