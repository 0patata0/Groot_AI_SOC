#!/usr/bin/env python3
"""Verify already acquired Ubuntu artifacts and create a new build context.

No network requests, Docker operations, host package installation, or exploit.
The caller must independently trust the Ubuntu archive keyring SHA256.
"""
import argparse
import datetime
import hashlib
import json
import lzma
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

BASE = Path(__file__).resolve().parent
HASH = re.compile(r"[a-f0-9]{64}\Z")
MAX_PACKAGES = 512 * 1024 * 1024
MAX_XZ_STREAMS = 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fields(text):
    out, key = {}, None
    for line in text.splitlines():
        if line.startswith((' ', '\t')):
            if key is None:
                raise ValueError('invalid_control_continuation')
            out[key] += '\n' + line.strip()
        elif line:
            key, separator, value = line.partition(':')
            if not separator or key in out:
                raise ValueError('invalid_or_duplicate_control_field')
            out[key] = value.strip()
    return out


def release_entry(release, source, packages):
    values = fields(release)
    if any(values.get(k) != v for k, v in
           [('Origin', 'Ubuntu'), ('Suite', source['suite']), ('Codename', source['suite'])]):
        raise ValueError('unexpected_release')
    matches = [line.split() for line in values.get('SHA256', '').splitlines()
               if len(line.split()) == 3 and line.split()[2] == source['packages_path']]
    if len(matches) != 1:
        raise ValueError('signed_packages_hash_missing_or_duplicate')
    digest, size, _ = matches[0]
    if not HASH.fullmatch(digest) or size != str(len(packages)) or sha(packages) != digest:
        raise ValueError('packages_hash_mismatch')
    return values


def decompress_packages(packages):
    # XZ permits concatenated streams (including empty streams) and padding in
    # multiples of four bytes. Bound the combined output, decoder memory, and
    # stream count rather than accepting arbitrary trailing data.
    remaining, plain, streams = packages, bytearray(), 0
    if not remaining:
        raise ValueError('packages_decompression_limit_or_trailing_data')
    while remaining:
        streams += 1
        if streams > MAX_XZ_STREAMS:
            raise ValueError('packages_decompression_limit_or_trailing_data')
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * 1024 * 1024)
        try:
            chunk = decoder.decompress(remaining, max_length=MAX_PACKAGES - len(plain) + 1)
        except lzma.LZMAError as error:
            raise ValueError('packages_decompression_limit_or_trailing_data') from error
        plain.extend(chunk)
        if len(plain) > MAX_PACKAGES or not decoder.eof:
            raise ValueError('packages_decompression_limit_or_trailing_data')
        trailing = decoder.unused_data
        remaining = trailing.lstrip(b'\x00')
        if (len(trailing) - len(remaining)) % 4:
            raise ValueError('packages_decompression_limit_or_trailing_data')
    return plain


def package_entry(packages, source, deb):
    plain = decompress_packages(packages)
    entries = [fields(part) for part in plain.decode('utf-8').split('\n\n') if part.strip()]
    matches = [item for item in entries if item.get('Package') == source['package']
               and item.get('Version') == source['package_version']
               and item.get('Architecture') == source['architecture']]
    if len(matches) != 1:
        raise ValueError('exact_package_record_missing_or_duplicate')
    item = matches[0]
    if item.get('Filename') != source['deb_path'] or item.get('Size') != str(len(deb)):
        raise ValueError('unexpected_package_path_or_size')
    if not HASH.fullmatch(item.get('SHA256', '')) or item['SHA256'] != sha(deb):
        raise ValueError('deb_hash_mismatch')
    return item


def read_regular(path, maximum):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('invalid_input_file')
    return path.read_bytes()


def prepare(args):
    source = json.loads((BASE / 'source.json').read_text())
    keyring = read_regular(args.keyring, 8 * 1024 * 1024)
    if not HASH.fullmatch(args.keyring_sha256) or sha(keyring) != args.keyring_sha256:
        raise ValueError('trusted_keyring_hash_mismatch')
    inrelease = read_regular(args.inrelease, 8 * 1024 * 1024)
    packages = read_regular(args.packages_xz, 64 * 1024 * 1024)
    deb = read_regular(args.deb, 8 * 1024 * 1024)
    gpgv = shutil.which('gpgv')
    if not gpgv:
        raise ValueError('gpgv_required_no_install_attempted')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('new_output_directory_required')
    # Verify copies of the bytes we hashed, avoiding input replacement during gpgv.
    with tempfile.TemporaryDirectory(prefix='sudo-provenance-') as work:
        work = Path(work)
        (work / 'keyring.gpg').write_bytes(keyring)
        (work / 'InRelease').write_bytes(inrelease)
        verified = subprocess.run([gpgv, '--homedir', str(work), '--keyring', str(work / 'keyring.gpg'),
                                   '--output', str(work / 'Release'), str(work / 'InRelease')],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if verified.returncode:
            raise ValueError('ubuntu_release_signature_invalid')
        release = (work / 'Release').read_text()
    release_values = release_entry(release, source, packages)
    record = package_entry(packages, source, deb)
    evidence = {
        'schema': 1, 'cve_id': source['cve_id'], 'package': source['package'],
        'package_version': record['Version'], 'architecture': record['Architecture'],
        'deb_url': source['archive'] + record['Filename'], 'deb_sha256': sha(deb),
        'inrelease_sha256': sha(inrelease), 'packages_sha256': sha(packages),
        'keyring_sha256': sha(keyring), 'release_signature_verified': True,
        'release_suite': release_values['Suite'], 'release_date': release_values.get('Date'),
        'base_image': source['base_image'],
        'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'historical-package-authenticity; not repository freshness or exploit verification',
        'attack_tested': False,
    }
    args.output.mkdir(mode=0o700)
    try:
        (args.output / 'sudo.deb').write_bytes(deb)
        payload = (json.dumps(evidence, sort_keys=True, indent=2) + '\n').encode()
        (args.output / 'preparation.json').write_bytes(payload)
        for name in ('Dockerfile', 'check.sh', 'source.json'):
            shutil.copyfile(BASE / name, args.output / name)
        print(json.dumps({'prepared': True, 'deb_sha256': sha(deb),
                          'preparation_sha256': sha(payload), 'base_image': source['base_image'],
                          'image_built': False, 'attack_tested': False}, sort_keys=True))
    except BaseException:
        shutil.rmtree(args.output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('inrelease', 'packages-xz', 'deb', 'keyring', 'output'):
        parser.add_argument('--' + option, type=Path, required=True)
    parser.add_argument('--keyring-sha256', required=True)
    args = parser.parse_args()
    try:
        prepare(args)
    except (ValueError, OSError, subprocess.SubprocessError, lzma.LZMAError) as error:
        print(json.dumps({'prepared': False, 'error': str(error) if isinstance(error, ValueError)
                          else 'artifact_verification_failed', 'attack_tested': False}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
