#!/usr/bin/env python3
"""One-shot private legacy decoder comparison, inside the existing B manager.

Parent pins the full manager CID/image and invokes this as container root. No
manager socket, service signal, active config edit, DB copy, or network request.
All actual payloads and native output remain in the new private /tmp stage.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import resource
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path('/var/ossec')
STAGE = Path('/tmp/capstone-stats-decoder-capacity-20261015')
FIXTURE = Path('/tmp/capstone-stats-fixture-20261015.jsonl')
FIXTURE_SHA = '74cde4f77b8dc1e5d3999ba2048e7f98180c0c5600f1c41ee8d9ee709e6d2f61'
BINARY = ROOT / 'bin/wazuh-logtest-legacy'
TREES = ('ruleset/decoders', 'ruleset/rules', 'etc/decoders', 'etc/rules', 'etc/lists')
FILES = ('etc/ossec.conf', 'etc/internal_options.conf', 'etc/local_internal_options.conf')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_uid, s.st_gid,
            stat.S_IMODE(s.st_mode), s.st_nlink, s.st_mtime_ns, s.st_ctime_ns]


def read(path, maximum=16*1024*1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'file_bound')
        with os.fdopen(os.dup(fd), 'rb') as f:
            raw = f.read(maximum + 1)
        need(len(raw) == before.st_size and identity(os.fstat(fd)) == identity(before)
             and identity(os.lstat(path)) == identity(before), 'file_changed')
        return raw, identity(before)
    finally:
        os.close(fd)


def write(path, raw, mode=0o400, gid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fchown(f.fileno(), 0, gid)
        os.fchmod(f.fileno(), mode)
        os.fsync(f.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def encoded(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode()


def pairs(rows):
    out = {}
    for key, value in rows:
        need(key not in out, 'duplicate_json_key')
        out[key] = value
    return out


def fields(obj, prefix=''):
    need(isinstance(obj, dict) and obj, 'stats_object_required')
    result = []
    for key, value in obj.items():
        need(isinstance(key, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', key), 'field_name')
        name = prefix + key
        if isinstance(value, dict):
            result.extend(fields(value, name + '.'))
        else:
            # Default JSON_Decoder stores an entire array (including objects)
            # as one dynamic field and null as one string field.
            need(type(value) in (int, float, str, bool, list) or value is None,
                 'unsupported_stats_leaf')
            result.append(name)
    need(len(set(result)) == len(result), 'ambiguous_flattened_key')
    return result


def source_snapshot():
    paths = [ROOT / name for name in FILES] + [BINARY, ROOT / 'lib/libwazuhext.so']
    for name in TREES:
        tree = ROOT / name
        need(tree.is_dir() and not tree.is_symlink(), 'source_directory')
        for parent, directories, files in os.walk(tree, followlinks=False):
            for entry in directories:
                need(not (Path(parent)/entry).is_symlink(), 'source_symlink')
            paths.extend(Path(parent)/entry for entry in files)
    need(len(paths) <= 4096, 'source_count_bound')
    out, total = {}, 0
    for path in sorted(paths):
        raw, meta = read(path)
        total += len(raw)
        need(total <= 128*1024*1024, 'source_total_bound')
        out[str(path.relative_to(ROOT))] = {'sha256': sha(raw), 'identity': meta}
    return out


def prepare(limit, before, gid):
    base = STAGE / str(limit)
    base.mkdir(mode=0o700)
    root = base / 'root'
    root.mkdir(mode=0o750)
    os.chown(root, 0, gid)
    root.chmod(0o750)
    need(identity(os.lstat(root))[3:6] == [0, gid, 0o750], 'private_root_permissions')
    for rel in list(TREES) + ['etc', 'logs', 'logs/alerts', 'logs/archives',
                             'logs/firewall', 'queue', 'queue/fts', 'queue/diff',
                             'queue/rids', 'queue/alerts', 'var', 'var/run', 'stats']:
        path = root / rel
        path.mkdir(mode=0o770, parents=True, exist_ok=True)
    for path in root.rglob('*'):
        if path.is_dir():
            os.chown(path, 0, gid)
            path.chmod(0o770)
    for rel, meta in before.items():
        if rel in ('bin/wazuh-logtest-legacy', 'lib/libwazuhext.so', 'etc/ossec.conf',
                   'etc/local_internal_options.conf'):
            continue
        path = root / rel
        path.parent.mkdir(mode=0o770, parents=True, exist_ok=True)
        raw, current = read(ROOT / rel)
        need(sha(raw) == meta['sha256'] and current == meta['identity'], 'copy_source_changed')
        write(path, raw, 0o640, gid)
    config, _ = read(ROOT / 'etc/ossec.conf')
    source = ET.fromstring('<root>' + config.decode() + '</root>')
    rulesets = source.findall('ossec_config/ruleset')
    need(len(rulesets) == 1, 'single_actual_ruleset_required')
    for node in rulesets[0]:
        if node.tag in ('decoder_dir', 'rule_dir', 'decoder_include', 'rule_include', 'list'):
            value = (node.text or '').strip()
            need(value and not value.startswith('/') and '..' not in Path(value).parts,
                 'nonprivate_ruleset_path')
    config = ('<ossec_config><global><jsonout_output>no</jsonout_output>'
              '<alerts_log>no</alerts_log><logall>no</logall><logall_json>no</logall_json>'
              '<email_notification>no</email_notification></global>' +
              ET.tostring(rulesets[0], encoding='unicode') + '</ossec_config>\n').encode()
    write(root / 'etc/ossec.conf', config, 0o640, gid)
    local, _ = read(ROOT / 'etc/local_internal_options.conf')
    need(not re.search(rb'^\s*analysisd\.decoder_order_size\s*=', local, re.M), 'unexpected_live_override')
    local += (b'' if local.endswith(b'\n') else b'\n') + f'analysisd.decoder_order_size={limit}\n'.encode()
    write(root / 'etc/local_internal_options.conf', local, 0o640, gid)
    # Legacy loads CDB files and writes FTS/diff inside this chroot after UID drop.
    for path in root.rglob('*'):
        if path.is_dir():
            os.chown(path, 0, gid)
            path.chmod(0o770)
    return base, root


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (40, 40))
    resource.setrlimit(resource.RLIMIT_AS, (2*1024**3, 2*1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8*1024*1024, 8*1024*1024))


def run_legacy(root, base):
    started = time.monotonic()
    proc = None
    timed_out = False
    with (STAGE/'input.jsonl').open('rb') as input_file, (base/'native.log').open('xb') as output:
        try:
            proc = subprocess.Popen([str(BINARY), '-D', str(root), '-c', 'etc/ossec.conf', '-v'],
                stdin=input_file, stdout=output, stderr=subprocess.STDOUT, cwd=root,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','LD_LIBRARY_PATH':'/var/ossec/lib'},
                start_new_session=True, preexec_fn=limits)
            while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic()-started > 45:
                    timed_out = True
                    break
                time.sleep(0.05)
        finally:
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            output.flush()
            os.fsync(output.fileno())
    (base/'native.log').chmod(0o400)
    need(not timed_out and proc.returncode == 0, 'native_failed')
    raw, _ = read(base/'native.log', 8*1024*1024)
    return raw, {'returncode': proc.returncode, 'seconds':round(time.monotonic()-started,3),
                 'timed_out':timed_out, 'native_log_sha256':sha(raw), 'child_reaped':True}


def parse_output(raw, expected, limit):
    text = raw.decode('utf-8', errors='strict')
    parts = text.split('**Phase 2: Completed decoding.')
    need(len(parts) == 3, 'native_event_count')
    result = []
    for part, names in zip(parts[1:], expected):
        need('**Phase 3: Completed filtering (rules).' in part, 'native_rule_phase_missing')
        phase2 = part.split('**Phase 3:',1)[0].split('**Rule debugging:',1)[0]
        decoder = re.findall(r"^\s+decoder: '([^']+)'$", phase2, re.M)
        # cJSON_Print(array) spans lines; identify its field header, not a
        # fabricated scalar-only closing quote on the same line.
        observed = re.findall(r"^       ([A-Za-z0-9_.-]+): '", phase2, re.M)
        observed = [name for name in observed if name != 'decoder']
        need(decoder == ['json'], 'native_decoder_unexpected')
        need(observed == names[:limit], 'native_fields_not_exact')
        rule = re.findall(r"^\s+Rule id: '([0-9]+)'$", part, re.M)
        level = re.findall(r"^\s+Level: '([0-9]+)'$", part, re.M)
        need(rule == ['86600'] and level == ['0'] and '**Alert to be generated.' not in part,
             'native_rule_unexpected')
        result.append({'input_fields':len(names),'decoded_fields':len(observed),
                       'exact_expected_prefix':True,'complete':len(observed)==len(names),
                       'rule_id':86600,'level':0,'alert_generated':False})
    count = text.count('Too many fields for JSON decoder.')
    expected_errors = sum(max(0,len(names)-limit) for names in expected)
    need(count == expected_errors, 'native_error_count')
    return {'cases':result,'field_limit_error_count':count,'expected_error_count':expected_errors}


def main():
    need(sys.platform == 'linux' and os.geteuid() == 0 and len(sys.argv)==1, 'linux_container_root_only')
    os.umask(0o077)
    def interrupted(signum, frame):
        raise ValueError('native_comparison_interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    gid = grp.getgrnam('wazuh').gr_gid
    need(gid==999 and pwd.getpwnam('wazuh').pw_uid==999, 'installed_wazuh_uid_gid')
    payload, meta = read(FIXTURE, 16384)
    need(meta[3:7]==[0,0,0o400,1] and len(payload)==8882 and sha(payload)==FIXTURE_SHA,
         'fixed_fixture_changed')
    need(payload.endswith(b'\n') and payload.count(b'\n')==1 and b'\0' not in payload, 'single_input_line')
    obj = json.loads(payload, object_pairs_hook=pairs)
    need(set(obj)=={'timestamp','event_type','stats'} and obj['event_type']=='stats', 'stats_shape')
    actual = fields(obj)
    need(len(actual)==504, 'stats_native_field_count')
    obj['capstone']={'source':'suricata'}
    labelled = fields(obj)
    need(len(labelled)==505 and labelled[-1]=='capstone.source', 'labelled_field_count')
    before = source_snapshot()
    decoder_raw, _ = read(ROOT / 'ruleset/decoders/0006-json_decoders.xml')
    decoders = ET.fromstring('<root>' + decoder_raw.decode() + '</root>')
    defaults = [x for x in decoders if x.get('name') == 'json']
    need(len(defaults)==1 and defaults[0].findtext('plugin_decoder')=='JSON_Decoder'
         and defaults[0].findtext('json_array_structure') in (None,'array')
         and defaults[0].findtext('json_null_field') in (None,'string'),
         'native_json_default_contract')
    STAGE.mkdir(mode=0o700)
    result = {'schema_version':1,'status':'incomplete','fixture_sha256':FIXTURE_SHA,
              'fixture_bytes':8882,'recursive_scalar_leaves':508,
              'actual_native_fields':504,'labelled_native_fields':505,'arms':[],
              'manager_socket_used':False,'operating_files_changed':False,'agent_changed':False,
              'source_sha256':sha(Path(__file__).read_bytes()),'stage':str(STAGE)}
    try:
        write(STAGE/'input.jsonl',payload+json.dumps(obj,separators=(',',':')).encode()+b'\n')
        write(STAGE/'before.json',encoded(before))
        for limit in (256,1024):
            base, root = prepare(limit,before,gid)
            raw, command = run_legacy(root,base)
            verdict = parse_output(raw,[actual,labelled],limit)
            result['arms'].append({'decoder_order_size':limit,**command,**verdict})
        result['status']='native_comparison_passed'
    except Exception as exc:
        result['status']='rejected'
        result['reason']=str(exc) if isinstance(exc,ValueError) else type(exc).__name__
    finally:
        try:
            result['source_unchanged']=source_snapshot()==before
        except Exception:
            result['source_unchanged']=False
        if not result['source_unchanged']:
            result['status']='rejected'
        write(STAGE/'result.json',encoded(result))
    print(encoded(result).decode(),end='')
    return 0 if result['status']=='native_comparison_passed' else 1


if __name__=='__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({'status':'rejected_before_result','reason':str(exc) if isinstance(exc,ValueError) else type(exc).__name__},sort_keys=True))
        sys.exit(1)
