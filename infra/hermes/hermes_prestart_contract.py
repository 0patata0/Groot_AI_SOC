"""Pure metadata contracts for a future operator-only prestart workflow.

No Docker, filesystem, subprocess, network or writes. These checks do not gather
evidence or authorize operations. A future operator must supply fresh trusted
inspect data under the deployment lock. There is no executable deployment CLI.
"""
from __future__ import annotations

import hashlib
import json
import re

IMAGE = 'sha256:2fd023efbb8d3d2b0ce1a73d028b07370cff34f567cfe0e999553e8c327ea283'
OLD_ID = '6c2ed13aea89404463061ea2032084bdd159ae784aff4e7bd9eea7406ba9b30b'
IMAGE_TAG = 'nousresearch/hermes-agent:v2026.9.24'
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_ENV_KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
_HOST = {
    'NetworkMode': 'bridge', 'RestartPolicy': {'Name': 'unless-stopped', 'MaximumRetryCount': 0},
    'AutoRemove': False, 'Privileged': False, 'ReadonlyRootfs': False,
    'Binds': ['/opt/hermes-data:/opt/data'], 'Mounts': None, 'Tmpfs': None,
    'PortBindings': {}, 'PublishAllPorts': False, 'CapAdd': None, 'CapDrop': None,
    'Devices': [], 'DeviceRequests': None, 'DeviceCgroupRules': None, 'SecurityOpt': None,
    'GroupAdd': None, 'Dns': None, 'DnsOptions': [], 'DnsSearch': [], 'ExtraHosts': None,
    'Links': None, 'VolumesFrom': None, 'ShmSize': 67108864, 'IpcMode': 'private',
    'CgroupnsMode': 'private', 'PidMode': '', 'UTSMode': '', 'UsernsMode': '',
    'Init': None, 'Isolation': '', 'Runtime': 'runc', 'LogConfig': {'Type': 'json-file', 'Config': {}},
    'Memory': 0, 'MemorySwap': 0, 'MemoryReservation': 0, 'MemorySwappiness': None,
    'OomKillDisable': None, 'OomScoreAdj': 0, 'CpuShares': 0, 'CpuPeriod': 0, 'CpuQuota': 0,
    'CpuRealtimePeriod': 0, 'CpuRealtimeRuntime': 0, 'NanoCpus': 0, 'CpusetCpus': '',
    'CpusetMems': '', 'PidsLimit': None, 'Ulimits': None, 'StorageOpt': None, 'Sysctls': None,
    'ConsoleSize': [0, 0],
    'MaskedPaths': ['/proc/acpi', '/proc/asound', '/proc/interrupts', '/proc/kcore',
                    '/proc/keys', '/proc/latency_stats', '/proc/sched_debug', '/proc/scsi',
                    '/proc/timer_list', '/proc/timer_stats', '/sys/devices/virtual/powercap',
                    '/sys/firmware'],
    'ReadonlyPaths': ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'],
}
_CONFIG = {
    'User': 'root', 'WorkingDir': '/opt/hermes',
    'Entrypoint': ['/opt/hermes/docker/entrypoint-dispatch.sh'], 'Cmd': ['gateway', 'run'],
    'Tty': False, 'OpenStdin': False, 'StdinOnce': False, 'AttachStdin': False,
    'AttachStdout': False, 'AttachStderr': False, 'StopSignal': None, 'StopTimeout': None,
    'ExposedPorts': None, 'Healthcheck': None, 'Domainname': '', 'Volumes': {'/opt/data': {}},
}
_ENDPOINT_GENERATED = {
    'NetworkID', 'EndpointID', 'Gateway', 'IPAddress', 'IPPrefixLen', 'IPv6Gateway',
    'GlobalIPv6Address', 'GlobalIPv6PrefixLen', 'MacAddress', 'DNSNames',
}


class ContractError(ValueError):
    """Fixed code only; never includes inspect values or environment secrets."""


def _require(value, code):
    if not value:
        raise ContractError(code)


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                          separators=(',', ':'))
    except (ValueError, TypeError):
        raise ContractError('invalid_metadata') from None


def _same(a, b):
    # JSON distinguishes true from 1, unlike Python dict equality.
    return _canonical(a) == _canonical(b)


def _mapping(value):
    _require(type(value) is dict and all(type(k) is str for k in value), 'invalid_mapping')
    return value


def environment(values):
    _require(type(values) is list and len(values) <= 256, 'invalid_environment')
    result = {}
    for item in values:
        _require(type(item) is str and len(item) <= 65536 and '=' in item and
                 not any(x in item for x in ('\r', '\n', '\0')), 'invalid_environment')
        key, value = item.split('=', 1)
        _require(_ENV_KEY.fullmatch(key) and key not in result, 'invalid_environment')
        result[key] = value
    return result


def _identity(info, expected_id):
    _mapping(info)
    _require(type(expected_id) is str and _HEX.fullmatch(expected_id), 'invalid_expected_id')
    _require(info.get('Id') == expected_id and info.get('Image') == IMAGE, 'identity_mismatch')
    return _mapping(info.get('State'))


def _networks(info):
    networks = _mapping(_mapping(info.get('NetworkSettings')).get('Networks'))
    _require(set(networks) == {'bridge'}, 'unsupported_network')
    bridge = _mapping(networks['bridge'])
    for key in ('IPAMConfig', 'Aliases', 'Links', 'DriverOpts'):
        _require(bridge.get(key) is None, 'unsupported_network')
    return {key: value for key, value in bridge.items() if key not in _ENDPOINT_GENERATED}


def validate_baseline(info, *, expected_id=OLD_ID):
    """Check only the observed fixed profile; unknown create options need review."""
    state = _identity(info, expected_id)
    _require(state.get('Running') is True and state.get('OOMKilled') is False and
             state.get('Paused') is False and state.get('Restarting') is False,
             'baseline_not_running')
    _require(info.get('Name') == '/hermes', 'baseline_name_mismatch')
    config, host = _mapping(info.get('Config')), _mapping(info.get('HostConfig'))
    for key, value in _CONFIG.items():
        _require(_same(config.get(key), value), 'unsupported_config')
    for key, value in _HOST.items():
        _require(_same(host.get(key), value), 'unsupported_host_config')
    for key, value in host.items():
        if key not in _HOST:
            _require(_canonical(value) in {'null', 'false', '0', '""', '[]', '{}'},
                     'unknown_host_option')
    _require(config.get('Hostname') == expected_id[:12] and
             config.get('Image') in {IMAGE, IMAGE_TAG}, 'unsupported_image_reference')
    env = environment(config.get('Env'))
    _require(env.get('HERMES_UID') == '995' and env.get('HERMES_GID') == '986' and
             env.get('HERMES_HOME') == '/opt/data', 'unsupported_runtime_environment')
    mounts = info.get('Mounts')
    _require(type(mounts) is list and len(mounts) == 1, 'unsupported_mount')
    mount = _mapping(mounts[0])
    wanted = {'Type': 'bind', 'Source': '/opt/hermes-data', 'Destination': '/opt/data',
              'RW': True, 'Propagation': 'rprivate'}
    _require(all(_same(mount.get(k), v) for k, v in wanted.items()), 'unsupported_mount')
    _networks(info)
    # This fingerprint is a comparison aid, not authentication or a signature.
    return {'profile': 'hermes-prestart-v1', 'container_id': expected_id,
            'fingerprint': hashlib.sha256(_canonical(info).encode()).hexdigest()}


def validate_created(baseline, candidate, *, expected_new_id, expected_name):
    """No start is permitted unless the freshly created candidate is equivalent."""
    validate_baseline(baseline)
    _require(expected_new_id != baseline['Id'], 'candidate_is_original')
    state = _identity(candidate, expected_new_id)
    _require(type(expected_name) is str and
             re.fullmatch(r'hermes-prestart-[0-9a-f]{12}', expected_name), 'invalid_candidate_name')
    _require(candidate.get('Name') == '/' + expected_name, 'candidate_name_mismatch')
    _require(_proven_stopped(state) and state.get('Status') == 'created' and
             state.get('StartedAt') == '0001-01-01T00:00:00Z', 'candidate_already_started')
    old_config = dict(baseline['Config'])
    new_config, new_host = candidate_comparison_fields(candidate)
    _require(new_config.get('Hostname') == expected_new_id[:12] and
             new_config.get('Image') == IMAGE, 'candidate_image_reference_mismatch')
    for config in (old_config, new_config):
        config.pop('Hostname', None)
        config.pop('Image', None)
        config['Env'] = environment(config.get('Env'))
    _require(_same(old_config, new_config), 'candidate_config_mismatch')
    _require(_same(baseline['HostConfig'], new_host), 'candidate_host_config_mismatch')
    _require(_same(baseline['Mounts'], candidate.get('Mounts')), 'candidate_mount_mismatch')
    _require(_same(_networks(baseline), _networks(candidate)), 'candidate_network_mismatch')
    return {'equivalent': True, 'never_started': True, 'container_id': expected_new_id}


def candidate_comparison_fields(candidate, *, started=False):
    """Map only the exact native-create defaults observed on fixed B.

    Docker CLI create sets stdout/stderr attach true and sends OOM-disable false.
    The existing detached original records false/false/null. Require the entire
    observed candidate combination before mapping for comparison. On fixed B's
    unsupported OOM-disable host, the daemon converts false to null at start.
    Only the caller's explicit post-start lifecycle path may expect that null;
    current metadata must also prove a real started running/exited process.
    Never apply to the original or modify either inspect object.
    """
    _require(candidate.get('Id') != OLD_ID, 'candidate_is_original')
    config = dict(_mapping(candidate.get('Config')))
    host = dict(_mapping(candidate.get('HostConfig')))
    _require(type(started) is bool, 'candidate_lifecycle_invalid')
    state = _mapping(candidate.get('State'))
    if started:
        stamp=state.get('StartedAt')
        _require(type(stamp) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z',stamp) and
                 stamp != '0001-01-01T00:00:00Z' and state.get('OOMKilled') is False and
                 ((state.get('Status') == 'running' and state.get('Running') is True and
                   state.get('Restarting') is False and state.get('Paused') is False and
                   state.get('Dead') is False and type(state.get('Pid')) is int and state['Pid'] > 1) or
                  (state.get('Status') == 'exited' and _proven_stopped(state) and
                   type(state.get('FinishedAt')) is str and state['FinishedAt'] not in {'','0001-01-01T00:00:00Z'})),
                 'candidate_started_metadata_unproved')
        _require('OomKillDisable' in host and host['OomKillDisable'] is None,
                 'candidate_started_oom_default_mismatch')
    else:
        _require(_proven_stopped(state) and state.get('Status') == 'created' and
                 state.get('StartedAt') == '0001-01-01T00:00:00Z', 'candidate_never_started_unproved')
        _require(host.get('OomKillDisable') is False, 'candidate_cli_defaults_mismatch')
    _require(config.get('AttachStdout') is True and config.get('AttachStderr') is True,
             'candidate_cli_defaults_mismatch')
    config['AttachStdout'] = False
    config['AttachStderr'] = False
    host['OomKillDisable'] = None
    return config, host


def _proven_stopped(state):
    return (state.get('Running') is False and state.get('Restarting') is False and
            state.get('Paused') is False and state.get('Dead') is False and
            type(state.get('Pid')) is int and state['Pid'] == 0 and
            state.get('Status') in {'created', 'exited'})


def recovery_decision(old, new, *, expected_new_id, protected_unchanged, database_ok,
                      retained_name, candidate_name):
    """Return a permitted intent only; this function never restarts or renames.

    Inspect fields must be refreshed immediately before each mutation. A returned
    intent cannot be reused after names, process state or protected data changes.
    Database writes after candidate startup are never discarded by this API.
    """
    old_state = _identity(old, OLD_ID)
    new_state = _identity(new, expected_new_id)
    _require(expected_new_id != OLD_ID, 'candidate_is_original')
    _require(type(retained_name) is str and re.fullmatch(r'hermes-retained-[0-9a-f]{12}', retained_name)
             and type(candidate_name) is str and
             re.fullmatch(r'hermes-prestart-[0-9a-f]{12}', candidate_name), 'invalid_recovery_names')
    if protected_unchanged is not True or database_ok is not True:
        return {'intent': 'manual_review', 'reason': 'protected_state_unverified'}
    if not _proven_stopped(new_state):
        return {'intent': 'manual_review', 'reason': 'candidate_stop_unproved'}
    if old.get('Name') not in {'/hermes', '/' + retained_name} or new.get('Name') not in {
            '/hermes', '/' + candidate_name} or old.get('Name') == new.get('Name'):
        return {'intent': 'manual_review', 'reason': 'name_binding_unverified'}
    if old_state.get('Running') is True and old.get('Name') == '/hermes' and \
            old_state.get('Restarting') is False and old_state.get('Paused') is False:
        return {'intent': 'keep_original', 'database_restore': False}
    if _proven_stopped(old_state):
        return {'intent': 'restore_original_name_then_start', 'database_restore': False}
    return {'intent': 'manual_review', 'reason': 'original_state_unverified'}
