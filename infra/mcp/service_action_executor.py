#!/usr/bin/env python3
"""Fixed service actions, separated from rule-file edits and arbitrary commands.

Imported only from a root-owned fixed deployment path by rule-change-executor.
No caller field becomes a command, path, Docker option, probe URL or identity.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import sys
import time
import unicodedata

REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_STATE = 512 * 1024
POLICY_VERSION = 1
PROFILES = {
    "a:vector": {
        "host": "a", "kind": "systemd-vector", "unit": "capstone-vector.service", "actions": ["restart"],
        "stop_seconds": 60, "verify_seconds": 180,
        "impact": "Host log normalization pauses during restart; no configuration, source logs or checkpoints are changed.",
        "files": ["/etc/capstone-vector/vector.toml", "/etc/capstone-vector/vector.env",
                  "/etc/capstone-vector/transforms/correlation.vrl", "/etc/capstone-vector/transforms/nftables.vrl",
                  "/etc/capstone-vector/transforms/suricata.vrl", "/etc/capstone-vector/transforms/waf_audit_context.vrl",
                  "/etc/capstone-vector/transforms/waf_json_guard.vrl"],
    },
    "a:wazuh-agent": {
        "host": "a", "kind": "systemd-agent", "unit": "wazuh-agent.service", "actions": ["restart"],
        "stop_seconds": 120, "verify_seconds": 180,
        "impact": "A host agent collection pauses during restart; the Wazuh manager is not restarted.",
        "files": ["/var/ossec/etc/ossec.conf", "/var/ossec/etc/local_internal_options.conf"],
    },
    "b:wazuh-agent": {
        "host": "b", "kind": "systemd-agent", "unit": "wazuh-agent.service", "actions": ["restart"],
        "stop_seconds": 120, "verify_seconds": 180,
        "impact": "B host agent collection pauses during restart; the Wazuh manager is not restarted.",
        "files": ["/var/ossec/etc/ossec.conf", "/var/ossec/etc/local_internal_options.conf"],
    },
    "a:waf": {
        "host": "a", "container": "waf", "kind": "nginx", "actions": ["reload", "restart"],
        "stop_seconds": 30, "verify_seconds": 90,
        "impact": "Web security proxy connections can be interrupted; DetectionOnly must remain enabled.",
        "files": ["/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf"],
        "mounts": [["/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf", "/etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf", False]],
        "probe": {"port": 80, "path": "/dvwa/login.php", "host": "localhost", "marker": "DVWA"},
    },
    "a:suricata": {
        "host": "a", "container": "suricata", "kind": "suricata", "actions": ["restart"],
        "stop_seconds": 30, "verify_seconds": 120,
        "impact": "Passive IDS detection pauses during the existing container restart; no inline transition.",
        "files": ["/home/groot_a/capstone/suricata/ruleset/GROOT_A_local.rules", "/home/groot_a/capstone/suricata/ruleset/suricata.rules", "/home/groot_a/capstone/suricata/ruleset/all.rules"],
        "mounts": [["/home/groot_a/capstone/suricata/ruleset", "/rules", False]],
    },
    "a:chatproxy": {
        "host": "a", "container": "chatproxy", "kind": "nginx", "actions": ["reload", "restart"],
        "stop_seconds": 30, "verify_seconds": 90,
        "impact": "Chat and dashboard access can be interrupted; no proxy or TLS configuration edits.",
        "files": ["/home/groot_a/capstone/chatproxy/nginx.conf"] +
                 ["/home/groot_a/capstone/chatproxy/tls/" + name for name in
                  ("chat.crt", "chat.key", "chatduck.crt", "chatduck.key", "wazuh.crt", "wazuh.key", "wazuhduck.crt", "wazuhduck.key")],
        "mounts": [["/home/groot_a/capstone/chatproxy/nginx.conf", "/etc/nginx/nginx.conf", False], ["/home/groot_a/capstone/chatproxy/tls", "/etc/nginx/tls", False]],
        "probe": {"port": 443, "path": "/api/v4/system/ping", "host": "chat.grootlab.duckdns.org", "json_status": "OK", "certificate": "/home/groot_a/capstone/chatproxy/tls/chatduck.crt"},
    },
    "b:wazuh-manager": {
        "host": "b", "container": "single-node-wazuh.manager-1", "kind": "wazuh", "actions": ["restart"],
        "stop_seconds": 60, "verify_seconds": 120,
        "impact": "SIEM collection and analysis pause; the indexer and dashboard are not restarted.",
        "files": ["/home/groot_b/capstone/wazuh/single-node/config/wazuh_cluster/wazuh_manager.conf", "/var/lib/docker/volumes/single-node_wazuh_etc/_data/ossec.conf", "/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/local_rules.xml"],
        "mounts": [["/var/lib/docker/volumes/single-node_wazuh_etc/_data", "/var/ossec/etc", True]],
    },
    "b:wazuh-dashboard": {
        "host": "b", "container": "single-node-wazuh.dashboard-1", "kind": "dashboard", "actions": ["restart"],
        "stop_seconds": 30, "verify_seconds": 120,
        "impact": "Dashboard access pauses; the manager and indexer remain unchanged.",
        "files": ["/home/groot_b/capstone/wazuh/single-node/config/wazuh_dashboard/opensearch_dashboards.yml", "/home/groot_b/capstone/wazuh/single-node/config/wazuh_dashboard/wazuh.yml", "/home/groot_b/capstone/wazuh/single-node/config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem", "/home/groot_b/capstone/wazuh/single-node/config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem"],
        "mounts": [["/home/groot_b/capstone/wazuh/single-node/config/wazuh_dashboard/opensearch_dashboards.yml", "/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml", True]],
        "probe": {"port": 443, "path": "/app/login", "host": "wazuh.grootlab.duckdns.org", "marker": "OpenSearch Dashboards", "certificate": "/home/groot_b/capstone/wazuh/single-node/config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem"},
    },
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _policy(target):
    # Bind the actual verifier/dispatcher source as well as its fixed profile.
    source = Path(__file__).read_bytes()
    return {"version": POLICY_VERSION, "profile": PROFILES[target],
            "executor_sha256": hashlib.sha256(source).hexdigest(),
            "recovery": "none; never replay an uncertain dispatched action"}


class ServiceBackend:
    def __init__(self, engine):
        self.engine = engine
        self.helper = sys.modules[type(engine).__module__]
        self.error = self.helper.RuleChangeError

    def _call(self, args, timeout=20):
        return self.engine.runner.call([self.helper.DOCKER] + args, timeout=timeout)

    def observe(self, target):
        profile = PROFILES[target]
        if profile['kind'].startswith('systemd-'):
            return self.observe_systemd(target)
        try:
            info = json.loads(self._call(["inspect", profile["container"]]))[0]
            cid = info["Id"]
            if not SHA.fullmatch(cid) or info.get("Name") != "/" + profile["container"]:
                raise self.error("service container identity mismatch")
            state = info["State"]
            if not state.get("Running") or state.get("Restarting"):
                raise self.error("service must be an existing running container")
            mounts = sorted([[m["Source"], m["Destination"], m["RW"]] for m in info["Mounts"]])
            if any(item not in mounts for item in profile["mounts"]):
                raise self.error("service mount differs from fixed profile")
            files = list(profile["files"])
            hashes = {}
            for name in files:
                data, _ = self.helper._read_regular(name, self.helper.MAX_RULESET)
                hashes[name] = hashlib.sha256(data).hexdigest()
            observed = {"container_id": cid, "image_id": info["Image"],
                        "started_at": state["StartedAt"], "running": state["Running"],
                        "health": state.get("Health", {}).get("Status", "none"),
                        "oom_killed": bool(state.get("OOMKilled")),
                        "config_sha256": digest({"config": info["Config"], "host": info["HostConfig"], "mounts": mounts}),
                        "files_sha256": digest(hashes)}
            if profile["kind"] == "nginx":
                config = self._call(["exec", cid, "nginx", "-T"], timeout=30)
                observed["nginx_config_sha256"] = hashlib.sha256(config).hexdigest()
                text = self._call(["top", cid, "-eo", "pid,ppid,args"]).decode("utf-8", "strict")
                masters, workers = [], []
                for line in text.splitlines()[1:]:
                    fields = line.split(None, 2)
                    if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
                        raise self.error("invalid nginx process observation")
                    if fields[2].startswith("nginx: master process "):
                        masters.append(int(fields[0]))
                    if fields[2] == "nginx: worker process":
                        workers.append([int(fields[0]), int(fields[1])])
                if len(masters) != 1 or not workers or any(p[1] != masters[0] for p in workers):
                    raise self.error("nginx master/worker state unavailable")
                observed["nginx_master_pid"] = masters[0]
                observed["nginx_worker_pids"] = sorted(p[0] for p in workers)
            if target == "a:waf":
                data, _ = self.helper._read_regular(profile["files"][0])
                self.helper._validate_candidate("waf", data.decode("utf-8"))
                if "MODSEC_RULE_ENGINE=DetectionOnly" not in info["Config"].get("Env", []):
                    raise self.error("WAF DetectionOnly mode is not fixed")
            if target == "a:suricata":
                spec = self.engine.spec("a:suricata-local")
                self.engine._inspect(spec)
                self.engine._snapshot(spec)
            return observed
        except (KeyError, IndexError, ValueError, UnicodeError) as exc:
            raise self.error("invalid service observation") from exc

    def observe_systemd(self, target):
        profile = PROFILES[target]
        fields = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'Type', 'InvocationID',
                  'MainPID', 'ExecMainStartTimestampMonotonic', 'FragmentPath', 'DropInPaths',
                  'NeedDaemonReload', 'Transient',
                  'TimeoutStartUSec', 'TimeoutStopUSec', 'KillMode', 'Restart')
        # Exec* properties include runtime timestamps and can contain embedded
        # newlines. Unit/drop-in bytes below bind the executable configuration.
        raw = self.engine.runner.call(['/usr/bin/systemctl', 'show', '--all', '--no-pager',
            '--property=' + ','.join(fields), profile['unit']], timeout=10).decode('utf-8', 'strict')
        rows = [line.split('=', 1) for line in raw.splitlines()]
        if any(len(row) != 2 for row in rows) or len({row[0] for row in rows}) != len(rows):
            raise self.error('invalid systemd observation')
        p = dict(rows)
        if (set(p) != set(fields) or p['Id'] != profile['unit'] or p['LoadState'] != 'loaded'
                or p['Transient'] != 'no' or p['NeedDaemonReload'] != 'no'
                or p['ActiveState'] not in ('active', 'inactive', 'failed')
                or not re.fullmatch(r'[a-z][a-z-]{0,47}', p['SubState'])
                or not re.fullmatch(r'[a-z][a-z-]{0,47}', p['Result'])
                or not re.fullmatch(r'[0-9a-f]{32}|', p['InvocationID'])
                or any(not re.fullmatch(r'[0-9]{1,20}', p[k]) for k in ('MainPID','ExecMainStartTimestampMonotonic'))):
            raise self.error('systemd unit unavailable, transitional, or needs daemon reload')
        paths = [p['FragmentPath']] + p['DropInPaths'].split()
        if not paths[0] or len(paths) > 33 or any(not re.fullmatch(
                r'/(?:etc|run|usr/lib|lib)/systemd/system/[A-Za-z0-9_.@/-]+', name) for name in paths):
            raise self.error('systemd unit paths outside fixed roots')
        hashes = {}
        for name in paths + profile['files']:
            data, meta = self.helper._read_regular(name, 4 * 1024 * 1024)
            if meta.st_uid != 0 or meta.st_mode & (0o022 if name in paths else 0o002):
                raise self.error('systemd configuration must be root owned and not world writable')
            hashes[name] = hashlib.sha256(data).hexdigest()
        immutable = {k:p[k] for k in fields if k not in ('ActiveState','SubState','Result','InvocationID','MainPID','ExecMainStartTimestampMonotonic')}
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        if not re.fullmatch(r'[0-9a-f-]{36}', boot): raise self.error('boot identity unavailable')
        return {'runtime_kind':'systemd', 'unit':p['Id'], 'boot_id':boot,
            'active_state':p['ActiveState'], 'sub_state':p['SubState'], 'result':p['Result'],
            'running':p['ActiveState']=='active' and p['SubState']=='running',
            'invocation_id':p['InvocationID'], 'main_pid':int(p['MainPID']),
            'start_monotonic_us':int(p['ExecMainStartTimestampMonotonic']),
            'config_sha256':digest(immutable), 'files_sha256':digest(hashes)}

    def preflight_systemd(self, target):
        profile = PROFILES[target]
        if profile['kind'] == 'systemd-vector':
            # Only three path variables from the fixed root-owned environment
            # file are passed. No shell source/eval or arbitrary environment.
            raw, _ = self.helper._read_regular('/etc/capstone-vector/vector.env', 65536)
            values = {}
            for line in raw.decode().splitlines():
                if not line.strip() or line.lstrip().startswith('#'): continue
                key, sep, value = line.partition('=')
                if key in ('SURICATA_EVE_PATH','WAF_AUDIT_PATH','WAF_ACCESS_PATH'):
                    value = value.strip().strip('\"\'')
                    if not sep or key in values or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,240}', value):
                        raise self.error('invalid Vector path environment')
                    values[key] = value
            if len(values) != 3: raise self.error('Vector path environment incomplete')
            argv = ['/usr/bin/env','-C','/etc/capstone-vector','-i','PATH=/usr/bin:/bin',
                    'VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true', 'INVOCATION_ID='+'0'*32]
            argv += [k+'='+v for k,v in sorted(values.items())]
            argv += ['/usr/local/bin/vector','validate','--no-environment','/etc/capstone-vector/vector.toml']
            self.engine.runner.call(argv, timeout=45)
        else:
            for binary in ('wazuh-agentd','wazuh-logcollector','wazuh-syscheckd','wazuh-modulesd'):
                self.engine.runner.call(['/var/ossec/bin/'+binary,'-t'], timeout=30)

    def verify_systemd(self, target, before):
        after = self.observe_systemd(target)
        if (any(after[k] != before[k] for k in ('unit','boot_id','config_sha256','files_sha256'))
                or not after['running'] or after['result'] != 'success'
                or not after['invocation_id'] or after['invocation_id'] == before['invocation_id']):
            raise self.error('systemd restart identity, configuration or readiness not verified')
        if PROFILES[target]['kind'] == 'systemd-vector':
            pid = after['main_pid']
            if pid <= 0 or Path('/proc/'+str(pid)+'/exe').resolve() != Path('/usr/local/bin/vector').resolve():
                raise self.error('Vector executable not verified')
            fd = os.open('/var/log/capstone-vector/telemetry/health.jsonl', os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as f:
                meta = os.fstat(f.fileno())
                if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1
                        or meta.st_mode & 0o022): raise self.error('Vector telemetry unavailable')
                offset = max(0,meta.st_size-1048576)
                f.seek(offset); lines=f.read(1048576).splitlines()
                if offset: lines = lines[1:]
            matching = []
            for line in lines:
                try: item=json.loads(line)['capstone_collection_health']
                except (ValueError,KeyError,TypeError): continue
                if not isinstance(item,dict): continue
                if (item.get('metric')=='uptime_seconds' and str(item.get('vector_pid'))==str(pid)
                        and item.get('invocation_id')==after['invocation_id']
                        and type(item.get('observed_unix')) in (int,float)):
                    matching.append(item['observed_unix'])
            if not matching or not -5 <= self.engine.clock()-max(matching) <= 30:
                raise self.error('Vector fresh invocation telemetry unavailable')
        else:
            # Wazuh forking units can legitimately report MainPID=0. Verify
            # actual host executables and a fresh post-dispatch connection state.
            for name in ('wazuh-agentd','wazuh-logcollector'):
                raw = self.engine.runner.call(['/usr/bin/pgrep','-x',name[:15]], timeout=5).decode()
                pids = raw.split()
                if len(pids)>128 or any(not p.isdecimal() for p in pids): raise self.error('agent PID evidence invalid')
                found = [p for p in pids if Path('/proc/'+p+'/exe').resolve() == Path('/var/ossec/bin/'+name).resolve()]
                if len(found)!=1: raise self.error('agent host processes unavailable')
            state, meta = self.helper._read_regular('/var/ossec/var/run/wazuh-agentd.state',65536)
            if self.engine.clock()-meta.st_mtime > 30 or not re.search(rb"(?m)^status=['\"]?connected['\"]?\s*$",state):
                raise self.error('agent connection not verified')
        return after

    def preflight(self, target, observation):
        if PROFILES[target]['kind'].startswith('systemd-'):
            return self.preflight_systemd(target)
        kind, cid = PROFILES[target]["kind"], observation["container_id"]
        if kind == "nginx":
            self._call(["exec", cid, "nginx", "-t"], timeout=30)
        elif kind == "suricata":
            self._call(["exec", cid, "suricata", "-T", "-S", "/rules/all.rules"], timeout=180)
        elif kind == "wazuh":
            self._call(["exec", cid, "/var/ossec/bin/wazuh-analysisd", "-t"], timeout=60)

    def dispatch(self, target, action, before):
        if PROFILES[target]['kind'].startswith('systemd-'):
            if action != 'restart': raise self.error('systemd action not allowlisted')
            return self.engine.runner.call(['/usr/bin/systemctl','--no-block','restart',PROFILES[target]['unit']],timeout=10)
        cid = before["container_id"]
        if action == "reload":
            self._call(["exec", cid, "nginx", "-s", "reload"], timeout=30)
        else:
            grace = PROFILES[target]["stop_seconds"]
            self._call(["restart", "--time", str(grace), cid], timeout=grace + 30)

    def _http_probe(self, probe):
        # Fixed loopback only. HTTPS authenticates the peer against the exact
        # current certificate file before sending the application request.
        if "certificate" in probe:
            pem, _ = self.helper._read_regular(probe["certificate"], 256 * 1024)
            match = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
            if not match:
                raise self.error("health probe certificate unavailable")
            expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(match.group().decode("ascii"))).digest()
        connection = http.client.HTTPConnection("127.0.0.1", probe["port"], timeout=5)
        try:
            if "certificate" in probe:
                raw_socket = socket.create_connection(("127.0.0.1", probe["port"]), timeout=5)
                try:
                    connection.sock = ssl._create_unverified_context().wrap_socket(raw_socket, server_hostname=probe["host"])
                except Exception:
                    raw_socket.close()
                    raise
            else:
                connection.connect()
            if "certificate" in probe and not hmac.compare_digest(
                    hashlib.sha256(connection.sock.getpeercert(binary_form=True)).digest(), expected):
                raise self.error("health probe TLS certificate pin mismatch")
            connection.request("GET", probe["path"], headers={"Host": probe["host"], "Connection": "close"})
            response = connection.getresponse()
            body = response.read(256 * 1024 + 1)
            if response.status != 200 or len(body) > 256 * 1024:
                raise self.error("service application health endpoint is not ready")
            if "json_status" in probe and json.loads(body).get("status") != probe["json_status"]:
                raise self.error("service application status is not ready")
            if "marker" in probe and probe["marker"].encode("utf-8") not in body:
                raise self.error("service application response marker is missing")
        finally:
            connection.close()

    def verify(self, target, action, before, dispatched_at):
        profile = PROFILES[target]
        if profile['kind'].startswith('systemd-'):
            after = self.verify_systemd(target, before)
            if profile['kind']=='systemd-agent':
                _, meta = self.helper._read_regular('/var/ossec/var/run/wazuh-agentd.state',65536)
                if meta.st_mtime < dispatched_at: raise self.error('agent connection evidence predates dispatch')
            return after
        after = self.observe(target)
        for key in ("container_id", "image_id", "config_sha256", "files_sha256", "nginx_config_sha256"):
            if after.get(key) != before.get(key):
                raise self.error("service identity or configuration changed during the action")
        if action == "restart":
            old = datetime.fromisoformat(before["started_at"].replace("Z", "+00:00"))
            new = datetime.fromisoformat(after["started_at"].replace("Z", "+00:00"))
            if new <= old or not dispatched_at - 1 <= new.timestamp() <= self.engine.clock() + 5:
                raise self.error("service has no new restart timestamp")
        else:
            if after["started_at"] != before["started_at"] or after["nginx_master_pid"] != before["nginx_master_pid"]:
                raise self.error("reload unexpectedly restarted the service")
            if not set(after["nginx_worker_pids"]) - set(before["nginx_worker_pids"]):
                raise self.error("nginx has no newly loaded worker generation")
        if profile["kind"] == "suricata":
            spec = self.engine.spec("a:suricata-local")
            runtime = self.engine._inspect(spec)
            stats = self.engine._suricata_socket("ruleset-stats", 10)
            if any(type(stats.get(key)) is not int or stats[key] < 0 for key in
                   ("rules_loaded", "rules_failed", "rules_skipped")) or not stats["rules_loaded"] or stats["rules_failed"] or stats["rules_skipped"]:
                raise self.error("Suricata rules are absent, failed or skipped")
            loaded = self.engine._suricata_time(self.engine._suricata_socket("ruleset-reload-time", 10).get("last_reload"))
            started = self.engine._suricata_time(runtime["started_at"])
            if runtime["container_id"] != after["container_id"] or runtime["started_at"] != after["started_at"] or not started <= loaded <= self.engine.clock() + 5:
                raise self.error("Suricata active rule load is stale or inconsistent")
        elif profile["kind"] == "wazuh":
            text = self._call(["exec", after["container_id"], "/var/ossec/bin/wazuh-control", "status"]).decode()
            for process in ("wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-apid"):
                if process + " is running..." not in text.splitlines():
                    raise self.error("Wazuh core process is not ready")
        if "probe" in profile:
            self._http_probe(profile["probe"])
        if after["health"] not in ("none", "healthy") or after["oom_killed"]:
            raise self.error("service Docker health is not ready")
        return after


class ServiceActionService:
    def __init__(self, engine, backend=None):
        self.engine = engine
        self.helper = sys.modules[type(engine).__module__]
        self.error = self.helper.RuleChangeError
        self.backend = backend or ServiceBackend(engine)
        self.state_dir = engine.state_dir / "services"
        if not getattr(engine, "read_only", False):
            self.state_dir.mkdir(mode=0o700, exist_ok=True)
        st = self.state_dir.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise self.error("service state directory must be owned by executor and mode 0700")

    def _profile(self, target, action=None):
        if not isinstance(target, str) or target not in PROFILES or PROFILES[target]["host"] != self.engine.host:
            raise self.error("service target is not allowlisted on this host")
        profile = PROFILES[target]
        if action is not None and action not in profile["actions"]:
            raise self.error("service action is not allowlisted")
        return profile

    def _path(self, request_id):
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise self.error("invalid operation request ID")
        return self.state_dir / (request_id + ".json")

    def _save(self, record):
        data = canonical(record)
        if len(data) > MAX_STATE:
            raise self.error("service operation state too large")
        self.helper._atomic_bytes(self._path(record["request_id"]), data, mode=0o600)

    def _load(self, request_id):
        data, _ = self.helper._read_regular(self._path(request_id), MAX_STATE)
        record = json.loads(data)
        if record.get("request_id") != request_id:
            raise self.error("service operation state identity mismatch")
        return record

    def _public(self, record):
        return {key: record[key] for key in ("request_id", "target", "action", "status", "plan_sha256", "proposal_digest", "result", "result_posted")}

    def get_target(self, target):
        profile = self._profile(target)
        with self.engine.locked():
            observation = self.backend.observe(target)
            result = {"target": target, "allowed_actions": profile["actions"], "observation": observation,
                    "base_state_sha256": digest(observation), "policy_sha256": digest(_policy(target)),
                    "impact": profile["impact"], "automatic_recovery": "none",
                    "restart_grace_seconds": profile["stop_seconds"],
                    "restart_timeout_effect": "Docker may SIGKILL after the fixed graceful-stop interval"}
            if profile['kind'].startswith('systemd-'):
                result['restart_grace_seconds'] = None
                result['restart_timeout_effect'] = 'Existing systemd unit timeouts apply; no timeout or kill policy is changed. Worker verifies one queued restart only.'
        if profile["kind"] == "suricata":
            # Reuse the canonical reader after releasing the workflow lock.
            # Approval still binds only the original observation, unchanged.
            try:
                evidence = self.engine.get_target("a:suricata-local")["runtime"]
                if evidence.get("container_id") != observation["container_id"]:
                    raise self.error("container changed between read observations")
                result["rule_source_evidence"] = evidence
            except (OSError, self.error):
                result["rule_source_evidence"] = {"status": "unavailable",
                    "evidence_scope": "rule source not verified; do not infer its path or loading failure"}
            result["rule_engine_evidence"] = self._rule_engine_evidence(observation)
        return result

    def _rule_engine_evidence(self, observation):
        """Read counters without changing the approval-bound service snapshot.

        A reload on either side of the counter read or a container restart
        invalidates this receipt. Counts do not identify individual loaded SIDs
        or prove that current disk bytes are the engine's loaded generation.
        """
        kst = timezone(timedelta(hours=9))
        result = {"status": "unavailable", "scope": "single_tenant_engine_counters",
                  "per_sid_load_verified": False, "current_file_load_verified": False}
        try:
            with self.engine.locked():
                spec = self.engine.spec("a:suricata-local")
                before = self.engine._inspect(spec, timeout=5)
                first = self.engine._suricata_socket("ruleset-reload-time", 5).get("last_reload")
                stats = self.engine._suricata_socket("ruleset-stats", 5)
                last = self.engine._suricata_socket("ruleset-reload-time", 5).get("last_reload")
                after = self.engine._inspect(spec, timeout=5)
                loaded = self.engine._suricata_time(first)
                now = self.engine.clock()
                keys = ("rules_loaded", "rules_failed", "rules_skipped")
                if (any(type(stats.get(key)) is not int or stats[key] < 0 for key in keys)
                        or loaded != self.engine._suricata_time(last)
                        or not self.engine._suricata_time(before["started_at"]) <= loaded <= now + 5
                        or any(before.get(key) != after.get(key) or before.get(key) != observation.get(key)
                               for key in ("container_id", "started_at"))):
                    raise self.error("inconsistent Suricata counter observation")
                result.update(status="observed", **{key: stats[key] for key in keys},
                              last_reload_kst=datetime.fromtimestamp(loaded, kst).isoformat(),
                              container_id=before["container_id"])
        except (OSError, self.error, ValueError, KeyError, TypeError):
            result["reason"] = "runtime_counter_unavailable_or_inconsistent"
        result["observed_at_kst"] = datetime.fromtimestamp(self.engine.clock(), kst).isoformat()
        return result

    def _post(self, record):
        answer = self.engine.broker.request("POST", "/operations", record["proposal"])
        self._binding(record, answer)
        if not answer.get("posted"):
            raise self.error("operation approval card was not posted")
        record["status"] = "pending"
        self._save(record)

    def _binding(self, record, answer):
        for key, expected in (("request_id", record["request_id"]), ("plan_sha256", record["plan_sha256"]),
                              ("proposal_digest", record["proposal_digest"]),
                              ("kind", "service"), ("target", record["target"]),
                              ("before_observation_sha256", record["proposal"]["plan"]["before_observation_sha256"]),
                              ("expires_at", record["proposal"]["expires_at"])):
            if answer.get(key) != expected:
                raise self.error("service broker binding mismatch")

    def propose(self, target, action, base_state_sha256, reason):
        self._profile(target, action)
        if not isinstance(base_state_sha256, str) or not SHA.fullmatch(base_state_sha256):
            raise self.error("base_state_sha256 must come from service target retrieval")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 200 or len(reason.encode("utf-8")) > 500 or any(
                unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs") for c in reason):
            raise self.error("service reason must be 1..200 printable characters")
        with self.engine.locked():
            before = self.backend.observe(target)
            if digest(before) != base_state_sha256:
                raise self.error("service changed since retrieval; fetch current state and retry")
            self.backend.preflight(target, before)
            if self.backend.observe(target) != before:
                raise self.error("service changed during preflight")
            summary = ("unit=%s; active=%s; sub=%s; invocation=%s" %
                (before['unit'],before['active_state'],before['sub_state'],before['invocation_id'])) if before.get('runtime_kind')=='systemd' else (
                "container=%s; started=%s; running=%s; health=%s" %
                (before['container_id'][:12],before['started_at'],before['running'],before['health']))
            plan = {"action": action, "before_observation_sha256": base_state_sha256,
                    "policy_sha256": digest(_policy(target)), "reason": reason.strip(),
                    "before_summary": summary}
            active = 0
            for path in self.state_dir.glob("*.json"):
                old = self._load(path.stem)
                if old["status"] in ("posting", "pending", "prepared", "executing"):
                    active += 1
                    if old["target"] == target and old["proposal"]["plan"] == plan:
                        if old["status"] == "posting":
                            self._post(old)
                        return self._public(old)
            if active >= 32:
                raise self.error("too many active service proposals")
            request_id = secrets.token_hex(16)
            proposal = {"request_id": request_id, "kind": "service", "target": target, "plan": plan,
                        "plan_sha256": digest(plan), "requested_by": "hermes-service-action",
                        "expires_at": int(self.engine.clock()) + 600}
            record = {"request_id": request_id, "target": target, "action": action,
                      "proposal": proposal, "plan_sha256": proposal["plan_sha256"],
                      "proposal_digest": digest(proposal), "before": before,
                      "status": "posting", "result": "", "result_posted": False}
            self._save(record)  # Same id and exact payload survive a lost POST response.
            self._post(record)
            return self._public(record)

    def _validate_record(self, record):
        proposal = record["proposal"]
        self._profile(record["target"], record["action"])
        if (proposal["request_id"] != record["request_id"] or proposal["kind"] != "service" or
                proposal["target"] != record["target"] or proposal["plan"]["action"] != record["action"] or
                digest(proposal) != record["proposal_digest"] or digest(proposal["plan"]) != record["plan_sha256"] or
                proposal["plan_sha256"] != record["plan_sha256"] or
                digest(record["before"]) != proposal["plan"]["before_observation_sha256"] or
                digest(_policy(record["target"])) != proposal["plan"]["policy_sha256"]):
            raise self.error("service plan, state, or executor policy changed")

    def _decision(self, record):
        self._validate_record(record)
        answer = self.engine.broker.request("GET", "/operations/" + record["request_id"])
        self._binding(record, answer)
        if answer.get("kind") != "service" or answer.get("target") != record["target"]:
            raise self.error("operation kind or target binding mismatch")
        if answer.get("status") not in ("pending", "approved", "denied", "expired", "consumed", "applied", "failed", "aborted"):
            raise self.error("invalid operation decision")
        return answer

    def _finish(self, record, status, detail, after=None):
        if after is None:
            try:
                after = self.backend.observe(record["target"])
            except Exception:
                after = {"available": False, "target": record["target"]}
        record["status"], record["result"] = status, detail
        record["after"] = after
        record["result_payload"] = {"proposal_digest": record["proposal_digest"], "status": status,
                                    "after_observation_sha256": digest(after), "detail": detail}
        self._save(record)
        self._post_result(record)

    def _post_result(self, record):
        if record["result_posted"]:
            return
        try:
            answer = self.engine.broker.request("POST", "/operations/" + record["request_id"] + "/result", record["result_payload"])
            self._binding(record, answer)
            if not answer.get("result_posted") or answer.get("status") != record["status"] or answer.get("after_observation_sha256") != record["result_payload"]["after_observation_sha256"]:
                raise self.error("operation result was not posted")
            record["result_posted"] = True
            self._save(record)
        except (self.error, OSError):
            pass  # Retry reporting only. The action is never repeated.

    def _execute(self, record):
        target, action, before = record["target"], record["action"], record["before"]
        try:
            self._validate_record(record)
            if self.backend.observe(target) != before:
                raise self.error("service state changed before execution")
            self.backend.preflight(target, before)
            if self.backend.observe(target) != before:
                raise self.error("service changed during final preflight")
            if int(self.engine.clock()) >= record["proposal"]["expires_at"]:
                raise self.error("approval expired during preflight")
        except Exception:
            self._finish(record, "aborted", "Approved service preconditions changed; no action was dispatched")
            return
        record["status"] = "prepared"
        self._save(record)
        answer = self.engine.broker.request("POST", "/operations/" + record["request_id"] + "/consume",
                                            {"proposal_digest": record["proposal_digest"]})
        self._binding(record, answer)
        if answer.get("status") != "consumed" or answer.get("consumed_decision") != "approve":
            raise self.error("service approval consume was not confirmed")
        record["status"] = "executing"
        record["dispatch_started_at"] = self.engine.clock()
        self._save(record)  # Durable intent before exactly one dispatch.
        try:
            # CAS once more after the network round trip. No fallback restart.
            if self.backend.observe(target) != before:
                raise self.error("service changed after approval consumption")
            self.backend.dispatch(target, action, before)
            deadline = time.monotonic() + PROFILES[target]["verify_seconds"]
            while True:
                try:
                    after = self.backend.verify(target, action, before, record["dispatch_started_at"])
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise self.error("service readiness verification timed out")
                    time.sleep(min(2, max(0, deadline - time.monotonic())))
        except Exception:
            self._finish(record, "failed", "Service action or verification failed; no automatic retry or fallback was attempted")
            return
        self._finish(record, "applied", "Approved service action completed once and runtime checks passed", after)

    def worker_once(self):
        results = []
        with self.engine.locked():
            for path in sorted(self.state_dir.glob("*.json")):
                record = self._load(path.stem)
                try:
                    if record["status"] in ("applied", "failed", "aborted"):
                        self._post_result(record)
                        continue
                    if record["status"] in ("denied", "expired"):
                        continue
                    expired = int(self.engine.clock()) >= record["proposal"]["expires_at"]
                    if record["status"] in ("posting", "pending") and expired:
                        record["status"] = "expired"
                        record["result"] = "Local approval deadline elapsed; no action was dispatched"
                        self._save(record)
                    elif record["status"] == "prepared" and expired:
                        self._finish(record, "failed", "Approval consumption outcome could not be confirmed before expiry; no dispatch or replay")
                    elif record["status"] == "executing":
                        # A crash can occur after intent but before/after the
                        # command. Never dispatch again or claim causality.
                        self._finish(record, "failed", "Interrupted dispatch outcome is uncertain; no automatic replay; inspect runtime before a new approval")
                    elif record["status"] == "posting":
                        self._post(record)
                    else:
                        decision = self._decision(record)
                        if decision["status"] in ("denied", "expired"):
                            record["status"] = decision["status"]
                            self._save(record)
                        elif decision["status"] == "consumed":
                            self._finish(record, "failed", "Approval was already consumed; no automatic dispatch or replay")
                        elif decision["status"] == "approved":
                            if int(self.engine.clock()) >= record["proposal"]["expires_at"]:
                                self._finish(record, "aborted", "Approval expired; no action was dispatched")
                            elif record["status"] == "prepared":
                                # A definitive approved GET means a previous
                                # consume did not commit; the CAS runs again.
                                self._execute(record)
                            else:
                                self._execute(record)
                except (self.error, OSError, KeyError, ValueError):
                    # An unavailable broker cannot authorize a command. Keep
                    # the durable phase so a consumed/uncertain action cannot replay.
                    record["result"] = "Operation validation or broker unavailable; no additional action dispatched"
                    self._save(record)
                results.append(self._public(record))
        return results

    def status(self, request_id):
        with self.engine.locked():
            record = self._load(request_id)
            out = self._public(record)
            if record["status"] in ("pending", "prepared"):
                try:
                    out["approval_status"] = self._decision(record)["status"]
                except self.error:
                    out["approval_status"] = "unavailable"
            if "after" in record:
                out["after_observation"] = record["after"]
                out["after_observation_sha256"] = digest(record["after"])
            return out
