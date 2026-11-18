#!/usr/bin/env python3
"""Opt-in native systemd proof on owned units and a C filesystem fixture.

No production unit, source, cache, account, Docker object or approval is used.
Names/paths, the diagnostic group and ExecStart are translated for the fixture;
this is not the production root entry point or Lifecycle.recover acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
       "PYTHONDONTWRITEBYTECODE": "1"}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load(name):
    spec = importlib.util.spec_from_file_location("owned_native_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_new(path, raw, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def wait_for(predicate, seconds=20):
    end = time.monotonic() + seconds
    while not predicate():
        require(time.monotonic() < end, "bounded native observation expired")
        time.sleep(0.1)


class OwnedManager:
    """Explicit fixture translation; never installed in production modules."""
    def __init__(self, root, names):
        self.root = root
        self.prefix = root.name + "-"
        self.names = {name: self.prefix + name for name in names}
        self.calls = []

    def command(self, args, timeout=15, check=True):
        require(args and args[0] == "/usr/bin/systemctl", "unexpected program")
        require(args[1] in ("show", "start", "stop", "enable", "disable", "daemon-reload", "reset-failed"), "unexpected verb")
        if args[1] != "daemon-reload":
            require(any(arg in self.names.values() for arg in args[2:]), "foreign unit rejected")
            require(all(not arg.endswith((".service", ".timer")) or arg in self.names.values() for arg in args[2:]), "foreign unit rejected")
        self.calls.append(list(args))
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=ENV, timeout=timeout)
        require(len(result.stdout) <= 65536 and len(result.stderr) <= 65536, "oversized manager reply")
        if check:
            require(result.returncode == 0, "owned systemctl failed: " + args[1] + ": " + result.stderr.decode(errors="replace")[:256])
        return result

    def __call__(self, args, *, timeout):
        translated = [self.names.get(arg, arg) for arg in args]
        if args[1] in ("enable", "disable"):
            translated.insert(2, "--runtime")
        result = self.command(translated, timeout)
        raw = result.stdout
        if args[1] == "show":
            text = raw.decode()
            for original, actual in sorted(self.names.items(), key=lambda item: len(item[1]), reverse=True):
                text = text.replace(actual, original)
            text = text.replace("/run/systemd/system/", "/etc/systemd/system/")
            text = text.replace("UnitFileState=enabled-runtime", "UnitFileState=enabled")
            raw = text.encode()
        return subprocess.CompletedProcess(args, result.returncode, raw, result.stderr)


CALLBACK = r'''import importlib.util,json,os,pathlib,sys,time
root=pathlib.Path(sys.argv[1]);operation=sys.argv[2]
assert root.parent==pathlib.Path('/run') and root.name.startswith('capstone-coordinator-')
if operation=='status':
    while True:time.sleep(1)
assert operation in ('apply','recover')
config=json.loads((root/'fixture.json').read_text())
spec=importlib.util.spec_from_file_location('owned_files',root/'code/release_files.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fs=m.FileSet('c',config['release_id'],config['rows'],0,filesystem_root=root/'fixture')
def save(name,value):
    path=root/name
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w')as stream:
        json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
if operation=='apply':
    replace=fs.replace;seen=[]
    def interrupted(row,data,expected):
        if len(seen)==2:
            save('controller-lost.json',{'pid':os.getpid(),'at_monotonic_ns':time.monotonic_ns(),'replaced':seen})
            os._exit(23)
        replace(row,data,expected);seen.append(row['target'])
    fs.replace=interrupted;fs.apply();raise AssertionError('interruption was not reached')
if not (root/'controller-lost.json').exists() or (root/'recovered.json').exists():sys.exit(75)
changed=fs.restore_core()
for row in fs.rows:
    raw,_=fs.read_target(row)
    expected=row['after_sha256']if row['target']in m.BARRIERS['c']else row['before_sha256']
    assert (m.sha(raw)if raw is not None else None)==expected
save('recovered.json',{'pid':os.getpid(),'at_monotonic_ns':time.monotonic_ns(),'changed':changed,
                      'core_restored':True,'reader_barrier_preserved':True,'fixture':True})
'''


def validate():
    require(sys.platform == "linux" and os.getuid() == os.geteuid() == 0, "Linux root required for owned-unit proof")
    require(Path("/run/systemd/system").is_dir(), "native system manager required")
    manifest = json.loads((HERE / "coordinator-manifest.json").read_text())
    witness_raw = (HERE / "witness-manifest.json").read_bytes()
    require(sha(witness_raw) == manifest["witness_manifest_sha256"], "frozen witness manifest changed")
    witness = json.loads(witness_raw)
    pins = {**witness["source_sha256"], **manifest["dependencies_sha256"], **manifest["source_sha256"]}
    require(all(sha((HERE / name).read_bytes()) == digest for name, digest in pins.items()), "frozen candidate changed")
    files, controls, native, helpers = [load(name) for name in
                                      ("release_files", "release_controls", "release_services", "release_helpers")]
    root = Path(tempfile.mkdtemp(prefix="capstone-coordinator-", dir="/run"))
    os.chmod(root, 0o700)
    report = {"schema": 1, "scope": "owned_system_manager_and_C_filesystem_fixture",
              "production_root_entry": False, "lifecycle_recover": False,
              "production_unit_changes": 0, "production_source_cache_changes": 0,
              "actual_reboot": False, "attacks": 0, "model_calls": 0,
              "candidate_pins_verified": len(pins), "checks": [], "cleanup": {},
              "translations": ["owned unit names", "fixture file paths", "Group=root",
                               "synthetic ExecStart", "enable/disable --runtime",
                               "fixture root as additional ReadWritePaths for synthetic receipts",
                               "show identity/path and enabled-runtime normalization"]}
    installed = {}
    backend = None
    result = None
    try:
        fixture = root / "fixture"
        fixture.mkdir(mode=0o700)
        release_id = uuid.uuid4().hex
        rows, after = [], {}
        for target in sorted(files.TARGETS["c"]):
            before = None if target in files.contract.OPTIONAL else ("synthetic before " + target + "\n").encode()
            candidate = ("synthetic candidate " + target + "\n").encode()
            mode = 0o550 if target == files.READER else 0o644
            rows.append({"target": target, "before_sha256": sha(before) if before else None,
                         "after_sha256": sha(candidate), "uid": 0, "gid": 0, "mode": mode})
            path = fixture / target.lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            if before:
                write_new(path, before, mode)
            after[target] = candidate
        storage = fixture / files.contract.BASE.relative_to("/") / release_id / "c"
        storage.mkdir(parents=True, mode=0o700)
        for name in ("candidates", "backups"):
            (storage / name).mkdir(mode=0o700)
        fs = files.FileSet("c", release_id, rows, 0, filesystem_root=fixture)
        for raw in after.values():
            fs.put("candidates", raw)
        fs.backup()
        plan_sha = sha(files.contract.canonical(rows))
        for name in ("release_status.py", "release_atomic.py", "release_files.py"):
            write_new(root / "code" / name, (HERE / name).read_bytes())
        write_new(root / "fixture.json", json.dumps({"release_id": release_id, "rows": rows}).encode())
        write_new(root / "callback.py", CALLBACK.encode())
        for directory in ("var/lib/capstone-diagnostics", "opt/capstone-diagnostics"):
            (fixture / directory).mkdir(parents=True, exist_ok=True)
        control = controls.Files(fs, plan_sha)
        control.install()
        names = set(native.Native("c", None, filesystem_root=fixture, runner=lambda *a, **k: None).units)
        names |= {controls.STATUS, controls.WATCH, controls.TIMER, controls.RUNNER}
        names |= {helpers.Manager.instance(op) for op in helpers.OPERATIONS}
        backend = OwnedManager(root, names)
        actual = backend.names
        callback = "/usr/bin/python3 -IB " + str(root / "callback.py") + " " + str(root)

        def translate(raw):
            text = raw.decode()
            for old, new in sorted(actual.items(), key=lambda item: len(item[0]), reverse=True):
                text = text.replace(old, new)
            text = text.replace("Group=capstone-diagnostics", "Group=root")
            text = text.replace("RuntimeDirectory=capstone-journal-release-status", "RuntimeDirectory=" + root.name + "-status")
            text = text.replace("/run/capstone-journal-release-status", "/run/" + root.name + "-status")
            for old in ("/var/lib/capstone-journal-release", "/var/lib/capstone-diagnostics", "/opt/capstone-diagnostics", "/etc/systemd/system"):
                text = text.replace(old, str(fixture / old.lstrip("/")))
            lines = []
            for line in text.splitlines():
                if line.startswith("ExecStart="):
                    operation = "status" if "release_status.py" in line else "recover" if line.endswith("recover") else "%i"
                    line = "ExecStart=" + callback + " " + operation
                lines.append(line)
            if any(line.startswith("ReadWritePaths=") for line in lines):
                lines.append("ReadWritePaths=" + str(root))
            return ("\n".join(lines) + "\n").encode()

        def install(path, raw):
            require(path.is_relative_to(Path("/run/systemd/system")) and
                    (path.name.startswith(root.name + "-") or
                     path.parent.name.startswith(root.name + "-") and path.name in (controls.DROPIN, "30-inventory-netlink.conf")), "unit path scope")
            write_new(path, raw, 0o644)
            installed[path] = raw

        for name in sorted(native.catalog("c")["collection_services"]):
            reader = name == "capstone-journal-reader.service"
            timeout = "150s" if name == native.OPTIONAL else "85s"
            raw = ("[Unit]\nDescription=Owned synthetic coordinator proof\n[Service]\nType=" + ("simple" if reader else "oneshot") +
                   "\nExecStart=" + callback + (" status" if reader else " recover") +
                   "\nUser=root\nUMask=0077\nProtectSystem=strict\nReadWritePaths=" + str(root) +
                   "\nNoNewPrivileges=yes\nPrivateTmp=yes\nMemoryAccounting=yes\nTasksAccounting=yes\nMemoryHigh=" + ("96M" if reader else "192M") + "\nMemoryMax=" +
                   ("128M" if reader else "256M") + "\nMemorySwapMax=0\nTasksMax=" + ("8" if reader else "64") +
                   "\nLimitNOFILE=1024\nKillMode=control-group\nTimeoutStopSec=5s\nTimeoutStartSec=" + timeout + "\nSuccessExitStatus=75\n").encode()
            install(Path("/run/systemd/system") / actual[name], raw)
        collection_timer = "capstone-system-diagnostics.timer"
        install(Path("/run/systemd/system") / actual[collection_timer],
                ("[Unit]\nDescription=Owned inactive collection schedule\n[Timer]\nOnActiveSec=1h\nUnit=" + actual["capstone-system-diagnostics.service"] +
                 "\n[Install]\nWantedBy=timers.target\n").encode())
        for path, raw in control.docs.items():
            if path.name == controls.DROPIN:
                original = path.parent.name[:-2]
                actual_path = Path("/run/systemd/system") / (actual[original] + ".d") / controls.DROPIN
            else:
                actual_path = Path("/run/systemd/system") / actual[path.name]
            install(actual_path, translate(raw))
        # The fixed baseline already includes this drop-in on the real hosts.
        # It has no traffic or kernel effect for the synthetic service.
        install(Path("/run/systemd/system") / (actual["capstone-system-diagnostics.service"] + ".d") /
                "30-inventory-netlink.conf", b"[Service]\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n")
        backend.command(["/usr/bin/systemctl", "daemon-reload"])
        manager = helpers.Manager(fs, plan_sha, runner=backend)
        device = native.Native("c", None, filesystem_root=fixture, runner=backend)
        report["collection_loaded"] = device.snapshot()
        device.collection_resources()
        report["checks"].append("native_collection_resource_contract")
        backend.command(["/usr/bin/systemctl", "start", actual["capstone-journal-reader.service"]])
        backend.command(["/usr/bin/systemctl", "start", actual[collection_timer]])
        baseline = device.snapshot()
        armed = manager.arm()
        report["helper_loaded"] = armed
        report["checks"].append("native_helper_load_and_arm")
        watch_path = Path("/run/systemd/system") / actual[controls.WATCH]
        original = installed[watch_path]
        drift = original.replace(b"MemoryMax=256M\n", b"MemoryMax=512M\n")
        require(drift != original, "resource drift fixture missing")
        watch_path.write_bytes(drift)
        installed[watch_path] = drift
        backend.command(["/usr/bin/systemctl", "daemon-reload"])
        try:
            manager.armed()
        except helpers.Refused as exc:
            require(str(exc) == "watchdog_resource_contract", "unexpected drift refusal")
        else:
            raise AssertionError("actual resource drift accepted")
        watch_path.write_bytes(original)
        installed[watch_path] = original
        backend.command(["/usr/bin/systemctl", "daemon-reload"])
        manager.armed()
        report["checks"].append("actual_loaded_resource_drift_refused")
        control.fence("collection")
        control.fence("consumer")
        device.stop("collection")
        device.wait_stopped("collection")
        old = device.probe("capstone-journal-reader.service")
        device.run(["/usr/bin/systemctl", "start", "capstone-journal-reader.service"])
        skipped = device.probe("capstone-journal-reader.service")
        require(skipped["ConditionResult"] == "no" and skipped["MainPID"] == "0" and
                skipped["ExecMainStartTimestampMonotonic"] == old["ExecMainStartTimestampMonotonic"], "fenced unit executed")
        report["checks"].append("actual_condition_fence_blocks_start")
        fs.install_barriers()
        job = manager.start_operation("apply")
        wait_for(lambda: (root / "controller-lost.json").exists() and not manager.operation_running("apply"))
        failed = manager.probe(job)
        require(failed["ExecMainStatus"] == "23" and failed["Result"] == "exit-code", "controller loss not observed")
        wait_for(lambda: (root / "recovered.json").exists(), 25)
        lost = json.loads((root / "controller-lost.json").read_text())
        recovered = json.loads((root / "recovered.json").read_text())
        require(recovered["pid"] != lost["pid"] and recovered["at_monotonic_ns"] > lost["at_monotonic_ns"]
                and recovered["changed"] == 2, "independent restore not proved")
        report["controller_loss"] = lost
        report["timer_recovery"] = recovered
        report["checks"].append("separate_native_timer_restores_interrupted_fixture_core")
        require(control.fenced("collection") and control.fenced("consumer"), "unexpected fence removal")
        control.unfence("collection")
        backend.command(["/usr/bin/systemctl", "daemon-reload"])
        device.resume_original("collection", baseline)
        resumed = device.snapshot()
        require(all((row["ActiveState"] == "active") == (baseline[name]["ActiveState"] == "active")
                    for name, row in resumed.items()), "resume changed baseline active set")
        require(int(resumed["capstone-journal-reader.service"]["ExecMainStartTimestampMonotonic"]) >
                int(baseline["capstone-journal-reader.service"]["ExecMainStartTimestampMonotonic"]), "reader did not restart")
        report["checks"].append("native_resume_only_original_active_units")
        manager.disarm()
        result = True
    except Exception as exc:
        report["failure"] = {"type": type(exc).__name__, "message": str(exc)[:1024]}
        result = False
    finally:
        errors = []
        try:
            write_new(root / "before-cleanup.json", json.dumps(report, sort_keys=True).encode())
        except Exception as exc:
            errors.append("checkpoint:" + type(exc).__name__)
        if backend:
            for original, name in sorted(backend.names.items(), key=lambda item: (not item[0].endswith(".timer"), item[0])):
                if "@." in name:
                    continue
                for verb in ("stop", "reset-failed"):
                    try:
                        backend.command(["/usr/bin/systemctl", verb, name], check=False)
                    except Exception as exc:
                        errors.append(type(exc).__name__ + ":" + verb + ":" + name)
                for target in ("timers.target.wants", "multi-user.target.wants"):
                    link = Path("/run/systemd/system") / target / name
                    if link.is_symlink():
                        expected = Path("/run/systemd/system") / name
                        if link.resolve() == expected:
                            link.unlink()
                        else:
                            errors.append("foreign owned-name enable link")
            for path, expected in installed.items():
                try:
                    if path.is_file() and not path.is_symlink() and path.read_bytes() == expected:
                        path.unlink()
                    else:
                        errors.append("unit content changed: " + str(path))
                except Exception as exc:
                    errors.append("unit removal:" + type(exc).__name__ + ":" + str(path))
            for parent in {path.parent for path in installed if path.parent.name.endswith(".d")}:
                try:
                    parent.rmdir()
                except Exception as exc:
                    errors.append("drop-in directory removal:" + type(exc).__name__ + ":" + str(parent))
            try:
                backend.command(["/usr/bin/systemctl", "daemon-reload"])
            except Exception as exc:
                errors.append("manager reload:" + type(exc).__name__)
            report["commands"] = backend.calls
        report["cleanup"]["unit_files_absent"] = all(not path.exists() for path in installed)
        report["cleanup"]["errors"] = errors
        # A running helper may still use the workspace after a stop timeout.
        running = []
        if backend:
            for name in backend.names.values():
                if "@." in name:
                    continue
                try:
                    probe = backend.command(["/usr/bin/systemctl", "show", name, "--property=MainPID,ActiveState,LoadState"], check=False)
                    fields = dict(line.split("=", 1) for line in probe.stdout.decode().splitlines() if "=" in line)
                    if fields.get("MainPID", "0") != "0" or fields.get("ActiveState") in ("active", "activating", "deactivating"):
                        running.append(name)
                except Exception as exc:
                    running.append(name)
                    errors.append("final unit observation:" + type(exc).__name__)
        report["cleanup"]["remaining_running_units"] = running
        if not errors and not running:
            shutil.rmtree(root)
            report["cleanup"]["workspace_absent"] = not root.exists()
        else:
            report["cleanup"]["workspace_preserved_for_recovery"] = str(root)
        report["passed"] = bool(result and not errors and not running and report["cleanup"].get("workspace_absent"))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-owned-units", action="store_true", required=True)
    args = parser.parse_args()
    require(args.run_owned_units, "explicit owned-unit opt-in required")
    report = validate()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
