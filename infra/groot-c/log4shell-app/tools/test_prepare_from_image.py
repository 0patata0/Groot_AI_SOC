#!/usr/bin/env python3
"""Offline preparation boundary tests; no Docker, JDK or network is required."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import prepare_from_image as prepare


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.app = self.source / prepare.APP
        repository = Path(__file__).resolve().parents[4]
        for relative in prepare.REQUIRED:
            destination = self.app / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repository / prepare.APP / relative, destination)
            destination.chmod(0o644)

    def tearDown(self):
        self.temporary.cleanup()

    def test_check_is_read_only_and_does_not_call_docker(self):
        before = sorted(path.relative_to(self.root).as_posix() for path in self.root.rglob("*"))
        with patch.object(prepare.subprocess, "run", side_effect=AssertionError("Docker must not run")):
            snapshot, report = prepare.fingerprint(self.source)
        self.assertEqual(report["schema"], 1)
        self.assertEqual(set(snapshot), set(prepare.REQUIRED))
        self.assertEqual(len(report["source_sha256"]), 64)
        self.assertEqual(before, sorted(path.relative_to(self.root).as_posix() for path in self.root.rglob("*")))

    def test_fingerprint_changes_for_source_and_builder(self):
        original = prepare.fingerprint(self.source)[1]["source_sha256"]
        for relative in ("src/main/resources/static/app.js", "tools/build_from_existing.py", "tools/prepare_from_image.py"):
            path = self.app / relative
            content = path.read_bytes()
            path.write_bytes(content + b"\n")
            self.assertNotEqual(original, prepare.fingerprint(self.source)[1]["source_sha256"])
            path.write_bytes(content)

    def test_missing_required_source_is_refused(self):
        (self.app / "src/main/resources/log4j2-spring.xml").unlink()
        with self.assertRaises(OSError):
            prepare.fingerprint(self.source)

    def test_symlink_source_is_refused(self):
        path = self.app / "src/main/resources/static/app.js"
        original = self.root / "outside.js"
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaises(ValueError):
            prepare.fingerprint(self.source)

    def test_writable_or_hardlinked_source_is_refused(self):
        path = self.app / "src/main/resources/static/app.js"
        path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "unsafe_source_file"):
            prepare.fingerprint(self.source)
        path.chmod(0o644)
        os.link(path, self.root / "hardlink.js")
        with self.assertRaisesRegex(ValueError, "unsafe_source_file"):
            prepare.fingerprint(self.source)

    def test_snapshot_directories_readable_for_container_uid(self):
        snapshot = prepare.fingerprint(self.source)[0]
        workspace = self.root / "workspace"
        workspace.mkdir()
        old_umask = os.umask(0o077)
        try:
            prepare.write_snapshot(snapshot, workspace)
        finally:
            os.umask(old_umask)
        for path in workspace.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o755 if path.is_dir() else 0o644)

    def test_changed_fingerprint_refused_before_docker(self):
        with patch.object(prepare.os, "geteuid", return_value=0), \
                patch.object(prepare, "fingerprint", return_value=({}, {"source_sha256": "a" * 64})), \
                patch.object(prepare, "Docker", side_effect=AssertionError("Docker must not run")):
            with self.assertRaisesRegex(ValueError, "source_changed_since_check"):
                prepare.prepare(self.source, "sha256:" + "1" * 64, self.root / "new.jar", "b" * 64, "/usr/bin/docker")

    def docker_object(self):
        docker = object.__new__(prepare.Docker)
        docker.command = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
        docker.image = "sha256:" + "1" * 64
        docker.pending = {}
        return docker

    def test_local_daemon_and_clean_environment_are_explicit(self):
        docker = self.docker_object()
        result = subprocess.CompletedProcess([], 0, b"ok", b"")
        with patch.object(prepare.subprocess, "run", return_value=result) as run:
            docker.run("info")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "info"])
        self.assertEqual(run.call_args.kwargs["env"], prepare.DOCKER_ENV)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_create_cannot_pull_or_access_network(self):
        docker = self.docker_object()
        result = subprocess.CompletedProcess([], 0, ("2" * 64 + "\n").encode(), b"")
        with patch.object(docker, "run", return_value=result) as run:
            docker.create("compile", ["--entrypoint", "sh", docker.image, "-c", "true"])
        arguments = run.call_args.args
        for key, value in (("--pull", "never"), ("--network", "none"), ("--user", "65532:65532"),
                           ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges:true")):
            self.assertEqual(arguments[arguments.index(key) + 1], value)
        self.assertIn("--read-only", arguments)
        self.assertNotIn("--privileged", arguments)

    def test_cleanup_refuses_unowned_container(self):
        docker = self.docker_object()
        docker.pending["temporary-name"] = "expected-token"
        for image, token in ((docker.image, "another-token"), ("sha256:" + "3" * 64, "expected-token")):
            data = [{"Id": "2" * 64, "Image": image, "Config": {"Labels": {"io.capstone.offline-build": token}}}]
            result = subprocess.CompletedProcess([], 0, json.dumps(data).encode(), b"")
            with patch.object(docker, "run", return_value=result) as run:
                with self.assertRaisesRegex(ValueError, "cleanup_not_verified"):
                    docker.cleanup()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], "container")

    def test_cleanup_removes_only_recorded_owned_id(self):
        docker = self.docker_object()
        docker.pending["temporary-name"] = "expected-token"
        data = [{"Id": "2" * 64, "Image": docker.image, "Config": {"Labels": {"io.capstone.offline-build": "expected-token"}}}]
        result = subprocess.CompletedProcess([], 0, json.dumps(data).encode(), b"")
        with patch.object(docker, "run", return_value=result) as run:
            docker.cleanup()
        self.assertEqual(run.call_args.args, ("rm", "--force", "2" * 64))
        self.assertFalse(docker.pending)

    def test_failed_create_cleanup_distinguishes_missing_from_daemon_failure(self):
        docker = self.docker_object()
        docker.pending["temporary-name"] = "expected-token"
        absent = subprocess.CompletedProcess([], 1, b"", b"Error response from daemon: No such container: temporary-name")
        ok = subprocess.CompletedProcess([], 0, b"linux", b"")
        with patch.object(docker, "run", side_effect=[absent, ok]) as run:
            docker.cleanup()
        self.assertFalse(docker.pending)
        self.assertEqual(run.call_args.args, ("info", "--format", "{{.OSType}}"))
        docker.pending["temporary-name"] = "expected-token"
        failed = subprocess.CompletedProcess([], 1, b"", b"daemon unavailable")
        with patch.object(docker, "run", side_effect=[failed, ok]):
            with self.assertRaisesRegex(ValueError, "cleanup_not_verified"):
                docker.cleanup()
        self.assertTrue(docker.pending)

    def run_fake_build(self, compile_failure=False, source_change=False):
        image = "sha256:" + "1" * 64
        destination = self.root / "new.jar"
        snapshot = {"src/main/java/Example.java": b"class Example {}",
                    "src/main/resources/application.properties": b"server.port=8080"}
        report = {"source_sha256": "a" * 64}
        calls = []
        original_stat = Path.stat

        def safe_parent(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if path == self.root:
                return SimpleNamespace(st_uid=0, st_mode=result.st_mode)
            return result

        class FakeDocker:
            def __init__(self, _executable, _image):
                pass

            def create(self, purpose, arguments):
                calls.append(("create", purpose))
                return "2" * 64

            def cleanup(self):
                calls.append(("cleanup",))

            def run(self, *arguments, **kwargs):
                if arguments[:2] == ("image", "inspect"):
                    value = [{"Id": image, "Os": "linux", "Architecture": "amd64", "Config": {}}]
                elif arguments[0] == "cp":
                    Path(arguments[2]).write_bytes(b"base")
                    return subprocess.CompletedProcess([], 0, b"", b"")
                elif arguments[0] == "start":
                    if compile_failure == "timeout":
                        raise subprocess.TimeoutExpired(["docker", "start"], 120)
                    if compile_failure:
                        raise ValueError("docker_start_failed")
                    return subprocess.CompletedProcess([], 0, b"javac 1.8.0_181\n", b"")
                elif arguments[0] == "inspect":
                    value = {"Running": False, "ExitCode": 0, "OOMKilled": False}
                else:
                    raise AssertionError(arguments)
                return subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b"")

        def extract(_base, directory):
            (directory / "lib").mkdir(parents=True)
            return {}

        def package(_base, _classes, _resources, output):
            output.write_bytes(b"new-jar")
            return {"output_sha256": "b" * 64}

        snapshots = [(snapshot, dict(report)), (snapshot, {"source_sha256": "c" * 64 if source_change else "a" * 64})]
        with patch.object(prepare.os, "geteuid", return_value=0), patch.object(Path, "stat", safe_parent), \
                patch.object(prepare.os, "chown"), patch.object(prepare, "fingerprint", side_effect=snapshots), \
                patch.object(prepare, "Docker", FakeDocker), \
                patch.object(prepare.packager, "extract_libraries", side_effect=extract), \
                patch.object(prepare.packager, "package_application", side_effect=package):
            if compile_failure or source_change:
                exception = subprocess.TimeoutExpired if compile_failure == "timeout" else ValueError
                expected = "timed out" if compile_failure == "timeout" else ("docker_start_failed" if compile_failure else "source_changed_during_build")
                with self.assertRaisesRegex(exception, expected):
                    prepare.prepare(self.source, image, destination, "a" * 64, "/usr/bin/docker")
                self.assertFalse(destination.exists())
            else:
                result = prepare.prepare(self.source, image, destination, "a" * 64, "/usr/bin/docker")
                self.assertTrue(result["temporary_containers_removed"])
                self.assertEqual(destination.read_bytes(), b"new-jar")
        self.assertFalse(list(self.root.glob(".log4shell-build-*")))
        self.assertGreaterEqual(calls.count(("cleanup",)), 2)

    def test_compiler_failure_cleans_temporary_workspace_and_containers(self):
        self.run_fake_build(compile_failure=True)

    def test_compiler_timeout_cleans_temporary_workspace_and_containers(self):
        self.run_fake_build(compile_failure="timeout")

    def test_source_change_during_build_removes_uncommitted_artifact(self):
        self.run_fake_build(source_change=True)

    def test_success_retains_only_final_jar(self):
        self.run_fake_build()


if __name__ == "__main__":
    unittest.main()
