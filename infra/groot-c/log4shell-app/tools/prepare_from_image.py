#!/usr/bin/env python3
"""Prepare the lab JAR from source and one already loaded JDK image, offline.

check SOURCE prints a source fingerprint without using Docker or writing files.
build SOURCE IMAGE_ID NEW.jar --expected-source-sha256 SHA performs the build.
The original image and all of its dependencies remain unchanged. Only disposable
containers are created; no network, Docker build, package manager or pull is used.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
import build_from_existing as packager


APP = Path("infra/groot-c/log4shell-app")
TOOLS = ("tools/build_from_existing.py", "tools/prepare_from_image.py")
REQUIRED = (
    "build.gradle", "settings.gradle",
    "src/main/java/fr/christophetd/log4shell/vulnerableapp/VulnerableAppApplication.java",
    "src/main/java/fr/christophetd/log4shell/vulnerableapp/MainController.java",
    "src/main/java/fr/christophetd/log4shell/vulnerableapp/LabCsrf.java",
    "src/main/resources/application.properties", "src/main/resources/log4j2-spring.xml",
    "src/main/resources/static/index.html", "src/main/resources/static/app.js",
    "src/main/resources/static/app.css",
) + TOOLS
MAX_SOURCE_BYTES = 8 * 1024 * 1024
DOCKER_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
              "HOME": "/root", "LC_ALL": "C"}
COMPILER_SCRIPT = r'''set -eu
unset JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS CLASSPATH
version=$(javac -version 2>&1)
printf '%s\n' "$version"
[ "$version" = 'javac 1.8.0_181' ] || exit 64
exec javac -J-Xmx256m -proc:none -encoding UTF-8 -source 1.8 -target 1.8 -cp '/work/lib/*' -d /work/classes "$@"
'''


def fingerprint(source):
    """Take a bounded, non-symlink source snapshot; hashes include the builders."""
    source = packager.reject_symlink_components(source)
    app = source / APP
    candidates = set(REQUIRED)
    for directory, suffix in (("src/main/java", ".java"), ("src/main/resources", None)):
        base = app / directory
        if not base.is_dir() or base.is_symlink():
            raise ValueError("source_tree_missing")
        for root, dirs, files in os.walk(base, followlinks=False):
            for name in dirs + files:
                path = Path(root) / name
                info = path.lstat()
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise ValueError("source_tree_special_file")
            for name in files:
                if suffix is not None and not name.endswith(suffix):
                    raise ValueError("unexpected_java_source_file")
                candidates.add((Path(root) / name).relative_to(app).as_posix())
    if len(candidates) > 256:
        raise ValueError("too_many_source_files")
    snapshot = {}
    total = 0
    for relative in sorted(candidates):
        if not re.fullmatch(r"[A-Za-z0-9._/-]+", relative):
            raise ValueError("unsafe_source_filename")
        path = packager.reject_symlink_components(app / relative)
        for directory in (path.parent,) + tuple(path.parent.parents):
            if directory == source.parent:
                break
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError("unsafe_source_directory")
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or not 0 < info.st_size <= MAX_SOURCE_BYTES):
            raise ValueError("unsafe_source_file")
        total += info.st_size
        if total > MAX_SOURCE_BYTES:
            raise ValueError("source_size_limit")
        snapshot[relative] = path.read_bytes()
        if len(snapshot[relative]) != info.st_size:
            raise ValueError("source_changed_during_snapshot")
    files = {name: packager.sha256(data) for name, data in snapshot.items()}
    digest = packager.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())
    return snapshot, {"schema": 1, "mode": "offline-image-jdk", "source_sha256": digest, "files": files}


class Docker:
    def __init__(self, executable, image):
        path = packager.reject_symlink_components(executable)
        info = path.stat()
        if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not os.access(path, os.X_OK):
            raise ValueError("unsafe_docker_executable")
        self.command = [str(path), "--host", "unix:///var/run/docker.sock"]
        self.image = image
        self.pending = {}

    def run(self, *args, timeout=30, allow_failure=False):
        result = subprocess.run(self.command + list(args), env=DOCKER_ENV, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        if len(result.stdout) + len(result.stderr) > 1024 * 1024:
            raise ValueError("docker_output_limit")
        if result.returncode and not allow_failure:
            # Image/source data and private compiler diagnostics are not printed.
            raise ValueError("docker_" + args[0] + "_failed")
        return result

    def create(self, purpose, arguments):
        token = secrets.token_hex(12)
        name = "capstone-log4shell-build-" + token
        self.pending[name] = token
        result = self.run("create", "--pull", "never", "--name", name,
                          "--label", "io.capstone.offline-build=" + token,
                          "--label", "io.capstone.offline-build-purpose=" + purpose,
                          "--network", "none", "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges:true", "--pids-limit", "128",
                          "--memory", "512m", "--cpus", "1", "--user", "65532:65532",
                          "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
                          "--env", "JAVA_TOOL_OPTIONS=", "--env", "_JAVA_OPTIONS=",
                          "--env", "JDK_JAVA_OPTIONS=", "--env", "CLASSPATH=", "--env", "HOME=/tmp",
                          *arguments)
        identity = result.stdout.decode().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise ValueError("invalid_build_container_identity")
        return identity

    def cleanup(self):
        errors = []
        for name, token in list(self.pending.items()):
            result = self.run("container", "inspect", name, allow_failure=True)
            if result.returncode:
                # A failed create may have left no container. Distinguish that
                # from a daemon failure before declaring cleanup successful.
                self.run("info", "--format", "{{.OSType}}")
                if b"No such container" not in result.stderr and b"No such object" not in result.stderr:
                    errors.append(name)
                else:
                    del self.pending[name]
                continue
            info = json.loads(result.stdout)
            if (len(info) != 1 or info[0].get("Image") != self.image
                    or info[0].get("Config", {}).get("Labels", {}).get("io.capstone.offline-build") != token):
                errors.append(name)
                continue
            self.run("rm", "--force", info[0]["Id"])
            del self.pending[name]
        if errors:
            raise ValueError("offline_build_cleanup_not_verified:" + ",".join(errors))


def write_snapshot(snapshot, workspace):
    for section in ("java", "resources"):
        target = workspace / section
        target.mkdir(mode=0o755)
        target.chmod(0o755)
        prefix = "src/main/" + section + "/"
        for relative, data in snapshot.items():
            if not relative.startswith(prefix):
                continue
            path = target / relative[len(prefix):]
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with path.open("xb") as handle:
                handle.write(data)
            path.chmod(0o644)
        for root, dirs, _ in os.walk(target):
            for name in dirs:
                (Path(root) / name).chmod(0o755)


def prepare(source, image, destination, expected_source, executable):
    if os.geteuid() != 0 or not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("root_and_local_image_id_required")
    snapshot, report = fingerprint(source)
    if not re.fullmatch(r"[a-f0-9]{64}", expected_source) or report["source_sha256"] != expected_source:
        raise ValueError("source_changed_since_check")
    destination = packager.reject_symlink_components(destination)
    if (destination.exists() or not destination.parent.is_dir()
            or not re.fullmatch(r"/[A-Za-z0-9._/-]+", str(destination))):
        raise ValueError("new_destination_required")
    parent_info = destination.parent.stat()
    if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
        raise ValueError("private_output_parent_required")
    docker = Docker(executable, image)
    info = json.loads(docker.run("image", "inspect", image).stdout)
    if (len(info) != 1 or info[0].get("Id") != image or info[0].get("Os") != "linux"
            or info[0].get("Architecture") != "amd64" or info[0].get("Config", {}).get("Volumes")):
        raise ValueError("preloaded_linux_amd64_image_without_volumes_required")
    workspace = Path(tempfile.mkdtemp(prefix=".log4shell-build-", dir=destination.parent))
    output_created = False
    try:
        # The stopped container supplies the original image JAR, not the live
        # service's replaced JAR. Its entrypoint/application is never started.
        extractor = docker.create("extract", ["--entrypoint", "java", image, "-version"])
        base = workspace / "base.jar"
        docker.run("cp", extractor + ":/app/spring-boot-application.jar", str(base))
        docker.cleanup()
        package_report = packager.extract_libraries(base, workspace / "dependencies")
        libraries = workspace / "dependencies/lib"
        libraries.chmod(0o755)
        for library in libraries.iterdir():
            library.chmod(0o644)
        write_snapshot(snapshot, workspace)
        classes = workspace / "classes"
        classes.mkdir(mode=0o700)
        os.chown(classes, 65532, 65532)
        sources = ["/work/java/" + name[len("src/main/java/"):]
                   for name in sorted(snapshot) if name.startswith("src/main/java/")]
        mounts = []
        for host, guest, readonly in ((workspace / "java", "/work/java", True),
                                     (libraries, "/work/lib", True), (classes, "/work/classes", False)):
            mounts += ["--mount", "type=bind,source=" + str(host) + ",target=" + guest + (",readonly" if readonly else "")]
        compiler = docker.create("compile", mounts + ["--workdir", "/tmp", "--entrypoint", "sh", image,
                                                     "-c", COMPILER_SCRIPT, "javac", *sources])
        result = docker.run("start", "--attach", compiler, timeout=120)
        state = json.loads(docker.run("inspect", "--format", "{{json .State}}", compiler).stdout)
        if state.get("Running") or state.get("ExitCode") != 0 or state.get("OOMKilled"):
            raise ValueError("offline_javac_failed")
        if result.stdout.decode().strip() != "javac 1.8.0_181":
            raise ValueError("compiler_version_not_confirmed")
        docker.cleanup()
        package_report = packager.package_application(base, classes, workspace / "resources", destination)
        output_created = True
        destination.chmod(0o644)
        if fingerprint(source)[1]["source_sha256"] != expected_source:
            raise ValueError("source_changed_during_build")
        report.update({"image_id": image, "compiler_version": "javac 1.8.0_181", "network": "none",
                       "package": package_report, "temporary_containers_removed": True})
        return report
    except BaseException:
        if output_created:
            destination.unlink()
        raise
    finally:
        try:
            docker.cleanup()
        finally:
            shutil.rmtree(workspace)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check")
    check.add_argument("source", type=Path)
    build = commands.add_parser("build")
    build.add_argument("source", type=Path)
    build.add_argument("image")
    build.add_argument("destination", type=Path)
    build.add_argument("--expected-source-sha256", required=True)
    build.add_argument("--docker", default=shutil.which("docker", path=DOCKER_ENV["PATH"]) or "/usr/bin/docker")
    args = parser.parse_args()
    def interrupted(signum, _frame):
        raise InterruptedError("interrupted_by_signal_" + str(signum))
    # SIGKILL/daemon loss cannot be handled, but normal interruption must run
    # the same owned-container and workspace cleanup as compiler failures.
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        if args.command == "check":
            report = fingerprint(args.source)[1]
        else:
            report = prepare(args.source, args.image, args.destination, args.expected_source_sha256, args.docker)
        print(json.dumps(report, sort_keys=True))
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError, packager.zipfile.BadZipFile) as error:
        print("offline_log4shell_preparation_refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
