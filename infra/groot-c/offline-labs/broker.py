#!/usr/bin/env python3
"""Root-only fixed-purpose Unix broker. Never exposes arbitrary Docker commands."""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

from manifest import CVE_RE, IMAGE_ID_RE, ManifestError, load_manifest, trusted_path, unique_object

SOCKET = Path("/run/capstone-offline-labs/control.sock")
RECEIPT = Path("/var/lib/capstone-offline-labs/runtime.json")
NONWEB_STATUS = Path("/var/lib/capstone-offline-labs/nonweb-status.json")
NONWEB_MAX_TTL = 600
NONWEB_MAX_BYTES = 16384
NETWORK = "offline-labs"
LABEL = "io.capstone.offline-labs"
TMPFS = "rw,nosuid,nodev,size=128m,mode=1777"
MAX_REQUEST = 4096
ID_RE = re.compile(r"[0-9a-f]{64}\Z")


class BrokerError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def runtime_hash(lab):
    value = {key: lab[key] for key in ("cve_id", "image_id", "host_port", "container_port")}
    value["policy"] = 1
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def name_for(lab):
    return "offline-lab-" + lab["cve_id"].lower()


def labels_for(lab):
    return {LABEL: "1", LABEL + ".cve": lab["cve_id"], LABEL + ".image": lab["image_id"],
            LABEL + ".contract": runtime_hash(lab)}


def guard_check():
    import guard
    guard.verify_guard()


def nonweb_status_document(data, cve_id, now):
    """Read a short-lived environment attestation, never an attack result."""
    if (not isinstance(data, dict) or set(data) != {"schema", "checked_at", "expires_at", "labs"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or type(data["checked_at"]) is not int or type(data["expires_at"]) is not int
            or not isinstance(data["labs"], dict) or len(data["labs"]) > 32):
        raise ValueError("invalid_nonweb_status")
    checked, expiry = data["checked_at"], data["expires_at"]
    if checked <= 0 or not 0 < expiry - checked <= NONWEB_MAX_TTL or now < checked:
        raise ValueError("invalid_nonweb_status_time")
    for identifier, row in data["labs"].items():
        if (not CVE_RE.fullmatch(identifier) or not isinstance(row, dict)
                or set(row) != {"status"} or not isinstance(row["status"], str)
                or row["status"] not in {"ready", "needs_setup", "error"}):
            raise ValueError("invalid_nonweb_status_lab")
    if now >= expiry:
        return {"status": "needs_setup", "verification": "expired", "checked_at": checked, "expires_at": expiry}
    if cve_id not in data["labs"]:
        return {"status": "needs_setup", "verification": "missing", "checked_at": checked, "expires_at": expiry}
    return {"status": data["labs"][cve_id]["status"], "verification": "environment_only",
            "checked_at": checked, "expires_at": expiry}


def validate_nonweb_file(info):
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
            or not 0 < info.st_size <= NONWEB_MAX_BYTES):
        raise ValueError("private_root_nonweb_status_required")


def read_nonweb_status(cve_id, path=NONWEB_STATUS, now=None):
    fallback = {"status": "needs_setup", "verification": "invalid", "checked_at": None, "expires_at": None}
    try:
        trusted_path(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            validate_nonweb_file(os.fstat(stream.fileno()))
            raw = stream.read(NONWEB_MAX_BYTES + 1)
        if len(raw) > NONWEB_MAX_BYTES:
            raise ValueError("nonweb_status_too_large")
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        return nonweb_status_document(data, cve_id, time.time() if now is None else now)
    except FileNotFoundError:
        return dict(fallback, verification="missing")
    except (OSError, ValueError, TypeError, RecursionError):
        return fallback


class Docker:
    def __init__(self, executable="/usr/bin/docker"):
        self.executable = executable

    def run(self, args, allow_absent=False, timeout=30):
        try:
            result = subprocess.run([self.executable, "--host", "unix:///var/run/docker.sock"] + args,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, timeout=timeout,
                                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent",
                                         "DOCKER_CONFIG": "/nonexistent", "LANG": "C", "LC_ALL": "C"})
        except (OSError, subprocess.SubprocessError):
            raise BrokerError("docker_unavailable") from None
        if result.returncode:
            if allow_absent and ("No such object:" in result.stderr or "No such container:" in result.stderr or "No such image:" in result.stderr):
                return None
            raise BrokerError("docker_operation_failed")
        return result.stdout.strip()

    def inspect(self, kind, identifier):
        output = self.run([kind, "inspect", identifier], allow_absent=True)
        if output is None:
            return None
        try:
            parsed = json.loads(output)
            if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
                raise ValueError()
            return parsed[0]
        except (ValueError, TypeError):
            raise BrokerError("invalid_docker_response") from None


class Receipts:
    def __init__(self, path=RECEIPT):
        self.path = Path(path)
        trusted_path(self.path.parent, directory=True)
        if self.path.parent.stat().st_mode & 0o077:
            raise BrokerError("private_receipt_directory_required")
        self.records = {}
        if self.path.exists() or self.path.is_symlink():
            trusted_path(self.path)
            if self.path.stat().st_mode & 0o077 or self.path.stat().st_size > 65536:
                raise BrokerError("invalid_receipt_permissions")
            data = json.loads(self.path.read_text(), object_pairs_hook=unique_object)
            if not isinstance(data, dict) or set(data) != {"schema", "containers"} or data["schema"] != 1 or not isinstance(data["containers"], dict):
                raise BrokerError("invalid_receipt")
            for cve, entry in data["containers"].items():
                if not CVE_RE.fullmatch(cve) or not isinstance(entry, dict) or set(entry) != {"container_id", "image_id", "runtime_sha256"}:
                    raise BrokerError("invalid_receipt")
                if not isinstance(entry["container_id"], str) or not ID_RE.fullmatch(entry["container_id"]) or not isinstance(entry["image_id"], str) or not IMAGE_ID_RE.fullmatch(entry["image_id"]) or not isinstance(entry["runtime_sha256"], str) or not ID_RE.fullmatch(entry["runtime_sha256"]):
                    raise BrokerError("invalid_receipt")
            self.records = data["containers"]

    def register(self, lab, container_id):
        records = dict(self.records)
        records[lab["cve_id"]] = {"container_id": container_id, "image_id": lab["image_id"], "runtime_sha256": runtime_hash(lab)}
        temporary = self.path.with_name(self.path.name + ".next-" + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "w") as stream:
                stream.write(canonical({"schema": 1, "containers": records}) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self.records = records
        finally:
            if temporary.exists():
                temporary.unlink()


def validate_network(info):
    if not info or info.get("Name") != NETWORK or info.get("Driver") != "bridge" or info.get("Scope") != "local" or info.get("Internal") is not False or info.get("EnableIPv6") is not False or info.get("Ingress", False) or info.get("ConfigOnly", False):
        raise BrokerError("network_contract_mismatch")
    if info.get("Labels", {}).get(LABEL) != "1" or info.get("Options", {}).get("com.docker.network.bridge.name") != "br-offline-labs" or info.get("Options", {}).get("com.docker.network.bridge.enable_icc") != "false":
        raise BrokerError("network_contract_mismatch")


def image_is_valid(image, lab):
    return bool(image and image.get("Id") == lab["image_id"] and image.get("Os") == "linux" and
                isinstance(image.get("Config"), dict) and not image["Config"].get("Volumes"))


def validate_container(info, lab, image):
    """Validate all security-relevant create options before any start or stop."""
    config, host = info.get("Config", {}), info.get("HostConfig", {})
    expected_labels = dict(image.get("Config", {}).get("Labels") or {})
    expected_labels.update(labels_for(lab))
    if not ID_RE.fullmatch(info.get("Id", "")) or info.get("Name") != "/" + name_for(lab) or info.get("Image") != lab["image_id"] or config.get("Image") != lab["image_id"] or config.get("Labels") != expected_labels or config.get("User") != "65532:65532":
        raise BrokerError("container_contract_mismatch")
    for key in ("Cmd", "Entrypoint"):
        if (config.get(key) or []) != (image["Config"].get(key) or []):
            raise BrokerError("container_command_mismatch")
    if (config.get("Env") or []) != (image["Config"].get("Env") or []):
        raise BrokerError("container_environment_mismatch")
    if (config.get("WorkingDir") or "") != (image["Config"].get("WorkingDir") or "") or config.get("Healthcheck", {}).get("Test") != ["NONE"]:
        raise BrokerError("container_command_mismatch")
    expected = {"ReadonlyRootfs": True, "Privileged": False, "AutoRemove": False, "NetworkMode": NETWORK,
                "IpcMode": "private", "PidMode": "", "UTSMode": "", "CgroupnsMode": "private",
                "Memory": 536870912, "MemorySwap": 536870912, "NanoCpus": 1000000000, "PidsLimit": 128,
                "Dns": ["127.0.0.1"], "Tmpfs": {"/tmp": TMPFS},
                "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}}}
    if any(host.get(key) != value for key, value in expected.items()):
        raise BrokerError("container_runtime_mismatch")
    if host.get("CapDrop") != ["ALL"] or host.get("CapAdd") or host.get("SecurityOpt") not in (["no-new-privileges:true"], ["no-new-privileges=true"], ["no-new-privileges"]):
        raise BrokerError("container_privilege_mismatch")
    for key in ("Binds", "Mounts", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules", "Links", "ExtraHosts", "DnsSearch", "DnsOptions", "Sysctls"):
        if host.get(key):
            raise BrokerError("container_extra_runtime_option")
    if host.get("UsernsMode") not in (None, "") or host.get("RestartPolicy") != {"Name": "no", "MaximumRetryCount": 0} or config.get("Volumes"):
        raise BrokerError("container_runtime_mismatch")
    expected_ports = {str(lab["container_port"]) + "/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(lab["host_port"])}]}
    if host.get("PortBindings") != expected_ports:
        raise BrokerError("container_port_mismatch")
    networks = info.get("NetworkSettings", {}).get("Networks", {})
    if set(networks) != {NETWORK}:
        raise BrokerError("container_network_mismatch")
    actual_ports = info.get("NetworkSettings", {}).get("Ports") or {}
    if info.get("State", {}).get("Running") and {port: bindings for port, bindings in actual_ports.items() if bindings} != expected_ports:
        raise BrokerError("container_port_mismatch")
    for port, bindings in actual_ports.items():
        if bindings and expected_ports.get(port) != bindings:
            raise BrokerError("container_port_mismatch")
    for mount in info.get("Mounts", []):
        if mount.get("Type") != "tmpfs" or mount.get("Destination") != "/tmp" or not mount.get("RW"):
            raise BrokerError("container_mount_mismatch")


def create_args(lab):
    args = ["container", "create", "--name", name_for(lab), "--pull=never", "--network", NETWORK,
            "--dns", "127.0.0.1", "--user", "65532:65532", "--read-only", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges=true", "--ipc", "private", "--cgroupns", "private",
            "--tmpfs", "/tmp:" + TMPFS, "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
            "--pids-limit", "128", "--restart", "no", "--no-healthcheck", "--stop-timeout", "10",
            "--log-driver", "json-file", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
            "--publish", "127.0.0.1:" + str(lab["host_port"]) + ":" + str(lab["container_port"]) + "/tcp"]
    for key, value in sorted(labels_for(lab).items()):
        args.extend(["--label", key + "=" + value])
    return args + [lab["image_id"]]


class Broker:
    def __init__(self, labs, docker, receipts, verify_guard=guard_check, nonweb_reader=read_nonweb_status):
        self.labs = {lab["cve_id"]: lab for lab in labs}
        self.docker, self.receipts, self.verify_guard = docker, receipts, verify_guard
        self.nonweb_reader = nonweb_reader
        self.lock = threading.Lock()

    def safety(self):
        try:
            self.verify_guard()
        except Exception:
            raise BrokerError("egress_guard_unverified") from None
        validate_network(self.docker.inspect("network", NETWORK))

    def inventory(self, lab):
        image = self.docker.inspect("image", lab["image_tag"])
        image_present = image_is_valid(image, lab)
        record = self.receipts.records.get(lab["cve_id"])
        by_name = self.docker.inspect("container", name_for(lab))
        if not record:
            if by_name:
                raise BrokerError("foreign_container_conflict")
            return image_present, image, None
        if record["image_id"] != lab["image_id"] or record["runtime_sha256"] != runtime_hash(lab):
            raise BrokerError("receipt_contract_mismatch")
        registered = self.docker.inspect("container", record["container_id"])
        if registered is None and by_name is None:
            return image_present, image, None
        if registered is None or by_name is None or registered.get("Id") != by_name.get("Id") or registered.get("Id") != record["container_id"]:
            raise BrokerError("foreign_container_conflict")
        # A running container's image may have lost its tag; still validate its ID.
        pinned_image = image if image_present else self.docker.inspect("image", lab["image_id"])
        if not image_is_valid(pinned_image, lab):
            raise BrokerError("registered_image_unavailable")
        validate_container(registered, lab, pinned_image)
        return image_present, pinned_image, registered

    def result(self, lab, image_present, container):
        status = "not_deployed" if container is None else ("running" if container.get("State", {}).get("Running") else "stopped")
        if container and (container.get("State", {}).get("Dead") or container.get("State", {}).get("Restarting") or container.get("State", {}).get("Paused")):
            status = "error"
        return {"image_present": image_present, "status": status,
                "container_id": container["Id"][:12] if container else None,
                "url": "http://127.0.0.1:" + str(lab["host_port"]) + lab["path"]}

    def status(self, labs):
        result = {}
        for lab in labs:
            kind = lab.get("type", "managed-http")
            if kind == "existing-http":
                # Native DVWA is owned elsewhere. No health URL, Docker adoption,
                # host command, or claim about its current liveness is implied.
                result[lab["cve_id"]] = {"type": kind, "managed": False,
                    "image_present": False, "status": "external", "container_id": None,
                    "url": None, "verification": "managed_externally"}
                continue
            if kind == "local-cli":
                result[lab["cve_id"]] = {"type": kind, "managed": False,
                    "image_present": False, "container_id": None, "url": None,
                    **self.nonweb_reader(lab["cve_id"]),
                    "attack_tested": False, "host_scenario_verified": False}
                continue
            try:
                present, _, container = self.inventory(lab)
                result[lab["cve_id"]] = self.result(lab, present, container)
            except BrokerError as error:
                conflict = error.code in {"foreign_container_conflict", "receipt_contract_mismatch"} or error.code.startswith("container_")
                try:
                    present = image_is_valid(self.docker.inspect("image", lab["image_tag"]), lab)
                except BrokerError:
                    present = False
                result[lab["cve_id"]] = dict(self.result(lab, present, None), status="conflict" if conflict else "error", error=error.code)
        return {"ok": True, "labs": result}

    def handle(self, request):
        try:
            if not isinstance(request, dict) or request.keys() - {"action", "cve_id"} or not isinstance(request.get("action"), str) or request["action"] not in {"status", "deploy", "stop"}:
                raise BrokerError("invalid_request")
            action, cve = request["action"], request.get("cve_id")
            if cve is not None and (not isinstance(cve, str) or cve not in self.labs):
                raise BrokerError("unknown_cve")
            if action != "status" and cve is None:
                raise BrokerError("cve_id_required")
            with self.lock:
                if action == "status":
                    safety_error = None
                    try:
                        self.safety()
                    except BrokerError as error:
                        safety_error = error.code
                    response = self.status([self.labs[cve]] if cve else list(self.labs.values()))
                    response.update({"deployment_allowed": safety_error is None, "safety_error": safety_error})
                    return response
                lab = self.labs[cve]
                kind = lab.get("type", "managed-http")
                if kind != "managed-http":
                    raise BrokerError("external_lab_managed_separately" if kind == "existing-http"
                                      else "local_cli_managed_separately")
                if action == "deploy":
                    self.safety()
                present, image, container = self.inventory(lab)
                if action == "deploy":
                    if not present:
                        raise BrokerError("pinned_image_unavailable")
                    if container is None:
                        container_id = self.docker.run(create_args(lab))
                        if not isinstance(container_id, str) or not ID_RE.fullmatch(container_id):
                            raise BrokerError("invalid_created_container_id")
                        container = self.docker.inspect("container", container_id)
                        if not container or container.get("Id") != container_id:
                            raise BrokerError("created_container_unavailable")
                        validate_container(container, lab, image)
                        self.receipts.register(lab, container_id)
                    if not container.get("State", {}).get("Running"):
                        self.safety()
                        self.docker.run(["container", "start", container["Id"]])
                elif container and container.get("State", {}).get("Running"):
                    self.docker.run(["container", "stop", container["Id"]])
                present, _, container = self.inventory(lab)
                return {"ok": True, "lab": self.result(lab, present, container)}
        except BrokerError as error:
            return {"ok": False, "error": error.code}
        except Exception:
            return {"ok": False, "error": "internal_error"}


def parse_request(data):
    if not data.endswith(b"\n") or len(data) > MAX_REQUEST or b"\n" in data[:-1]:
        raise BrokerError("invalid_request_frame")
    try:
        parsed = json.loads(data[:-1].decode("utf-8"), object_pairs_hook=unique_object)
        if not isinstance(parsed, dict):
            raise BrokerError("invalid_request_json")
        return parsed
    except (ValueError, UnicodeError, RecursionError):
        raise BrokerError("invalid_request_json") from None


def authorized_peer(connection, uid, gid):
    _, peer_uid, peer_gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return peer_uid == 0 or (peer_uid == uid and peer_gid == gid)


def serve(broker, uid, gid):
    trusted_path(SOCKET.parent, directory=True)
    info = SOCKET.parent.stat()
    if info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o750:
        raise BrokerError("invalid_socket_directory")
    lock_path = broker.receipts.path.parent / "broker.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    lock_info = os.fstat(descriptor)
    if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0 or lock_info.st_nlink != 1 or lock_info.st_mode & 0o077:
        os.close(descriptor)
        raise BrokerError("invalid_broker_lock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound_inode = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if SOCKET.exists() or SOCKET.is_symlink():
            current = SOCKET.lstat()
            if not stat.S_ISSOCK(current.st_mode) or current.st_uid != 0 or current.st_gid != gid or stat.S_IMODE(current.st_mode) != 0o660:
                raise BrokerError("foreign_control_socket")
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(1)
            try:
                probe.connect(str(SOCKET))
            except OSError as error:
                if error.errno != errno.ECONNREFUSED:
                    raise BrokerError("control_socket_in_use") from None
            else:
                raise BrokerError("control_socket_in_use")
            finally:
                probe.close()
            SOCKET.unlink()
        listener.bind(str(SOCKET))
        os.chown(SOCKET, 0, gid)
        os.chmod(SOCKET, 0o660)
        bound_inode = SOCKET.lstat().st_ino
        listener.listen(16)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                try:
                    if not authorized_peer(connection, uid, gid):
                        raise BrokerError("peer_not_authorized")
                    frame = b""
                    while b"\n" not in frame and len(frame) <= MAX_REQUEST:
                        chunk = connection.recv(min(1024, MAX_REQUEST + 1 - len(frame)))
                        if not chunk:
                            break
                        frame += chunk
                    reply = broker.handle(parse_request(frame))
                except BrokerError as error:
                    reply = {"ok": False, "error": error.code}
                except (OSError, ValueError):
                    reply = {"ok": False, "error": "invalid_request"}
                try:
                    connection.sendall((canonical(reply) + "\n").encode())
                except OSError:
                    pass
    finally:
        listener.close()
        if bound_inode and SOCKET.exists() and SOCKET.lstat().st_ino == bound_inode:
            SOCKET.unlink()
        os.close(descriptor)


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise BrokerError("root_linux_required")
    uid, gid = int(os.environ["OFFLINE_LABS_UID"]), int(os.environ["OFFLINE_LABS_GID"])
    if not 1 <= uid <= 2147483647 or not 1 <= gid <= 2147483647:
        raise BrokerError("unprivileged_service_identity_required")
    docker_path = Path(os.environ.get("OFFLINE_LABS_DOCKER", "/usr/bin/docker"))
    trusted_path(docker_path)
    labs = load_manifest(os.environ["OFFLINE_LABS_MANIFEST"], require_root=True)
    state_path = Path(os.environ.get("OFFLINE_LABS_STATE", str(RECEIPT)))
    serve(Broker(labs, Docker(str(docker_path)), Receipts(state_path)), uid, gid)


if __name__ == "__main__":
    try:
        main()
    except (BrokerError, ManifestError, OSError, ValueError, KeyError):
        print("offline_labs_broker_start_failed", file=sys.stderr)
        raise SystemExit(1)
