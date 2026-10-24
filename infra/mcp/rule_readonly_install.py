#!/usr/bin/env python3
"""Internal initial provisioner for the fixed, independently keyed rule reader.

Called by deploy.sh's SOC stage (or an explicit existing-server migration).
Does not run a worker, propose a change, rotate a key, or restart Hermes.
"""
import os
from pathlib import Path
import pwd
import re
import subprocess


def install(host, public_key):
    if os.geteuid() != 0 or host not in {"a", "b"}:
        raise ValueError("root and fixed host required")
    if not isinstance(public_key, str) or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\r\n]+)?", public_key):
        raise ValueError("one Ed25519 public key required")
    subprocess.run(["ssh-keygen", "-l", "-f", "/dev/stdin"], input=(public_key + "\n").encode(),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    try:
        pwd.getpwnam("ruleview")
    except KeyError:
        pass
    else:
        raise ValueError("existing ruleview requires explicit migration review")
    for name in ("/opt/rule-view", "/etc/sudoers.d/capstone-rule-readonly",
                 "/etc/ssh/sshd_config.d/63-capstone-rule-readonly.conf"):
        if os.path.lexists(name):
            raise ValueError("existing readonly namespace refused")
    # Readers never initialize workflow directories or lock files on a query.
    for name in ("/var/lib/rule-change/services",) + (("/var/lib/rule-change/containment",) if host == "a" else ()):
        path = Path(name)
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.lstat()
        if path.is_symlink() or not path.is_dir() or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError("unsafe workflow directory")
    subprocess.run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir",
                    "/opt/rule-view", "--shell", "/bin/bash", "ruleview"], check=True)
    subprocess.run(["usermod", "--password", "*", "ruleview"], check=True)
    user = pwd.getpwnam("ruleview")

    def write(name, content, mode, gid=0):
        path = Path(name)
        if path.is_symlink():
            raise ValueError("symlink refused")
        path.write_text(content)
        os.chown(path, 0, gid)
        os.chmod(path, mode)

    for name in ("/opt/rule-view", "/opt/rule-view/.ssh"):
        Path(name).mkdir(mode=0o750)
        os.chown(name, 0, user.pw_gid)
    # Public protocol code contains no credentials; broker config stays 0600.
    os.chmod("/opt/rule-change", 0o755)
    os.chmod("/opt/rule-change/rule_change_mcp.py", 0o644)
    write("/opt/rule-change/mcp-host", host + "\n", 0o644)
    wrapper = "/opt/rule-view/run-readonly.sh"
    write(wrapper, "#!/bin/sh\nexec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/python3 -I -B /opt/rule-change/rule_change_mcp.py --read-only\n", 0o750, user.pw_gid)
    write("/opt/rule-view/.ssh/authorized_keys", 'restrict,command="' + wrapper + '" ' + public_key + "\n", 0o640, user.pw_gid)
    sudo = "/etc/sudoers.d/capstone-rule-readonly"
    write(sudo, "Defaults:ruleview env_reset\nDefaults:ruleview !setenv\nruleview ALL=(root) NOPASSWD: /usr/local/sbin/rule-change-executor --read-only\n", 0o440)
    subprocess.run(["visudo", "-cf", sudo], check=True, stdout=subprocess.DEVNULL)
    write("/etc/ssh/sshd_config.d/63-capstone-rule-readonly.conf",
          "Match User ruleview\n    ForceCommand " + wrapper + "\n    AuthenticationMethods publickey\n"
          "    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    DisableForwarding yes\n"
          "    PermitTTY no\n    X11Forwarding no\n    PermitUserRC no\nMatch all\n", 0o644)
    subprocess.run(["sshd", "-t"], check=True)
