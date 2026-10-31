#!/usr/bin/env python3
"""Render the existing reviewed SOC engines for one fresh, immutable profile.

Only installation-time constants are adapted. Runtime callers never provide a
path, container name, command, approver, token, or profile. The original modules
remain unchanged; generated sources and their input hashes enter the receipt.
"""
import ast
import copy
import ipaddress
import json
import re


class Refused(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


def literal(value):
    return ast.parse(repr(value), mode="eval").body


def assigned(tree, name):
    nodes = [n for n in tree.body if isinstance(n, ast.Assign) and
             len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    need(len(nodes) == 1, "source_assignment_changed_" + name)
    return nodes[0]


def validate_profile(p):
    fields = {"schema", "role", "root", "security_host", "siem_host", "service_host",
              "agent_id", "interface", "machine_id", "docker", "hermes_uid", "hermes_gid",
              "manager_etc", "protected_ips", "waf_port", "container_ids", "dashboard_rw", "admin_protected_cidrs"}
    need(type(p) is dict and set(p) == fields and p["schema"] == 1, "profile_fields")
    need(p["role"] in ("a", "b"), "profile_role")
    need(p["root"] == "/opt/capstone", "fixed_bootstrap_root_required")
    addresses = [str(ipaddress.IPv4Address(p[k])) for k in ("security_host", "siem_host", "service_host")]
    need(len(set(addresses)) == 3 and all(ipaddress.ip_address(a).is_private for a in addresses), "profile_hosts")
    need(re.fullmatch(r"[0-9]{3,8}", p["agent_id"]) and p["agent_id"] != "000", "profile_agent")
    need(re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", p["interface"]), "profile_interface")
    need(re.fullmatch(r"[0-9a-f]{32}", p["machine_id"]), "profile_machine")
    need(p["docker"] in ("/usr/bin/docker", "/usr/local/bin/docker"), "profile_docker")
    need(all(type(p[k]) is int and 1 <= p[k] < 65534 for k in ("hermes_uid", "hermes_gid")), "profile_hermes_identity")
    need(p["manager_etc"] == "/var/lib/docker/volumes/capstone-siem_wazuh_etc/_data", "profile_manager_volume")
    need(type(p["waf_port"]) is int and 1024 <= p["waf_port"] <= 65535, "profile_waf_port")
    need(type(p["dashboard_rw"]) is bool, "profile_dashboard_mount")
    need(type(p["protected_ips"]) is list and 3 <= len(p["protected_ips"]) <= 128, "profile_protection")
    for value in p["protected_ips"]:
        need(str(ipaddress.IPv4Address(value)) == value, "profile_protected_address")
    need(set(addresses) <= set(p["protected_ips"]), "profile_protected_hosts")
    need(type(p["admin_protected_cidrs"]) is list and len(p["admin_protected_cidrs"]) <= 128, "profile_admin_networks")
    for value in p["admin_protected_cidrs"]:
        net = ipaddress.IPv4Network(value, strict=True)
        need(str(net) == value and net.prefixlen > 0, "profile_admin_CIDR")
    names = {"capstone-security-waf", "capstone-security-suricata"} if p["role"] == "a" else {
        "capstone-wazuh-manager", "capstone-wazuh-dashboard", "capstone-hermes", "capstone-mattermost"}
    need(set(p["container_ids"]) == names and all(re.fullmatch(r"[0-9a-f]{64}", value)
         for value in p["container_ids"].values()), "profile_container_ids")
    return p


def substitutions(p):
    root = p["root"]
    return {
        "/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf": root + "/security/config/GROOT_A_WAF.conf",
        "/home/groot_a/capstone/suricata/ruleset/GROOT_A_local.rules": root + "/security/rules/local.rules",
        "/home/groot_a/capstone/suricata/ruleset/suricata.rules": root + "/security/rules/suricata.rules",
        "/home/groot_a/capstone/suricata/ruleset/all.rules": root + "/security/rules/all.rules",
        "/home/groot_a/capstone/suricata/ruleset": root + "/security/rules",
        "/home/groot_a/capstone/secstack/logs/suricata/eve.json": root + "/security/logs/suricata/eve.json",
        "/home/groot_a/capstone/secstack/logs/suricata": root + "/security/logs/suricata",
        "/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/local_rules.xml": p["manager_etc"] + "/rules/capstone_portable_rules.xml",
        "/var/ossec/etc/rules/local_rules.xml": "/var/ossec/etc/rules/capstone_portable_rules.xml",
        "/var/lib/docker/volumes/single-node_wazuh_etc/_data/ossec.conf": p["manager_etc"] + "/ossec.conf",
        "/var/lib/docker/volumes/single-node_wazuh_etc/_data": p["manager_etc"],
        "/home/groot_b/capstone/wazuh/single-node/config/wazuh_cluster/wazuh_manager.conf": root + "/siem/wazuh/config/wazuh_cluster/wazuh_manager.conf",
        "https://10.200.10.10:8445": "https://" + p["siem_host"] + ":8445",
        "/usr/local/bin/docker": "/usr/local/libexec/capstone-soc-docker",
        "001": p["agent_id"], "ens192": p["interface"],
        "096e90b6243e438aa8a7b392be754732": p["machine_id"],
    }


class Bindings(ast.NodeTransformer):
    def __init__(self, mapping, containers):
        self.mapping, self.containers = mapping, containers

    def visit_Constant(self, node):
        if isinstance(node.value, str) and node.value in self.mapping:
            return ast.copy_location(ast.Constant(self.mapping[node.value]), node)
        return node

    def visit_List(self, node):
        # Container position only. Never change executable "suricata" or the
        # candidate-validation kind "waf" / "suricata".
        if len(node.elts) > 2 and isinstance(node.elts[0], ast.Name) and node.elts[0].id == "DOCKER" and \
                isinstance(node.elts[1], ast.Constant) and node.elts[1].value == "exec" and \
                isinstance(node.elts[2], ast.Constant) and node.elts[2].value in self.containers:
            node.elts[2] = ast.Constant(self.containers[node.elts[2].value])
        return self.generic_visit(node)


def replace_profile_paths(value, mapping, containers):
    if isinstance(value, dict):
        return {k: containers.get(v, v) if k == "container" else replace_profile_paths(v, mapping, containers)
                for k, v in value.items()}
    if isinstance(value, list):
        return [replace_profile_paths(v, mapping, containers) for v in value]
    if isinstance(value, str):
        return mapping.get(value, value)
    return value


def render(name, raw, profile, run_source=None):
    """Pure transform, suitable for tests with no system or network access."""
    p = validate_profile(profile)
    tree = ast.parse(raw)
    mapping = substitutions(p)
    containers = {"waf": "capstone-security-waf", "suricata": "capstone-security-suricata",
                  "single-node-wazuh.manager-1": "capstone-wazuh-manager",
                  "single-node-wazuh.dashboard-1": "capstone-wazuh-dashboard"}
    if name == "rule_change_mcp.py":
        node = assigned(tree, "SERVICE_TARGETS")
        node.value = literal([target for target in ast.literal_eval(node.value) if target != "a:chatproxy"])
    if name == "security_rule_inventory.py" and p["role"] == "b":
        assigned(tree, "WAZUH_CREDENTIALS").value = literal(p["root"] + "/siem/capstone-mcp/credentials.json")
        assigned(tree, "WAZUH_CREDENTIAL_FORMAT").value = literal("json")
        assigned(tree, "WAZUH_API_HOST").value = literal(p["siem_host"])
        assigned(tree, "WAZUH_API_USER").value = literal("capstone-ro")
    if name == "rule_change_executor.py":
        node = assigned(tree, "TARGETS")
        node.value = literal(replace_profile_paths(ast.literal_eval(node.value), mapping, containers))
        # Use full IDs for fixed runtime calls. A stopped/replaced container may
        # never be silently adopted by its convenient Docker name.
        target = ast.literal_eval(node.value)
        target = {k: v for k, v in target.items() if v["host"] == p["role"]}
        for spec in target.values():
            spec["container"] = p["container_ids"][spec["container"]]
            if spec["kind"] == "wazuh":
                spec["startup_path"] = p["root"] + "/siem/wazuh/capstone-local-rules.xml"
        node.value = literal(target)
        containers = {k: p["container_ids"][v] for k, v in containers.items() if v in p["container_ids"]}
    if name == "service_action_executor.py":
        node = assigned(tree, "PROFILES")
        need(isinstance(node.value, ast.Dict), "service_profile_shape")
        pairs = [(k, v) for k, v in zip(node.value.keys, node.value.values) if ast.literal_eval(k) != "a:chatproxy"]
        node.value = ast.Dict(keys=[k for k, _ in pairs], values=[v for _, v in pairs])
        profiles = replace_profile_paths(ast.literal_eval(node.value), mapping, containers)
        profiles = {k: v for k, v in profiles.items() if v["host"] == p["role"]}
        for value in profiles.values():
            if not value['kind'].startswith('systemd-'):
                value["expected_id"] = p["container_ids"][value["container"]]
        if "a:waf" in profiles:
            profiles["a:waf"]["probe"] = {"port": p["waf_port"], "path": "/dvwa/login.php", "host": "capstone-service", "marker": "DVWA"}
        if "b:wazuh-dashboard" in profiles:
            base = p["root"] + "/siem/"
            profiles["b:wazuh-dashboard"].update(
                files=[base + "wazuh/config/wazuh_dashboard/opensearch_dashboards.yml", base + "tls/wazuh.dashboard.pem"],
                mounts=[[base + "wazuh/config/wazuh_dashboard/opensearch_dashboards.yml", "/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml", p["dashboard_rw"]]],
                probe={"port": 443, "path": "/app/login", "host": "wazuh.dashboard", "marker": "OpenSearch Dashboards", "certificate": base + "tls/wazuh.dashboard.pem"})
        node.value = literal(profiles)
        # Preserve original name/mount checks and add the installation receipt.
        functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "observe"]
        need(len(functions) == 1, "service_observe_source")
        guards = [n for n in ast.walk(functions[0]) if isinstance(n, ast.If) and
                  any(isinstance(x, ast.Constant) and x.value == "service container identity mismatch" for x in ast.walk(n))]
        need(len(guards) == 1, "service_identity_guard_source")
        guards[0].test = ast.BoolOp(ast.Or(), [guards[0].test, ast.parse("cid != profile['expected_id']", mode="eval").body])
        mapping["127.0.0.1"] = p["security_host"] if p["role"] == "a" else p["siem_host"]
    if name == "incident_containment.py":
        # The managed reader keeps the exact source pins / current generation /
        # three-hardlink provenance contract. No legacy fallback is introduced.
        destinations = tuple(ipaddress.ip_network(x + "/32") for x in
                             (p["security_host"], p["siem_host"], p["service_host"]))
        assigned(tree, "DESTINATIONS").value = ast.parse("tuple(ipaddress.ip_network(x) for x in " + repr(tuple(map(str, destinations))) + ")", mode="eval").body
        original = assigned(tree, "PROTECTED")
        original.value = ast.BinOp(original.value, ast.Add(), ast.parse(
            "tuple(ipaddress.ip_network(x) for x in " + repr([x + "/32" for x in p["protected_ips"]] + p["admin_protected_cidrs"]) + ")", mode="eval").body)
    if name == "soc_management_run.py":
        class Identity(ast.NodeTransformer):
            def visit_Constant(self, node):
                if type(node.value) is int and node.value in (995, 986):
                    return ast.Constant(p["hermes_uid"] if node.value == 995 else p["hermes_gid"])
                return node
        tree = Identity().visit(tree)
    if name == "soc_management_controller.py":
        need(isinstance(run_source, bytes), "immutable_management_gate_required")
        commands = [n for n in ast.walk(tree) if isinstance(n, ast.List) and
                    any(isinstance(x, ast.Constant) and x.value == "/opt/data/management-code/run.py" for x in n.elts)]
        need(len(commands) == 1, "management_command_source")
        node = commands[0]
        index = next(i for i, x in enumerate(node.elts) if isinstance(x, ast.Constant) and x.value == "/opt/data/management-code/run.py")
        node.elts[index:index + 1] = [ast.Constant("-I"), ast.Constant("-B"), ast.Constant("-c"), ast.Constant(run_source.decode())]
        mapping.update({"995:986": str(p["hermes_uid"]) + ":" + str(p["hermes_gid"]),
                        "hermes": p["container_ids"]["capstone-hermes"],
                        "http://10.200.10.": "http://" + p["siem_host"] + ":8065/hooks/"})
        assigned(tree, "SERVICE_TARGETS").value = ast.parse("frozenset(('a:waf','a:suricata','b:wazuh-manager','b:wazuh-dashboard','a:vector','a:wazuh-agent','b:wazuh-agent'))", mode="eval").body
    if name == "soc_bot.py":
        # New installs have a private CA, so preserve real chain/IP validation.
        assigned(tree, "CTX").value = ast.parse("ssl.create_default_context(cafile='/etc/socbot/root-ca.pem')", mode="eval").body
    if name == "response-mcp.py":
        # The shared source now bounds legacy and fresh installations equally.
        # Refuse a source shape that could silently restore unbounded stdin.
        need(ast.literal_eval(assigned(tree, "MAX_RPC_CHARS").value) == 65536, "response_stdio_limit")
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        reads = [n for n in ast.walk(main) if isinstance(n, ast.Call) and
                 ast.unparse(n.func) == "sys.stdin.readline"]
        guards = [n for n in ast.walk(main) if isinstance(n, ast.If) and
                  ast.unparse(n.test) == "len(line) > MAX_RPC_CHARS"]
        need(len(reads) == 1 and len(reads[0].args) == 1 and
             ast.unparse(reads[0].args[0]) == "MAX_RPC_CHARS + 1" and
             len(guards) == 1 and any(isinstance(n, ast.Return) for n in guards[0].body), "response_stdio_source")
    tree = Bindings(mapping, containers).visit(tree)
    if name == "rule_change_executor.py" and p["role"] == "b":
        # The official manager copies its config-mount inputs on restart. Bind
        # live and startup bytes to the same exact approval, backup and rollback.
        extension = ast.parse(WAZUH_MIRROR)
        index = next(i for i, n in enumerate(tree.body) if isinstance(n, ast.If) and
                     isinstance(n.test, ast.Compare) and isinstance(n.test.left, ast.Name) and n.test.left.id == "__name__")
        tree.body[index:index] = extension.body
    ast.fix_missing_locations(tree)
    data = ("#!/usr/bin/python3 -IB\n# Installation-bound copy; edit source, not this generated file.\n" + ast.unparse(tree) + "\n").encode()
    compile(data, name, "exec")
    return data


WAZUH_MIRROR = '''
class PortableEngine(Engine):
    def _snapshot(self, spec):
        current, metadata, aux = super()._snapshot(spec)
        if spec["kind"] == "wazuh":
            startup, _ = _read_regular(spec["startup_path"])
            if startup != current:
                raise RuleChangeError("Wazuh live/startup rules drifted")
            aux["startup_sha256"] = sha256(startup)
        return current, metadata, aux

    def _backup(self, record, name, path):
        super()._backup(record, name, path)
        if name == "primary":
            spec = self.spec(record["payload"]["target"])
            if spec["kind"] == "wazuh":
                super()._backup(record, "startup", spec["startup_path"])

    def _service_apply(self, spec, record, candidate):
        if spec["kind"] == "wazuh":
            startup, meta = _read_regular(spec["startup_path"])
            backup = record["backups"]["startup"]
            if sha256(startup) != record["aux"]["startup_sha256"] or meta.st_ino != backup["inode"]:
                raise RuleChangeError("Wazuh startup rules changed since approval")
            _inplace_bytes(spec["startup_path"], candidate, backup["inode"])
        super()._service_apply(spec, record, candidate)
        if spec["kind"] == "wazuh" and _read_regular(spec["startup_path"])[0] != candidate:
            raise RuleChangeError("Wazuh startup candidate readback failed")

    def _restore(self, record, spec):
        super()._restore(record, spec)
        if spec["kind"] == "wazuh":
            backup = record["backups"].get("startup")
            if not backup:
                raise RuleChangeError("Wazuh startup backup unavailable")
            data, _ = _read_regular(backup["path"])
            if sha256(data) != backup["sha256"]:
                raise RuleChangeError("Wazuh startup backup hash mismatch")
            _inplace_bytes(spec["startup_path"], data, backup["inode"])

Engine = PortableEngine
'''


def protected_networks(protected, admin_networks=()):
    addresses = set(protected)
    for value in addresses:
        need(str(ipaddress.IPv4Address(value)) == value, "firewall_address")
    networks = ["0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "211.170.162.0/24",
                "168.126.63.1/32", "168.126.63.2/32", "8.8.8.8/32", "8.8.4.4/32", "1.1.1.1/32",
                "1.0.0.1/32", "9.9.9.9/32"]
    nets = list(ipaddress.collapse_addresses([ipaddress.ip_network(n) for n in networks] +
                                           [ipaddress.ip_network(a + "/32") for a in addresses] +
                                           [ipaddress.IPv4Network(a, strict=True) for a in admin_networks]))
    need(all(n.prefixlen > 0 for n in nets), "firewall_zero_network_refused")
    return nets


def firewall(protected, admin_networks=()):
    items = ", ".join(map(str, protected_networks(protected, admin_networks)))
    return ("table inet capstone_fw {\n set never_block { type ipv4_addr; flags interval; elements = { " + items + " }; }\n"
            " set agent_block { type ipv4_addr; flags timeout; timeout 10m; }\n"
            " chain input { type filter hook input priority -6; policy accept; ip saddr @never_block accept; "
            'ip saddr @agent_block log prefix "GROOT-FW BLOCK " drop; }\n'
            " chain forward { type filter hook forward priority -6; policy accept; ip saddr @never_block accept; "
            'ip saddr @agent_block log prefix "GROOT-FW BLOCK " drop; }\n}\n').encode()


def verify_firewall(value, protected, admin_networks=()):
    """Check native nft JSON semantics, including actual protected elements."""
    need(type(value) is dict and type(value.get("nftables")) is list, "nft_JSON_shape")
    sets, chains, rules = {}, {}, {"input": [], "forward": []}
    for row in value["nftables"]:
        need(type(row) is dict and len(row) == 1, "nft_object_shape")
        kind, obj = next(iter(row.items()))
        if kind == "metainfo":
            continue
        need(kind in ("table", "set", "chain", "rule") and obj.get("family") == "inet" and
             (obj.get("name") == "capstone_fw" if kind == "table" else obj.get("table") == "capstone_fw"), "nft_scope")
        if kind == "set":
            need(obj["name"] not in sets, "duplicate_nft_set"); sets[obj["name"]] = obj
        elif kind == "chain":
            need(obj["name"] not in chains, "duplicate_nft_chain"); chains[obj["name"]] = obj
        elif kind == "rule":
            need(obj.get("chain") in rules, "unexpected_nft_rule_chain")
            rules[obj["chain"]].append(obj.get("expr"))
    need(set(sets) == {"never_block", "agent_block"} and set(chains) == set(rules), "nft_exact_objects")
    need(sets["never_block"].get("type") == "ipv4_addr" and sets["never_block"].get("flags") == ["interval"] and
         sets["agent_block"].get("type") == "ipv4_addr" and sets["agent_block"].get("flags") == ["timeout"], "nft_set_types")
    observed = []
    for element in sets["never_block"].get("elem", []):
        if type(element) is str:
            observed.append(ipaddress.IPv4Network(element, strict=True))
        elif type(element) is dict and set(element) == {"prefix"}:
            prefix = element["prefix"]
            need(set(prefix) == {"addr", "len"}, "nft_prefix_shape")
            observed.append(ipaddress.IPv4Network(str(prefix["addr"]) + "/" + str(prefix["len"]), strict=True))
        else:
            raise Refused("unsupported_nft_protected_element")
    need(list(ipaddress.collapse_addresses(observed)) == protected_networks(protected, admin_networks), "nft_protected_elements_changed")
    match = lambda name: {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@" + name}}
    expected = [[match("never_block"), {"accept": None}],
                [match("agent_block"), {"log": {"prefix": "GROOT-FW BLOCK "}}, {"drop": None}]]
    for name, chain in chains.items():
        need(chain.get("type") == "filter" and chain.get("hook") == name and chain.get("prio") == -6 and
             chain.get("policy") == "accept" and rules[name] == expected, "nft_chain_or_drop_order_changed")
    return True


def verify_agent_ar(raw):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(b"<capstone>" + raw + b"</capstone>")
    need(all(block.tag == "ossec_config" for block in root), "agent_config_roots")
    clients = [client for block in root for client in block.findall("client")]
    need(len(clients) == 1 and len(clients[0].findall("disable-active-response")) == 1 and
         clients[0].findtext("disable-active-response") == "no", "agent_AR_not_enabled")
    return True


def manager_ar(raw, agent_id):
    import xml.etree.ElementTree as ET
    need(re.fullmatch(r"[0-9]{3,8}", agent_id) and agent_id != "000", "AR_agent")
    root = ET.fromstring(b"<capstone>" + raw + b"</capstone>")
    need(all(n.tag == "ossec_config" for n in root), "manager_config_shape")
    need(not any((n.findtext("name") == "capstone-containment" or n.findtext("command") == "capstone-containment")
                 for block in root for n in block if n.tag in ("command", "active-response")), "AR_already_exists")
    addition = ('\n<ossec_config><command><name>capstone-containment</name><executable>capstone-containment</executable>'
                '<timeout_allowed>no</timeout_allowed></command><active-response><disabled>no</disabled>'
                '<command>capstone-containment</command><location>defined-agent</location><agent_id>' + agent_id +
                '</agent_id><rules_id>100110</rules_id></active-response></ossec_config>\n').encode()
    return raw + addition


def agent_ar(raw):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(b"<capstone>" + raw + b"</capstone>")
    need(all(node.tag == "ossec_config" for node in root), "agent_AR_shape")
    clients = [client for block in root for client in block.findall("client")]
    need(len(clients) == 1, "agent_client_not_unique")
    flags = clients[0].findall("disable-active-response")
    need(len(flags) == 1 and flags[0].text == "yes", "agent_AR_disabled_baseline_required")
    spans = list(re.finditer(rb"<client\s*>.*?</client\s*>", raw, re.S))
    need(len(spans) == 1, "agent_client_source")
    block = spans[0].group()
    pattern = rb"(<disable-active-response\s*>\s*)yes(\s*</disable-active-response\s*>)"
    need(len(re.findall(pattern, block)) == 1, "agent_AR_source")
    new = re.sub(pattern, rb"\g<1>no\g<2>", block)
    return raw[:spans[0].start()] + new + raw[spans[0].end():]
