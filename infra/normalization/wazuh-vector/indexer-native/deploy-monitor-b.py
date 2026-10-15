#!/usr/bin/env python3
"""Root-only, one-shot operator CLI; never an MCP tool or a persistent service.

Prepare/inspect is read-only. Each mutating operation is an explicit operator
step. No retry of an uncertain POST/PUT, automatic name adoption, or deletion.
Only existing B Docker/curl/certificates and Python's standard library are used.
"""
import argparse
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import time


SOURCE_SHA = "f0262be494e605edcb22fb32f71f4854014dd4f671b035803886a5b1036bafd1"
NAME = "capstone-evidence-observation-v1"
MACHINE_ID = "1e143067c98a44ffba6eaa925dc038d7"
CONTAINER = "single-node-wazuh.indexer-1"
DOCKER = "/usr/local/bin/docker"
API = "/_plugins/_alerting/monitors"
STATE_DIR = Path("/var/lib/capstone-automation/indexer-observation")
MAX_RESPONSE = 2 * 1024 * 1024


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def nonfinite(_):
        raise Refused("nonfinite_json")
    def finite_float(value):
        result = float(value)
        require(math.isfinite(result), "nonfinite_json")
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)
    except (ValueError, UnicodeError) as error:
        raise Refused("invalid_json") from error


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def config_digest(monitor):
    # These are server lifecycle fields, not query, scripts, permissions, or actions.
    return digest({key: value for key, value in monitor.items()
                   if key not in {"enabled", "enabled_time", "last_update_time"}})


def keys_only(value, allowed):
    require(isinstance(value, dict) and set(value) <= set(allowed), "unexpected_query_field")


def unboost(value):
    value = copy.deepcopy(value)
    boost = value.pop("boost", 1.0)
    require(type(boost) in (int, float) and boost == 1.0, "query_boost_changed")
    return value


def canonical_clause(clause):
    require(isinstance(clause, dict) and len(clause) == 1, "invalid_query_clause")
    kind, original = next(iter(clause.items()))
    if kind == "bool":
        value = unboost(original)
        keys_only(value, {"filter", "must", "must_not", "should", "minimum_should_match", "adjust_pure_negative"})
        require(value.pop("adjust_pure_negative", True) is True, "query_negative_policy_changed")
        result = {}
        for name in ("filter", "must", "must_not", "should"):
            rows = value.get(name, [])
            require(isinstance(rows, list), "invalid_bool_query_list")
            result[name] = [canonical_clause(row) for row in rows]
        minimum = value.get("minimum_should_match")
        require(minimum is None or type(minimum) is int or isinstance(minimum, str), "invalid_minimum_should_match")
        result["minimum_should_match"] = None if minimum is None else str(minimum)
        return {kind: result}
    if kind in {"term", "regexp", "range"}:
        require(isinstance(original, dict) and len(original) == 1, "invalid_field_query")
        field, value = next(iter(original.items()))
        if kind == "term":
            value = {"value": value} if not isinstance(value, dict) else value
            value = unboost(value)
            keys_only(value, {"value", "case_insensitive"})
            require(value.pop("case_insensitive", False) is False, "query_case_policy_changed")
        elif kind == "regexp":
            value = {"value": value} if isinstance(value, str) else value
            value = unboost(value)
            keys_only(value, {"value", "flags_value", "max_determinized_states", "case_insensitive"})
            require(type(value.get("flags_value", 255)) is int and value.pop("flags_value", 255) == 255,
                    "regexp_flags_changed")
            require(type(value.get("max_determinized_states", 10000)) is int
                    and value.pop("max_determinized_states", 10000) == 10000, "regexp_work_limit_changed")
            require(value.pop("case_insensitive", False) is False, "query_case_policy_changed")
        else:
            value = unboost(value)
            keys_only(value, {"gte", "lte", "from", "to", "include_lower", "include_upper"})
            require(not ("gte" in value and "from" in value) and not ("lte" in value and "to" in value),
                    "ambiguous_range_query")
            require(value.get("include_lower", True) is True and value.get("include_upper", True) is True,
                    "range_boundary_changed")
            value = {"gte": value.get("gte", value.get("from")), "lte": value.get("lte", value.get("to"))}
        return {kind: {field: value}}
    if kind == "terms":
        value = unboost(original)
        require(len(value) == 1 and isinstance(next(iter(value.values())), list), "invalid_terms_query")
        return {kind: value}
    if kind == "script":
        value = unboost(original)
        keys_only(value, {"script"})
        return {kind: value}  # exact source, language and params; no script substitutions
    raise Refused("unexpected_query_clause")


def canonical_aggs(aggregations):
    require(isinstance(aggregations, dict), "invalid_aggregations")
    result = {}
    for name, aggregate in aggregations.items():
        keys_only(aggregate, {"terms", "aggs", "aggregations"})
        require("terms" in aggregate and not ("aggs" in aggregate and "aggregations" in aggregate),
                "unexpected_aggregation_type")
        terms = copy.deepcopy(aggregate["terms"])
        keys_only(terms, {"field", "size", "order", "min_doc_count", "shard_min_doc_count",
                          "show_term_doc_count_error", "shard_size"})
        for key, expected in (("min_doc_count", 1), ("shard_min_doc_count", 0), ("shard_size", -1)):
            require(type(terms.get(key, expected)) is int and terms.pop(key, expected) == expected,
                    "aggregation_default_changed")
        require(terms.pop("show_term_doc_count_error", False) is False, "aggregation_error_policy_changed")
        order = terms.get("order")
        terms["order"] = order if isinstance(order, list) else [order]
        result[name] = {"terms": terms, "aggs": canonical_aggs(aggregate.get("aggs", aggregate.get("aggregations", {})))}
    return result


def canonical_search(search):
    keys_only(search, {"indices", "query"})
    query = search.get("query", {})
    keys_only(query, {"size", "_source", "timeout", "track_total_hits", "terminate_after", "query", "aggs", "aggregations"})
    require(not ("aggs" in query and "aggregations" in query), "ambiguous_aggregations")
    result = copy.deepcopy(query)
    result.pop("aggs", None)
    result.pop("aggregations", None)
    hits = result.get("track_total_hits")
    require(hits is True or type(hits) is int and hits == 2147483647, "exact_hits_tracking_changed")
    result["track_total_hits"] = True
    result["query"] = canonical_clause(query.get("query"))
    result["aggs"] = canonical_aggs(query.get("aggs", query.get("aggregations", {})))
    return {"indices": search["indices"], "query": result}


def validate_monitor(monitor, candidate, enabled):
    require(isinstance(monitor, dict), "invalid_monitor")
    for key in ("type", "name", "monitor_type", "schedule"):
        require(monitor.get(key) == candidate[key], "monitor_identity_or_schedule_changed")
    require(monitor.get("enabled") is enabled, "monitor_enabled_state_mismatch")
    inputs = monitor.get("inputs")
    require(isinstance(inputs, list) and len(inputs) == 1, "monitor_inputs_changed")
    require(isinstance(inputs[0], dict) and set(inputs[0]) == {"search"}, "monitor_input_type_changed")
    search = inputs[0].get("search", {})
    require(search.get("indices") == ["wazuh-alerts-*"], "monitor_indices_changed")
    query = search.get("query", {})
    require(type(query.get("size")) is int and query.get("size") == 0 and query.get("_source") is False,
            "monitor_hit_privacy_changed")
    require(canonical_search(search) == canonical_search(candidate["inputs"][0]["search"]),
            "monitor_query_semantics_changed")
    actual = monitor.get("triggers")
    require(isinstance(actual, list) and len(actual) == 2, "monitor_triggers_changed")
    for wanted, row in zip(candidate["triggers"], actual):
        item = row.get("query_level_trigger", row)
        expected = wanted["query_level_trigger"]
        for key in ("id", "name", "severity", "condition", "actions"):
            require(item.get(key) == expected[key], "monitor_trigger_or_actions_changed")


def safe_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,200}", value),
            "invalid_monitor_id")
    return value


def revision(response):
    require(isinstance(response, dict), "invalid_api_response")
    safe_id(response.get("_id"))
    for key in ("_seq_no", "_primary_term"):
        require(type(response.get(key)) is int and response[key] >= 0,
                "missing_api_cas_revision")
    require(response["_primary_term"] > 0, "invalid_primary_term")
    return {key: response[key] for key in ("_id", "_seq_no", "_primary_term")}


def protected(path, directory=False, private=False):
    item = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    require(kind(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022,
            "unsafe_root_path")
    require(directory or item.st_nlink == 1, "unsafe_hardlinked_file")
    require(not private or item.st_mode & 0o077 == 0, "unsafe_private_permissions")


class StateStore:
    def __init__(self, path):
        self.path = path

    def read(self):
        if not self.path.exists() and not self.path.is_symlink():
            return None
        protected(self.path, private=True)
        require(self.path.stat().st_size <= MAX_RESPONSE, "state_too_large")
        value = strict_json(self.path.read_bytes())
        require(isinstance(value, dict) and value.get("candidate_sha256") == SOURCE_SHA,
                "state_source_mismatch")
        return value

    def write(self, value):
        data = json.dumps(value, sort_keys=True, allow_nan=False).encode() + b"\n"
        descriptor, temporary = tempfile.mkstemp(prefix=".state-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.exists() or self.path.is_symlink():
                protected(self.path, private=True)
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class CurlAPI:
    def __init__(self):
        result = subprocess.run([DOCKER, "inspect", "--format", "{{.Id}} {{.State.Running}}", CONTAINER],
                                capture_output=True, timeout=10, check=False)
        require(result.returncode == 0, "indexer_container_unavailable")
        value = result.stdout.decode("ascii", "strict").strip().split()
        require(len(value) == 2 and re.fullmatch(r"[0-9a-f]{64}", value[0])
                and value[1] == "true", "indexer_container_identity_invalid")
        self.container_id = value[0]

    def __call__(self, method, path, payload=None, expected=(200,)):
        require(path.startswith(API) or path == "/_plugins/_alerting/stats", "unexpected_api_path")
        cert = "/usr/share/wazuh-indexer/config/certs/"
        command = [DOCKER, "exec", "-i", self.container_id, "curl", "--disable", "--silent", "--show-error",
                   "--max-time", "35", "--max-filesize", str(MAX_RESPONSE),
                   "--noproxy", "*",
                   "--cacert", cert + "root-ca.pem", "--cert", cert + "admin.pem",
                   "--key", cert + "admin-key.pem", "-H", "Content-Type: application/json",
                   "-X", method, "-w", "\n%{http_code}", "https://wazuh.indexer:9200" + path]
        body = None
        if payload is not None:
            command += ["--data-binary", "@-"]
            body = json.dumps(payload, allow_nan=False).encode()
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESPONSE + 4096, MAX_RESPONSE + 4096))
        # Response stays in a private anonymous B file, not an unbounded pipe/Mac log.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            # Never let docker exec -i consume the operator's remaining SSH script.
            input_options = {"stdin": subprocess.DEVNULL} if body is None else {"input": body}
            result = subprocess.run(command, **input_options, stdout=output, stderr=errors,
                                    timeout=45, preexec_fn=limits, check=False)
            require(result.returncode == 0, "indexer_request_failed_or_reply_uncertain")
            output.seek(0)
            raw = output.read(MAX_RESPONSE + 1)
        require(len(raw) <= MAX_RESPONSE, "api_response_too_large")
        try:
            content, status = raw.rsplit(b"\n", 1)
            status = int(status)
        except (ValueError, TypeError) as error:
            raise Refused("invalid_http_status") from error
        value = strict_json(content)
        require(status in expected, "indexer_http_" + str(status))
        return status, value


def exact_names(api):
    status, result = api("GET", API + "/_search", {
        "size": 100, "track_total_hits": True,
        "query": {"match": {"monitor.name": NAME}},
    }, expected=(200, 404))
    if status == 404:
        error = result.get("error", {})
        causes = [error] + error.get("root_cause", []) if isinstance(error, dict) else []
        wrapped = error.get("caused_by", {}) if isinstance(error, dict) else {}
        # Installed Alerting 2.19.6.0 wraps IndexNotFoundException and drops its
        # structured index field. Accept only this exact observed missing index.
        exact_wrapped_missing = (isinstance(error, dict) and error.get("type") == "alerting_exception"
                                 and isinstance(wrapped, dict) and wrapped.get("type") == "exception"
                                 and wrapped.get("reason") == "org.opensearch.index.IndexNotFoundException: no such index [.opendistro-alerting-config]")
        require(exact_wrapped_missing or any(row.get("type") == "index_not_found_exception"
                    and row.get("index") == ".opendistro-alerting-config" for row in causes),
                "unexpected_monitor_search_404")
        return []
    require(result.get("timed_out") is False, "monitor_name_search_timed_out")
    shards = result.get("_shards", {})
    require(shards.get("failed") == 0 and shards.get("successful") == shards.get("total")
            and type(shards.get("total")) is int and shards["total"] > 0,
            "monitor_name_search_partial")
    hits = result.get("hits", {})
    total = hits.get("total")
    if isinstance(total, dict):
        require(total.get("relation") == "eq", "monitor_name_search_inexact")
        total = total.get("value")
    rows = hits.get("hits")
    require(type(total) is int and 0 <= total <= 100 and isinstance(rows, list)
            and len(rows) == total, "monitor_name_search_overflow")
    matched = []
    for row in rows:
        source = row.get("_source", {})
        if isinstance(source.get("monitor"), dict):
            source = source["monitor"]
        if source.get("name") == NAME:
            matched.append(safe_id(row.get("_id")))
    require(len(matched) <= 1, "duplicate_exact_monitor_names")
    return matched


def saved_record(response, candidate, enabled):
    rev = revision(response)
    monitor = response.get("monitor")
    validate_monitor(monitor, candidate, enabled)
    return {"candidate_sha256": SOURCE_SHA, "phase": "enabled" if enabled else "disabled",
            **rev, "monitor_sha256": digest(monitor), "config_sha256": config_digest(monitor),
            "verified_at_epoch_ms": time.time_ns() // 1000000}


def get_owned(api, state, candidate):
    require(state is not None, "monitor_not_managed")
    require(state.get("phase") in {"disabled", "enabled"}, "previous_mutation_uncertain")
    require(exact_names(api) == [state["_id"]], "managed_monitor_name_identity_changed")
    _, response = api("GET", API + "/" + safe_id(state["_id"]))
    actual = saved_record(response, candidate, state["phase"] == "enabled")
    for key in ("_id", "_seq_no", "_primary_term", "monitor_sha256", "config_sha256"):
        require(actual[key] == state[key], "managed_monitor_changed_since_last_verify")
    return response


def operate(operation, api, store, candidate):
    state = store.read()
    if operation == "inspect":
        names = exact_names(api)
        result = {"operation": operation, "exact_name_count": len(names), "monitor_ids": names,
                  "candidate_sha256": SOURCE_SHA, "state_phase": state.get("phase") if state else None,
                  "mutated": False}
        if state and state.get("phase") in {"enabled", "disabled"}:
            get_owned(api, state, candidate)
            result.update({"managed_config_verified": True, "enabled": state["phase"] == "enabled"})
        elif len(names) == 1:
            _, observed = api("GET", API + "/" + names[0])
            rev = revision(observed)
            monitor = observed.get("monitor", {})
            require(type(monitor.get("enabled")) is bool, "invalid_observed_enabled")
            validate_monitor(monitor, candidate, monitor["enabled"])
            result.update({"managed_config_verified": False, "observed_enabled": monitor["enabled"],
                           "observed_revision": rev, "observed_config_sha256": config_digest(monitor),
                           "automatic_adoption_allowed": False})
        return result
    if operation == "observe":
        get_owned(api, state, candidate)
        _, stats = api("GET", "/_plugins/_alerting/stats")
        nodes = stats.get("_nodes", {})
        require(nodes.get("failed") == 0 and nodes.get("successful") == nodes.get("total")
                and type(nodes.get("total")) is int and nodes["total"] > 0, "scheduler_stats_partial")
        executions = []
        for node in stats.get("nodes", {}).values():
            job = node.get("jobs_info", {}).get(state["_id"])
            if job is None:
                continue
            require(isinstance(job, dict), "invalid_scheduler_job")
            last = job.get("last_execution_time")
            require(last is None or type(last) is int and last > 0, "invalid_execution_timestamp")
            require(type(job.get("running_on_time")) is bool, "invalid_scheduler_timeliness")
            executions.append({"last_execution_time": last, "running_on_time": job["running_on_time"]})
        return {"operation": operation, "monitor_id": state["_id"], "enabled": state["phase"] == "enabled",
                "observed_at_epoch_ms": time.time_ns() // 1000000, "scheduler_executions": executions,
                "proves_query_or_delivery_success": False, "mutated": False}
    if operation == "create-disabled":
        if state:
            get_owned(api, state, candidate)
            require(state["phase"] == "disabled", "already_enabled_use_inspect")
            return {"operation": operation, "changed": False, "monitor_id": state["_id"], "enabled": False}
        require(exact_names(api) == [], "unmanaged_same_name_monitor_do_not_adopt")
        store.write({"candidate_sha256": SOURCE_SHA, "phase": "create_pending"})
        _, created = api("POST", API, candidate, expected=(200, 201))
        rev = revision(created)
        store.write({"candidate_sha256": SOURCE_SHA, "phase": "create_readback_pending", **rev})
        record = saved_record(created, candidate, False)
        # The trusted API parses/re-renders defaults. Bind that exact server result
        # to this acknowledged POST revision, then compare an independent GET.
        require(exact_names(api) == [record["_id"]], "post_create_name_not_unique")
        _, fetched = api("GET", API + "/" + record["_id"])
        readback = saved_record(fetched, candidate, False)
        for key in ("_id", "_seq_no", "_primary_term", "monitor_sha256", "config_sha256"):
            require(readback[key] == record[key], "create_readback_changed")
        store.write(readback)
        return {"operation": operation, "changed": True, "monitor_id": record["_id"], "enabled": False,
                "server_config_sha256": record["config_sha256"], "actions": 0}
    require(operation in {"enable", "disable"}, "invalid_operation")
    current = get_owned(api, state, candidate)
    wanted_enabled = operation == "enable"
    if current["monitor"]["enabled"] is wanted_enabled:
        return {"operation": operation, "changed": False, "monitor_id": state["_id"], "enabled": wanted_enabled}
    body = copy.deepcopy(current["monitor"])
    body["enabled"] = wanted_enabled
    # The API assigns its own lifecycle timestamps; all query/user/default fields
    # round-trip from the verified existing monitor, never arbitrary operator JSON.
    body.pop("enabled_time", None)
    body.pop("last_update_time", None)
    store.write({**state, "phase": operation + "_pending"})
    path = API + "/" + state["_id"] + "?if_seq_no=" + str(state["_seq_no"]) + "&if_primary_term=" + str(state["_primary_term"])
    _, updated = api("PUT", path, body)
    next_state = saved_record(updated, candidate, wanted_enabled)
    same_configuration = next_state["config_sha256"] == state["config_sha256"]
    if not same_configuration:
        # Installed Alerting 2.19.6.0 creates schema 0 but its UPDATE path stamps
        # IndexUtils.scheduledJobIndexSchemaVersion (8). Permit this one observed
        # transition only when every other configuration byte-equivalent value
        # still matches the prior server canonical hash (including permissions).
        prior_schema = current["monitor"].get("schema_version")
        next_schema = updated["monitor"].get("schema_version")
        if type(prior_schema) is int and prior_schema == 0 and type(next_schema) is int and next_schema == 8:
            without_migration = copy.deepcopy(updated["monitor"])
            without_migration["schema_version"] = 0
            same_configuration = config_digest(without_migration) == state["config_sha256"]
    require(next_state["_id"] == state["_id"] and next_state["_primary_term"] >= state["_primary_term"]
            and next_state["_seq_no"] > state["_seq_no"]
            and same_configuration, "update_config_or_revision_changed")
    require(exact_names(api) == [state["_id"]], "post_update_name_not_unique")
    _, fetched = api("GET", API + "/" + state["_id"])
    readback = saved_record(fetched, candidate, wanted_enabled)
    for key in ("_id", "_seq_no", "_primary_term", "monitor_sha256", "config_sha256"):
        require(readback[key] == next_state[key], "update_readback_changed")
    store.write(readback)
    return {"operation": operation, "changed": True, "monitor_id": state["_id"],
            "enabled": wanted_enabled, "server_config_sha256": readback["config_sha256"], "actions": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("inspect", "create-disabled", "enable", "disable", "observe"))
    args = parser.parse_args()
    require(os.geteuid() == 0 and Path("/etc/machine-id").read_text().strip() == MACHINE_ID,
            "root_or_machine_identity_mismatch")
    os.umask(0o077)
    source_dir = Path(__file__).absolute().parent
    protected(source_dir, directory=True)
    source = source_dir / "monitor.json"
    protected(source)
    require(source.stat().st_size < 65536, "candidate_too_large")
    raw = source.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCE_SHA, "candidate_source_sha_mismatch")
    candidate = strict_json(raw)
    validate_monitor(candidate, candidate, False)
    # Existing parent must already be managed; no broad recursive mkdir/chmod.
    protected(STATE_DIR.parent, directory=True)
    if args.operation in {"inspect", "observe"}:
        if STATE_DIR.exists() or STATE_DIR.is_symlink():
            protected(STATE_DIR, directory=True, private=True)
        api = CurlAPI()
        print(json.dumps(operate(args.operation, api, StateStore(STATE_DIR / "state.json"), candidate), sort_keys=True))
        return
    if not STATE_DIR.exists():
        STATE_DIR.mkdir(mode=0o700)
    protected(STATE_DIR, directory=True, private=True)
    lock = STATE_DIR / ".lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    try:
        protected(lock, private=True)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = operate(args.operation, CurlAPI(), StateStore(STATE_DIR / "state.json"), candidate)
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        main()
    except Refused as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        sys.exit(1)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        print(json.dumps({"ok": False, "error": "operator_check_failed_no_automatic_retry"}))
        sys.exit(1)
