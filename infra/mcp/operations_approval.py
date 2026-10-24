#!/usr/bin/env python3
"""Separate approval protocol for fixed service actions and temporary containment.

POST /operations accepts exactly request_id, kind, target, plan, plan_sha256,
expires_at, requested_by. request_id is a client-generated 32-hex idempotency key.
Hashes use SHA256 of canonical JSON (sorted keys, compact separators, ASCII).
POST /operations/<id>/consume accepts only proposal_digest. Result accepts only
proposal_digest, status, after_observation_sha256, detail. Observations describe
actual state; they are not required to equal the immutable action-plan hash.

The caller supplies transport authentication and Mattermost dependencies. This
module never executes a service command or firewall operation. In particular,
the containment helper must independently expire its temporary nftables entry
after 600 seconds even if this broker is unavailable or restarted.
"""
import hashlib
import ipaddress
import json
import re
import secrets
import threading
import time
import unicodedata
from collections import Counter
from datetime import datetime, timedelta, timezone


SERVICE_ACTIONS = {
    "a:waf": frozenset(("reload", "restart")),
    "a:suricata": frozenset(("restart",)),
    "a:chatproxy": frozenset(("reload", "restart")),
    "b:wazuh-manager": frozenset(("restart",)),
    "b:wazuh-dashboard": frozenset(("restart",)),
}
SERVICE_IMPACT = {
    "a:waf": "웹 보안 프록시 연결이 잠시 중단될 수 있습니다.",
    "a:suricata": "IDS 탐지가 잠시 중단됩니다.",
    "a:chatproxy": "채팅·대시보드 접속이 잠시 중단될 수 있습니다.",
    "b:wazuh-manager": "SIEM 수집·분석이 잠시 중단됩니다.",
    "b:wazuh-dashboard": "대시보드 접속이 잠시 중단됩니다.",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
REQUESTER = re.compile(r"^[a-zA-Z0-9_.:@-]{1,80}$")
FIELDS = frozenset(("request_id", "kind", "target", "plan", "plan_sha256", "expires_at", "requested_by"))
SERVICE_FIELDS = frozenset(("action", "before_observation_sha256", "before_summary", "policy_sha256", "reason"))
CONTAINMENT_FIELDS = frozenset(("ip", "action", "temporary_expires_at", "keep_seconds",
                              "before_observation_sha256", "evidence_sha256"))
KST = timezone(timedelta(hours=9), "KST")


def display_summary_kst(summary):
    """Card-only conversion; the exact approved plan and digests stay unchanged."""
    def convert(match):
        try:
            stamp = datetime.fromisoformat(match[0].replace('Z', '+00:00'))
            return stamp.astimezone(KST).isoformat() + ' (KST)' if stamp.tzinfo else match[0] + ' (시간대 확인 필요)'
        except ValueError:
            return match[0] + ' (시각 확인 필요)'
    return re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?', convert, summary)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _hash(value):
    return isinstance(value, str) and bool(SHA256.fullmatch(value))


def _text(value, max_chars=200, max_bytes=500):
    return (isinstance(value, str) and 1 <= len(value) <= max_chars and
            len(value.encode("utf-8")) <= max_bytes and
            not any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs") for c in value))


class OperationsBroker:
    def __init__(self, *, post, enabled, source_ok, approvers, action_url, audit=None,
                 post_card=None, card_state=None):
        self.post = post
        self.enabled = enabled
        self.source_ok = source_ok
        self.approvers = approvers
        self.action_url = action_url
        self.audit = audit or (lambda event, record: None)
        self.post_card = post_card or (lambda record, payload: self.post(payload))
        self.card_state = card_state or (lambda event, record, body=None: True)
        self.records = {}
        self.lock = threading.Lock()

    @staticmethod
    def validate(req):
        if not isinstance(req, dict) or set(req) != FIELDS:
            raise ValueError("invalid operation fields")
        if not isinstance(req["request_id"], str) or not REQUEST_ID.fullmatch(req["request_id"]):
            raise ValueError("invalid request_id")
        if not isinstance(req["requested_by"], str) or not REQUESTER.fullmatch(req["requested_by"]):
            raise ValueError("invalid requester")
        if type(req["expires_at"]) is not int:
            raise ValueError("invalid expiry")
        plan = req["plan"]
        if not isinstance(plan, dict) or not _hash(req["plan_sha256"]) or digest(plan) != req["plan_sha256"]:
            raise ValueError("invalid plan or plan SHA-256")
        if req["kind"] == "service":
            if not isinstance(req["target"], str) or req["target"] not in SERVICE_ACTIONS:
                raise ValueError("service target is not allowlisted")
            if set(plan) != SERVICE_FIELDS or plan.get("action") not in SERVICE_ACTIONS[req["target"]]:
                raise ValueError("invalid service plan or unsupported action")
            if (not _hash(plan["before_observation_sha256"]) or not _hash(plan["policy_sha256"]) or
                    not _text(plan["reason"]) or not _text(plan["before_summary"])):
                raise ValueError("invalid service observation, policy hash or reason")
        elif req["kind"] == "containment":
            if req["target"] != "a:incident-ip" or set(plan) != CONTAINMENT_FIELDS:
                raise ValueError("invalid containment target or plan")
            try:
                address = ipaddress.IPv4Address(plan["ip"])
            except (ValueError, TypeError, ipaddress.AddressValueError):
                raise ValueError("invalid containment IP")
            if str(address) != plan["ip"] or not address.is_global or address.is_multicast or address.is_reserved:
                raise ValueError("containment IP must be a public unicast IPv4 address")
            if (plan["action"] != "temporary_block" or type(plan["keep_seconds"]) is not int or
                    plan["keep_seconds"] != 3600 or type(plan["temporary_expires_at"]) is not int or
                    plan["temporary_expires_at"] != req["expires_at"] or
                    not _hash(plan["before_observation_sha256"]) or not _hash(plan["evidence_sha256"])):
                raise ValueError("invalid temporary containment plan")
        else:
            raise ValueError("invalid operation kind")
        return digest(req)

    def _expire_locked(self):
        now = time.time()
        for oid, rec in list(self.records.items()):
            if rec["status"] in ("posting", "pending", "approved", "denied") and now >= rec["expires_at"]:
                self.card_state("expire", rec)
                rec["status"] = "expired"
                rec["decided_at"] = now
                self.audit("expired", rec)
            if not self._active(rec) and now - rec.get("finished_at", rec["expires_at"]) > 3600:
                del self.records[oid]
        if len(self.records) > 256:
            terminal = sorted(((oid, rec) for oid, rec in self.records.items() if not self._active(rec)),
                              key=lambda row: row[1].get("finished_at", row[1]["expires_at"]))
            for oid, _ in terminal[:len(self.records) - 256]:
                del self.records[oid]

    @staticmethod
    def _active(rec):
        return (rec["status"] in ("posting", "pending", "approved", "denied", "consumed", "reporting", "report_error") or
                (rec["kind"] == "containment" and rec["status"] == "expired" and not rec["result_posted"]))

    @staticmethod
    def _public(rec):
        keys = ("request_id", "kind", "target", "plan_sha256", "proposal_digest", "expires_at", "status",
                "decision", "by", "decided_at", "posted", "consumed_decision", "result_posted", "result_attempts", "result_status")
        return {**{key: rec.get(key, "") for key in keys}, "operation_id": rec["request_id"],
                "before_observation_sha256": rec["plan"]["before_observation_sha256"],
                "after_observation_sha256": rec.get("after_observation_sha256", "")}

    def health(self):
        with self.lock:
            self._expire_locked()
            counts = Counter(rec["status"] for rec in self.records.values())
            return {"status": "ready", "approval_configured": bool(self.enabled()),
                    "active_operations": sum(self._active(rec) for rec in self.records.values()),
                    "operation_status_counts": dict(counts)}

    @staticmethod
    def _card(rec):
        plan = rec["plan"]
        expiry = datetime.fromtimestamp(rec["expires_at"], KST).strftime("%Y-%m-%d %H:%M:%S KST")
        header = ("요청 ID: `%s`\n종류: `%s`\n대상: `%s`\n요청자: `%s`\n"
                  "제안 SHA-256: `%s`\n작업 계획 SHA-256: `%s`\n변경 전 관찰 SHA-256: `%s`\n만료: `%s`" %
                  (rec["request_id"], rec["kind"], rec["target"], rec["requested_by"], rec["proposal_digest"],
                   rec["plan_sha256"], plan["before_observation_sha256"], expiry))
        if rec["kind"] == "service":
            expected = ("같은 컨테이너·설정을 유지하고, 시작 시각이 바뀌며 정상 상태를 확인합니다."
                        if plan["action"] == "restart" else
                        "같은 master 프로세스를 유지하고, 새 worker와 정상 응답을 확인합니다.")
            return (header + "\n\n작업: `%s`\n고정 실행 정책 SHA-256: `%s`\n변경 전 상태:\n\n    %s\n\n"
                    "예상 변경 후 상태: %s\n영향: %s\n"
                    "사유:\n\n    %s\n\n지정된 서비스의 이 작업 한 건만 승인합니다. "
                    "적용 전 상태가 달라지면 중단하며, 실행 결과는 별도 실측 SHA-256으로 보고합니다." %
                    (plan["action"], plan["policy_sha256"], display_summary_kst(plan["before_summary"]), expected,
                     SERVICE_IMPACT[rec["target"]], plan["reason"]))
        return (header + "\n\n외부 IP `%s`는 이미 임시 차단했습니다.\n"
                "증거 SHA-256: `%s`\n무응답 시 최초 임시 차단 후 10분 이내 자동 해제됩니다.\n"
                "[60분 유지]는 승인 시각부터 60분까지만 유지하고, [해제 요청]은 다음 worker 처리에서 해제합니다. "
                "진행 중인 룰·서비스 작업 때문에 처리가 늦어질 수 있지만, 유지 승인이 적용되기 전에는 "
                "원래 10분의 커널 TTL이 상한입니다. 브로커 장애 시에도 임시 차단 기한은 방화벽과 실행기가 독립적으로 지킵니다." %
                (plan["ip"], plan["evidence_sha256"]))

    def create(self, req):
        if not self.enabled():
            return {"error": "operation approval is not configured"}, 503
        try:
            proposal_digest = self.validate(req)
        except (ValueError, TypeError, UnicodeError) as exc:
            return {"error": str(exc)}, 400
        oid = req["request_id"]
        with self.lock:
            self._expire_locked()
            prior = self.records.get(oid)
            if prior:
                if not secrets.compare_digest(prior["proposal_digest"], proposal_digest):
                    return {"error": "request_id already binds a different operation"}, 409
                code = 409 if prior["status"] == "posting" else (200 if prior["posted"] else 502)
                return self._public(prior), code
            max_ttl = 600 if req["kind"] == "containment" else 900
            if not time.time() < req["expires_at"] <= time.time() + max_ttl:
                return {"error": "invalid operation expiry"}, 400
            if sum(self._active(row) for row in self.records.values()) >= 64:
                return {"error": "too many active operations"}, 429
            # Copy through canonical JSON so a caller cannot mutate the committed plan.
            rec = json.loads(canonical(req))
            rec.update(proposal_digest=proposal_digest, nonce=secrets.token_hex(32), status="posting",
                       decision="", consumed_decision="", by="", decided_at=0, posted=False,
                       result_posted=False, result_attempts=0)
            rec["card_text"] = self._card(rec)
            if len(rec["card_text"].encode("utf-8")) > 8000:
                return {"error": "operation card too large"}, 400
            self.records[oid] = rec
        choices = (("승인", "approve"), ("거부", "deny")) if rec["kind"] == "service" else \
                  (("60분 유지", "keep"), ("해제 요청", "release"))
        actions = [{"id": decision, "name": label, "style": "primary" if index == 0 else "danger",
                    "integration": {"url": self.action_url() + "/operation-actions", "context": {
                        "operation_id": oid, "kind": rec["kind"], "nonce": rec["nonce"],
                        "proposal_digest": proposal_digest, "decision": decision}}}
                   for index, (label, decision) in enumerate(choices)]
        payload = {"username": "SOC-Agent", "attachments": [{"color": "#e0a800",
                   "title": "서비스 작업 승인 요청" if rec["kind"] == "service" else "임시 IP 차단 · 유지 또는 해제",
                   "text": rec["card_text"], "actions": actions, "footer": "capstone operations HITL", "ts": int(time.time())}]}
        posted, _ = self.post_card(rec, payload)
        with self.lock:
            self._expire_locked()
            rec["posted"] = bool(posted)
            if rec["status"] == "posting":
                rec["status"] = "pending" if posted and self.card_state("pending", rec) else "error"
            if rec["status"] != "pending":
                self.audit("post_error", rec)
                return {"error": "operation card failed or expired; approval is disabled", **self._public(rec)}, 502
            self.audit("created", rec)
            return self._public(rec), 200

    def get(self, oid):
        with self.lock:
            self._expire_locked()
            rec = self.records.get(oid)
            return (self._public(rec), 200) if rec else ({"error": "operation not found"}, 404)

    def action(self, body, peer_ip):
        if not self.enabled() or not self.source_ok(peer_ip) or not isinstance(body, dict):
            return {"ephemeral_text": "허용되지 않은 승인 요청 또는 콜백 출처입니다."}
        ctx = body.get("context")
        uid = body.get("user_id")
        if not isinstance(ctx, dict) or not isinstance(uid, str) or uid not in self.approvers():
            return {"ephemeral_text": "승인 권한이 없거나 요청이 유효하지 않습니다."}
        oid = ctx.get("operation_id")
        if not isinstance(oid, str):
            return {"ephemeral_text": "유효하지 않은 작업 요청입니다."}
        with self.lock:
            self._expire_locked()
            rec = self.records.get(oid)
            if not rec or rec["status"] != "pending":
                return {"ephemeral_text": "처리되었거나 만료된 작업입니다."}
            choices = ("approve", "deny") if rec["kind"] == "service" else ("keep", "release")
            if (ctx.get("kind") != rec["kind"] or ctx.get("decision") not in choices or
                    not isinstance(ctx.get("nonce"), str) or not isinstance(ctx.get("proposal_digest"), str) or
                    not secrets.compare_digest(ctx["nonce"], rec["nonce"]) or
                    not secrets.compare_digest(ctx["proposal_digest"], rec["proposal_digest"])):
                return {"ephemeral_text": "인증되지 않은 작업 승인 요청입니다."}
            if not self.card_state("decision", rec, body):
                return {"ephemeral_text": "승인 카드 식별 또는 결정 보존을 확인하지 못했습니다. 결정은 반영되지 않았습니다."}
            rec.update(decision=ctx["decision"], by=uid, decided_at=time.time(),
                       status="approved" if ctx["decision"] in ("approve", "keep") else "denied")
            self.audit("decision", rec)
            text = rec["card_text"] + "\n\n결정: `%s` · 승인자 ID: `%s`" % (rec["decision"], uid)
        return {"ephemeral_text": "작업 결정을 기록했습니다.", "update": {"message": "", "props": {"attachments": [{
            "title": "작업 승인 결정", "color": "#28a745" if rec["status"] == "approved" else "#d24b4b",
            "text": text, "footer": "capstone operations HITL", "ts": int(time.time())}]}}}

    def consume(self, oid, req):
        if not isinstance(req, dict) or set(req) != {"proposal_digest"} or not _hash(req["proposal_digest"]):
            return {"error": "invalid consume request"}, 400
        with self.lock:
            self._expire_locked()
            rec = self.records.get(oid)
            if not rec:
                return {"error": "operation not found"}, 404
            if not secrets.compare_digest(req["proposal_digest"], rec["proposal_digest"]):
                return {"error": "proposal digest mismatch"}, 409
            allowed = ("approved",) if rec["kind"] == "service" else ("approved", "denied", "expired")
            if rec["status"] not in allowed:
                return {"error": "operation cannot be consumed"}, 409
            if not self.card_state("protect", rec):
                return {"error": "approval card state unavailable"}, 503
            rec["consumed_decision"] = "expired" if rec["status"] == "expired" else rec["decision"]
            rec["status"] = "consumed"
            self.audit("consumed", rec)
            return self._public(rec), 200

    def result(self, oid, req):
        fields = {"proposal_digest", "status", "after_observation_sha256", "detail"}
        try:
            valid = (isinstance(req, dict) and set(req) == fields and _hash(req["proposal_digest"]) and
                     _hash(req["after_observation_sha256"]) and _text(req["detail"]))
        except UnicodeError:
            valid = False
        if not valid:
            return {"error": "invalid operation result"}, 400
        result_digest = digest(req)
        with self.lock:
            self._expire_locked()
            rec = self.records.get(oid)
            if not rec:
                return {"error": "operation not found"}, 404
            if not secrets.compare_digest(req["proposal_digest"], rec["proposal_digest"]):
                return {"error": "proposal digest mismatch"}, 409
            allowed = ("applied", "failed", "aborted") if rec["kind"] == "service" else \
                      (("kept", "released", "failed") if rec["consumed_decision"] == "keep" else ("released", "expired", "failed"))
            if not isinstance(req["status"], str) or req["status"] not in allowed:
                return {"error": "result is incompatible with operation decision"}, 409
            prior = rec.get("result_digest")
            if prior and not secrets.compare_digest(prior, result_digest):
                return {"error": "result differs from first report"}, 409
            if rec["result_posted"]:
                return self._public(rec), 200
            abort_before_consume = (rec["kind"] == "service" and req["status"] == "aborted" and
                                    rec["status"] in ("pending", "approved", "denied", "expired"))
            if rec["status"] not in ("consumed", "report_error") and not abort_before_consume:
                return {"error": "operation has not been consumed or result is in progress"}, 409
            if rec["result_attempts"] >= 3:
                return {"error": "result retries exhausted"}, 429
            if not self.card_state("protect", rec):
                return {"error": "approval card state unavailable"}, 503
            rec.update(status="reporting", result_digest=result_digest, result_status=req["status"],
                       result_attempts=rec["result_attempts"] + 1,
                       after_observation_sha256=req["after_observation_sha256"])
            text = (rec["card_text"] + "\n\n결정: `%s` · 승인자 ID: `%s`\n실행 결과: `%s`\n"
                    "실행 후 관찰 SHA-256: `%s`\n관찰 결과:\n\n    %s" %
                    (rec["consumed_decision"], rec["by"] or "자동 기한 만료", req["status"],
                     req["after_observation_sha256"], req["detail"]))
        posted, _ = self.post({"username": "SOC-Agent", "attachments": [{"title": "운영 작업 결과",
                              "color": "#d24b4b" if req["status"] == "failed" else "#28a745",
                              "text": text, "footer": "capstone operations HITL", "ts": int(time.time())}]})
        with self.lock:
            rec.update(status=req["status"] if posted else "report_error", result_posted=bool(posted),
                       finished_at=time.time())
            self.audit("result" if posted else "result_post_error", rec)
            response = self._public(rec)
        return response, 200 if posted else 502
