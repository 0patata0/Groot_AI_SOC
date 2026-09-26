#!/usr/bin/env python3
"""capstone 알림 채널 추상화 — 백엔드를 env 한 블록으로 교체(엔드포인트만 바꾸면 됨). 표준 라이브러리만(오프라인).

원칙: 응답 서버/정책엔진은 notifier.send(backend, event) 만 부른다. "어디로 보내는지"는 설정에만 존재.
백엔드(RESP_NOTIFY_BACKEND):
  none    아무것도 안 함(기본).
  http    RESP_NOTIFY_URL 로 JSON POST. Mattermost/Rocket.Chat incoming webhook, 사내 웹훅 등(내부망). 페이로드 {"text":요약,"event":{...}} = Mattermost/Slack 호환.
  email   RESP_NOTIFY_SMTP(host:587) 로 메일. 이 망은 587 아웃바운드 열림. RESP_NOTIFY_FROM/TO, (선택)RESP_NOTIFY_SMTP_USER/PASS, STARTTLS.
  slack   ⚠️ 이 망에선 불가(아웃바운드 443 전면 차단, 2026-09-27 실측). 나중에 443 열리거나 프록시가 생기면 backend 만 slack 으로 바꾸면 됨(엔드포인트 교체 원칙 유지). 지금은 호출 시 실패 로그.
승인(request_approval)은 여기서 처리하지 않는다 — MCP elicitation(클라이언트/런타임이 표시)로 하므로 서버는 채널을 모른다. 이 모듈은 알림/감사 푸시 전용.

best-effort: send() 는 예외를 던지지 않고 (ok:bool, detail:str) 를 돌려준다. 짧은 타임아웃. 호출자(응답 서버)의 stdout(프로토콜 채널)을 절대 건드리지 않는다.
"""
import json
import os
import smtplib
import urllib.request
from email.message import EmailMessage

TIMEOUT = float(os.environ.get("RESP_NOTIFY_TIMEOUT", "4"))


def _summary(ev):
    k = ev.get("kind", "event")
    if k == "block":
        return "[SOC] BLOCK %s for %sm (reason %s, by %s)" % (ev.get("ip"), ev.get("minutes"), ev.get("reason"), ev.get("by", "mcp"))
    if k == "unblock":
        return "[SOC] UNBLOCK %s (reason %s)" % (ev.get("ip"), ev.get("reason"))
    if k == "rejected":
        return "[SOC] response REJECTED: %s %s (%s)" % (ev.get("action"), ev.get("ip"), ev.get("reason"))
    return "[SOC] " + json.dumps(ev, ensure_ascii=False)


def _http(ev):
    url = os.environ.get("RESP_NOTIFY_URL")
    if not url:
        return False, "RESP_NOTIFY_URL unset"
    body = json.dumps({"text": _summary(ev), "event": ev}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    tok = os.environ.get("RESP_NOTIFY_TOKEN")
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return 200 <= r.status < 300, "http %s" % r.status


def _email(ev):
    host = os.environ.get("RESP_NOTIFY_SMTP")            # host:port (587 recommended on this net)
    frm = os.environ.get("RESP_NOTIFY_FROM")
    to = os.environ.get("RESP_NOTIFY_TO")
    if not (host and frm and to):
        return False, "RESP_NOTIFY_SMTP/FROM/TO unset"
    h, _, p = host.partition(":")
    port = int(p or "587")
    msg = EmailMessage()
    msg["Subject"] = _summary(ev)[:120]
    msg["From"] = frm
    msg["To"] = to
    msg.set_content(json.dumps(ev, ensure_ascii=False, indent=2))
    with smtplib.SMTP(h, port, timeout=TIMEOUT) as s:
        try:
            s.starttls()
        except smtplib.SMTPException:
            pass
        u, pw = os.environ.get("RESP_NOTIFY_SMTP_USER"), os.environ.get("RESP_NOTIFY_SMTP_PASS")
        if u and pw:
            s.login(u, pw)
        s.send_message(msg)
    return True, "sent to %s" % to


def _slack(ev):
    # 이 망에선 도달 불가(443 차단). backend=slack 로 바꾸는 것만으로 교체되게 형태는 유지.
    return False, "slack backend disabled on this network (outbound 443 blocked)"


BACKENDS = {"none": lambda ev: (True, "noop"), "http": _http, "email": _email, "slack": _slack}


def send(backend, ev):
    """(ok, detail). 예외 없이. backend 미지정/none → noop."""
    backend = (backend or "none").strip().lower()
    fn = BACKENDS.get(backend)
    if fn is None:
        return False, "unknown backend: %s" % backend
    try:
        return fn(ev)
    except Exception as e:
        return False, "%s: %s" % (type(e).__name__, e)


if __name__ == "__main__":
    # 자체 테스트: RESP_NOTIFY_BACKEND 환경으로 백엔드 골라 샘플 이벤트 전송.
    be = os.environ.get("RESP_NOTIFY_BACKEND", "none")
    ok, detail = send(be, {"kind": "block", "ip": "203.0.113.7", "minutes": 10, "reason": "selftest", "by": "cli"})
    print("backend=%s ok=%s detail=%s" % (be, ok, detail))
