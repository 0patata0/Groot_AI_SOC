#!/usr/bin/env python3
"""Verify the lab UI API with inert input and an in-memory browser session.

Run on an already authorized management path, for example:
    python3 -B verify.py http://127.0.0.1:8000/log4shell/

The verifier uses only the standard library, follows no redirects, bypasses no
access control, and writes no cookies, response bodies, tokens, or cache files.
It performs two expected upstream requests and, when still inside the one-second
start interval, one rate-limit probe. A probe crossing that interval can produce
one additional benign upstream request. Uncertain timing is reported as SKIP,
not PASS. A concurrent request can require one extra attempt after 1.1 seconds.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


MAX_RESPONSE_BYTES = 64 * 1024
NORMAL_INPUT = {"mode": "normal", "api_version": "capstone-ui-verification"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class Response:
    status: int
    body: Any
    headers: Any


class VerificationFailure(Exception):
    pass


def checked_base_url(value: str) -> str:
    """Reject ambiguous URLs; do not echo the supplied address on error."""
    try:
        if len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in value):
            raise ValueError
        parsed = urllib.parse.urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/log4shell/"
            or parsed.port == 0
        ):
            raise ValueError
        return urllib.parse.urlunsplit(parsed)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            "Use an http(s) URL ending in /log4shell/, without credentials or query."
        ) from None


class Verifier:
    def __init__(self, base_url: str) -> None:
        self.base = base_url
        self.endpoint = urllib.parse.urljoin(base_url, "api.php")
        parsed = urllib.parse.urlsplit(base_url)
        self.origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPCookieProcessor(self.cookies),
        )
        self.csrf: str | None = None
        self.failed = False
        self.current_test = "bootstrap"
        self.last_upstream_started: float | None = None

    def request(
        self,
        method: str,
        payload: dict[str, Any] | None = None,
        *,
        csrf: bool = True,
        bootstrap: bool = False,
    ) -> Response:
        url = self.endpoint + ("?action=bootstrap" if bootstrap else "")
        headers = {
            "Accept": "application/json",
            "User-Agent": "Groot-Log4Shell-UI-Verifier/1.0",
            "Origin": self.origin,
            "Referer": self.base,
        }
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if csrf and self.csrf is not None:
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            content_type = response.headers.get_content_type()
            response_headers = response.headers
        if len(raw) > MAX_RESPONSE_BYTES or content_type != "application/json":
            return Response(status, None, response_headers)
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            body = None
        return Response(status, body, response_headers)

    def report(self, name: str, response: Response, passed: bool, *, app_status=None) -> None:
        # Output is deliberately limited to stable test names and statuses.
        result: dict[str, Any] = {
            "test": name,
            "status": "PASS" if passed else "FAIL",
            "http_status": response.status,
        }
        if isinstance(app_status, int) and not isinstance(app_status, bool):
            result["app_status"] = app_status
        print(json.dumps(result, separators=(",", ":")), flush=True)
        self.failed |= not passed

    def rejection(self, name: str, payload: dict[str, Any], expected: int, *, csrf=True) -> None:
        self.current_test = name
        response = self.request("POST", payload, csrf=csrf)
        passed = (
            response.status == expected
            and isinstance(response.body, dict)
            and response.body.get("ok") is False
            and "response" not in response.body
        )
        self.report(name, response, passed)
        if not passed:
            # A rejected-input test must not unexpectedly reach the lab. Stop
            # without running any additional validation payloads in that case.
            raise VerificationFailure

    def upstream_request(self, name: str, payload: dict[str, Any]) -> Response:
        self.current_test = name
        self.last_upstream_started = time.monotonic()
        response = self.request("POST", payload)
        if response.status == 429:
            time.sleep(1.1)
            self.last_upstream_started = time.monotonic()
            response = self.request("POST", payload)
        return response

    def rate_limit_probe(self) -> bool:
        """Test only a measurable start interval; do not change the API policy."""
        self.current_test = "immediate_rate_limit"
        if self.last_upstream_started is None:
            raise VerificationFailure
        before = time.monotonic() - self.last_upstream_started
        if before >= 1.0:
            print(json.dumps({
                "test": self.current_test, "status": "SKIP",
                "reason": "request_start_window_elapsed", "http_status": 0,
                "request_sent": False, "elapsed_before_ms": round(before * 1000, 1),
            }, separators=(",", ":")), flush=True)
            return True

        response = self.request("POST", NORMAL_INPUT)
        after = time.monotonic() - self.last_upstream_started
        passed = (
            response.status == 429
            and isinstance(response.body, dict)
            and response.body.get("ok") is False
            and response.headers.get("Retry-After") == "1"
        )
        if passed:
            self.report(self.current_test, response, True)
            return True

        # The server timestamps request starts, not completions. If this benign
        # probe is successful but the interval has elapsed before its response
        # arrives, the client cannot establish when the server accepted it.
        valid_response = (
            response.status == 200
            and isinstance(response.body, dict)
            and response.body.get("ok") is True
            and isinstance(response.body.get("request"), dict)
            and response.body["request"].get("mode") == "normal"
            and isinstance(response.body.get("response"), dict)
            and response.body["response"].get("status") == 200
        )
        if valid_response and after >= 1.0:
            print(json.dumps({
                "test": self.current_test, "status": "SKIP",
                "reason": "request_start_window_boundary", "http_status": 200,
                "request_sent": True, "elapsed_before_ms": round(before * 1000, 1),
                "elapsed_after_ms": round(after * 1000, 1),
            }, separators=(",", ":")), flush=True)
            return True

        self.report(self.current_test, response, False)
        return False

    def run(self) -> bool:
        response = self.request("GET", csrf=False, bootstrap=True)
        body = response.body
        csrf = body.get("csrf") if isinstance(body, dict) else None
        cookie_list = list(self.cookies)
        secure = urllib.parse.urlsplit(self.base).scheme == "https"
        cookie_name = "__Secure-groot_log4shell_ui_https" if secure else "groot_log4shell_ui_http"
        session_ok = any(
            c.name == cookie_name
            and c.secure == secure
            and c.path == "/log4shell/"
            and c.has_nonstandard_attr("HttpOnly")
            and str(c.get_nonstandard_attr("SameSite", "")).lower() == "strict"
            for c in cookie_list
        )
        passed = (
            response.status == 200
            and isinstance(body, dict)
            and body.get("ok") is True
            and isinstance(csrf, str)
            and re.fullmatch(r"[0-9a-f]{64}", csrf) is not None
            and session_ok
            and response.headers.get("Cache-Control", "").lower() == "no-store"
        )
        self.report("bootstrap", response, passed)
        if not passed:
            return False
        self.csrf = csrf

        self.rejection("csrf_missing", NORMAL_INPUT, 403, csrf=False)
        self.rejection("unknown_target_key", {**NORMAL_INPUT, "target": "disabled-target-field"}, 400)
        self.rejection("header_crlf", {**NORMAL_INPUT, "api_version": "capstone\r\nverification"}, 400)
        self.rejection(
            "header_dollar_braces",
            {**NORMAL_INPUT, "api_version": "$" + "{capstone-ui-verification}"},
            400,
        )

        self.current_test = "method_put"
        response = self.request("PUT", NORMAL_INPUT)
        passed = (
            response.status == 405
            and isinstance(response.body, dict)
            and response.body.get("ok") is False
            and {v.strip() for v in response.headers.get("Allow", "").split(",")} == {"GET", "POST"}
        )
        self.report("method_put", response, passed)
        if not passed:
            return False

        response = self.upstream_request("normal_request", NORMAL_INPUT)
        body = response.body if isinstance(response.body, dict) else {}
        app = body.get("response") if isinstance(body.get("response"), dict) else {}
        request = body.get("request") if isinstance(body.get("request"), dict) else {}
        app_status = app.get("status")
        passed = (
            response.status == 200
            and body.get("ok") is True
            and app_status == 200
            and isinstance(app.get("body"), str)
            and re.fullmatch(r"Hello,\s*world!", app["body"].strip()) is not None
            and request.get("mode") == "normal"
            and request.get("header_name") == "X-Api-Version"
            and request.get("header_value") == NORMAL_INPUT["api_version"]
        )
        self.report("normal_request", response, passed, app_status=app_status)
        if not passed:
            return False

        if not self.rate_limit_probe():
            return False

        time.sleep(1.1)
        response = self.upstream_request("missing_header", {"mode": "missing-header"})
        body = response.body if isinstance(response.body, dict) else {}
        app = body.get("response") if isinstance(body.get("response"), dict) else {}
        request = body.get("request") if isinstance(body.get("request"), dict) else {}
        app_status = app.get("status")
        passed = (
            response.status == 200
            and body.get("ok") is True
            and app_status == 400
            and request.get("mode") == "missing-header"
            and request.get("header_value") is None
        )
        self.report("missing_header", response, passed, app_status=app_status)
        return not self.failed

    def close(self) -> None:
        self.csrf = None
        self.cookies.clear()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", type=checked_base_url, help="Authorized UI URL ending in /log4shell/")
    args = parser.parse_args()
    verifier = Verifier(args.base_url)
    try:
        return 0 if verifier.run() else 1
    except VerificationFailure:
        return 1
    except Exception:
        # Exception messages may contain URLs or response details. Never print
        # them, and do not produce a traceback containing request objects.
        print(json.dumps({"test": verifier.current_test, "status": "ERROR", "http_status": 0}), flush=True)
        return 1
    finally:
        verifier.close()


if __name__ == "__main__":
    sys.exit(main())
