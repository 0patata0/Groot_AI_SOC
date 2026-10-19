#!/usr/bin/env python3
"""Check the Spring UI, actual runtime versions and one inert log request.

Only a fixed ASCII message is logged. Cookies, CSRF tokens and bodies stay in
memory; output contains stable result labels only. No exploit or callback.
"""
import http.cookiejar
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify(base, hostname="", public_port="80"):
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.path != "/log4shell/" or parsed.query or parsed.fragment:
        raise ValueError("invalid_verification_url")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(path, data=None, headers=None):
        request_headers = {"Accept": "*/*", "User-Agent": "Groot-Spring-Lab-Verifier/1.0"}
        if hostname:
            request_headers["Host"] = hostname
        request_headers.update(headers or {})
        req = urllib.request.Request(urllib.parse.urljoin(base, path), data=data, headers=request_headers)
        try:
            response = opener.open(req, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read(256 * 1024 + 1)
            if len(body) > 256 * 1024:
                raise ValueError("response_size")
            return response.code, response.headers, body

    status, _, body = request("", headers={"Accept": "text/html, */*;q=0.8"})
    if status != 200 or b"Log4Shell" not in body:
        raise ValueError("spring_ui_failed")
    for asset in ("app.js", "app.css"):
        status, _, body = request(asset)
        if status != 200 or not body:
            raise ValueError("spring_asset_failed")
    status, _, body = request("api/status", headers={"Accept": "application/json"})
    result = json.loads(body)
    if status != 200 or not isinstance(result, dict) or result.get("ok") is not True or result.get("log4jApiVersion") != "2.14.1" or result.get("log4jCoreVersion") != "2.14.1" or not result.get("javaVersion") or not isinstance(result.get("csrfToken"), str) or not 0 < len(result["csrfToken"]) <= 512:
        raise ValueError("spring_runtime_identity_failed")
    token = result["csrfToken"]
    message = "capstone-spring-verification"
    data = urllib.parse.urlencode({"source": "parameter", "message": message}).encode("ascii")
    status, _, body = request("api/log", data, {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", "X-Lab-CSRF-Token": token})
    result = json.loads(body)
    if status != 200 or not isinstance(result, dict) or result.get("ok") is not True or result.get("source") != "parameter" or result.get("level") != "INFO" or result.get("message") != message or not result.get("requestId") or not result.get("time"):
        raise ValueError("spring_logging_failed")
    if hostname:
        origin = "http://" + hostname + ("" if public_port == "80" else ":" + public_port)
        for path in ("/", "/log4shell", "/dvwa/login.php"):
            status, headers, _ = request(path)
            if status != 302 or headers.get("Location") != origin + "/log4shell/":
                raise ValueError("spring_hostname_route_failed")


if __name__ == "__main__":
    try:
        if not 2 <= len(sys.argv) <= 4:
            raise ValueError("verification_arguments")
        verify(*sys.argv[1:])
    except (ValueError, KeyError, OSError, urllib.error.URLError):
        print("log4shell_spring_not_ready", file=sys.stderr)
        raise SystemExit(1)
    print("log4shell_spring_ready")
