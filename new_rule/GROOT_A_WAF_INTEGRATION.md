# GROOT layer A (WAF) integration contract

> **Status from the 2026-10-06 SSH recheck in this session.** The WAF service is healthy, its custom GROOT conf is mounted, `nginx -t` passes, and it remains `DetectionOnly`. The live custom conf has **11 rule IDs**; chained rules make `SecRule` appear on 12 directive lines. FW v2 has `FORWARD=DROP`; Suricata is passive with `/rules/all.rules`, 11 local SIDs, and Phase-A options. B manager's `local_decoder.xml` and `local_rules.xml` lack the new WAF 100200+ and FW-prefix classifications; local IPS SID classification was not established by this check. Verify each before claiming end-to-end alerts. WAF `On` and IPS inline/drop remain pending. The original contract below predates deployment; the intended blocking integration uses `agent_block` and the approval broker. Broker URL and token environment variables are set on A. A generic Tier 2 approval-to-block path was verified on 2026-09-28, but this SSH recheck did not repeat it and the new WAF-alert-triggered path is unverified.

Owner: WAF rules. Counterparts: FW (nftables) owner, IPS (Suricata) owner.
Applies to `GROOT_A_WAF.conf` v1.0.0.

## 1. What the WAF emits

| Item | Value |
|---|---|
| Log file | `/var/log/modsecurity/audit.log` in the WAF container, mounted to `logs/modsec/audit.log` on the A host (base configuration inherited after the 2026-10-02 rule fix) |
| Format | one JSON object per line (ModSecurity v3 `SecAuditLogFormat JSON`) |
| Written when | a GROOT or CRS rule matches, or the backend returns 5xx / 4xx (not 404) |
| Source address field | `transaction.client_ip` (REMOTE_ADDR as seen by nginx) |
| Rule id field | `transaction.messages[].details.ruleId` |
| Priority field | tag `GROOT_A/priority/high`, `/medium`, `/low` in `details.tags` |
| Category field | tag `GROOT_A/category/<sqli,xss,rce,lfi,rfi,header-manipulation>` |
| CVE field | tag `CVE-YYYY-NNNN` when the rule targets a named CVE |
| Human label | `details.msg` starts with `WAF-<CAT>-<NNN>` |

The WAF currently runs in DetectionOnly. It does not block requests or change firewall state in that mode. The project's IP response path is response MCP → approval broker/Tier 2 → FW `agent_block`; the broker URL/token are configured on A, and the generic path passed an end-to-end test on 2026-09-28. Triggering that path from a new WAF alert still needs verification. Wazuh active response is not the configured automatic blocking path in the project record.

## 2. Namespaces (agree once, never overlap)

| Layer | Id space | Reason |
|---|---|---|
| WAF (ModSecurity) | 10100-10699 | CRS local range 1-99999, CRS itself uses 900000-999999 |
| IPS (Suricata sid) | 1000000+ (local) | ET / ET Pro use below 1000000 |
| Wazuh rules | 100200-100299 for WAF, pick your own blocks for FW and IPS | Wazuh built-ins use < 100000 |

Also agree on a shared tag prefix in Wazuh groups: `groot_a` (WAF), `groot_f` (FW),
`groot_i` (IPS), so one dashboard filter shows all three.

## 3. Division of detection (who owns what)

| Attack class | WAF | IPS | FW |
|---|---|---|---|
| SQLi, XSS, command injection, LFI/RFI in decoded HTTP | **owns** | only if plaintext on the backend leg and the IPS owner wants a second opinion; keep it low severity | no |
| Log4Shell, PHP-CGI, Spring4Shell payloads | **owns** (needs URL / entity decoding) | may keep ET signatures, expect double alerts on plaintext legs | no |
| Header manipulation (X-Forwarded-For) | **owns** | no | no |
| Scanner user-agents (sqlmap, nikto, nuclei) | no | **owns** | no |
| Port scans, SYN floods, rate limits | no | detect | **owns** (enforce) |
| IP reputation, geo blocks | no | optional | **owns** |
| TLS anomalies, C2 beacons, DNS tunnelling | no | **owns** | no |
| HTTP request smuggling, protocol violations | CRS 920 covers it | optional | no |

Rule of thumb: if detection needs the decoded request body or app context, it is
WAF. If it needs flow, timing, or non-HTTP protocols, it is IPS. If it is a
block decision on an address or port, it is FW.

## 4. What the WAF needs from the FW owner

- Allow 80/443 inbound to the nginx host and nginx -> DVWA on the backend port.
- Allow the Wazuh agent on the nginx host to reach the manager (1514/tcp, 1515/tcp).
- Use the FW owner's existing timeout-capable nftables `agent_block` set for approved IP responses. The original `groot_block` / direct Wazuh active-response proposal has not been adopted. The WAF never writes to the set.
- Do not NAT the client address before nginx. If the client IP is rewritten,
  `transaction.client_ip` becomes useless for correlation.

## 5. What the WAF needs from the IPS owner

- State where Suricata taps: in front of nginx (sees TLS, cannot read payloads)
  or on the nginx -> DVWA leg (plaintext, will overlap with WAF content rules).
  The overlap table above assumes the front tap.
- Emit EVE JSON with `src_ip` populated so Wazuh can join on it with
  `transaction.client_ip`.
- Keep local sids at 1000000+ and tag them `groot_i`.

## 6. Correlation rule the Wazuh owner should write (whoever that is)

The following was the original correlation proposal. The B manager's local decoder and rule files currently lack the new classifications, so multi-layer correlation still needs implementation and testing. A correlated alert can inform the agent's investigation; automatic insertion into `agent_block` has not been demonstrated.

```
WAF high  (100201)   + any IPS alert from same src_ip  -> proposed level 13 / response candidate
WAF high  (100201)   + FW drop log from same saddr     -> level 12
WAF medium (100202) x3 in 5 min from same src          -> level 10
```

Join key is the client IP in all three logs.

## 7. Change control

- Rule changes to `GROOT_A_WAF.conf` bump the `ver:` field and the header version.
- New rule ids stay inside the blocks in section 2. Tell the Wazuh owner when a
  new `GROOT_A/category/*` tag is introduced.
- Switching `SecRuleEngine` to On is a separate WAF blocking gate. Verify the rule load, benign traffic, malicious-request blocking, and rollback together with the IPS inline plan. Confirm the FW response path and broker configuration separately; `On` does not itself invoke active response.
