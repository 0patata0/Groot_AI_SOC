# GROOT layer A (WAF) integration contract

Owner: WAF rules. Counterparts: FW (nftables) owner, IPS (Suricata) owner.
Applies to `GROOT_A_WAF.conf` v1.0.0.

## 1. What the WAF emits

| Item | Value |
|---|---|
| Log file | `/var/log/modsec/modsec_audit.json` on the nginx host |
| Format | one JSON object per line (ModSecurity v3 `SecAuditLogFormat JSON`) |
| Written when | a GROOT or CRS rule matches, or the backend returns 5xx / 4xx (not 404) |
| Source address field | `transaction.client_ip` (REMOTE_ADDR as seen by nginx) |
| Rule id field | `transaction.messages[].details.ruleId` |
| Priority field | tag `GROOT_A/priority/high`, `/medium`, `/low` in `details.tags` |
| Category field | tag `GROOT_A/category/<sqli,xss,rce,lfi,rfi,header-manipulation>` |
| CVE field | tag `CVE-YYYY-NNNN` when the rule targets a named CVE |
| Human label | `details.msg` starts with `WAF-<CAT>-<NNN>` |

The WAF runs in DetectionOnly. It never blocks and never changes firewall state.
Any blocking derived from WAF alerts must be done by Wazuh active response
against the FW owner's nftables set, not by the WAF.

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
- Provide an nftables **set with a timeout** that Wazuh active response can add
  addresses to. Suggested name `groot_block`, element type `ipv4_addr`,
  timeout 10 minutes for the tuning phase. The WAF never writes to it.
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

Escalate when the same source hits two layers within 5 minutes:

```
WAF high  (100201)   + any IPS alert from same src_ip  -> level 13, add to groot_block
WAF high  (100201)   + FW drop log from same saddr     -> level 12
WAF medium (100202) x3 in 5 min from same src          -> level 10
```

Join key is the client IP in all three logs.

## 7. Change control

- Rule changes to `GROOT_A_WAF.conf` bump the `ver:` field and the header version.
- New rule ids stay inside the blocks in section 2. Tell the Wazuh owner when a
  new `GROOT_A/category/*` tag is introduced.
- Nobody switches `SecRuleEngine` to On without the FW owner confirming the
  nftables set exists, because active response will start calling it.
