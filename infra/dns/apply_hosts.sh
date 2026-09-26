#!/bin/bash
# 클라이언트 /etc/hosts 에 capstone groot.lab 이름 블록을 삽입/갱신(멱등). 단일 원본: infra/dns/groot.lab.hosts.
# 사용: sudo bash apply_hosts.sh [원본파일] [대상hosts]
#   기본 원본 = 스크립트 옆 groot.lab.hosts, 기본 대상 = /etc/hosts
# Mac·Linux 공용. 재실행 시 기존 블록만 교체(다른 항목 보존). 나중에 dnsmasq 로 넘어가면 이 스크립트 대신 원본을 addn-hosts 로 쓰면 됨.
set -euo pipefail
SRC=${1:-"$(cd "$(dirname "$0")" && pwd)/groot.lab.hosts"}
DST=${2:-/etc/hosts}
B="# >>> capstone groot.lab >>>"
E="# <<< capstone groot.lab <<<"
[ -f "$SRC" ] || { echo "source missing: $SRC" >&2; exit 1; }
if [ ! -w "$DST" ]; then echo "need write access to $DST — run with sudo" >&2; exit 1; fi
tmp=$(mktemp)
# 기존 블록 제거(마커 사이 삭제)
awk -v b="$B" -v e="$E" 'BEGIN{s=0} $0==b{s=1;next} $0==e{s=0;next} !s{print}' "$DST" > "$tmp"
# 활성 라인(주석·빈줄 제외)만 새 블록으로 추가
{ echo "$B"; grep -vE '^[[:space:]]*(#|$)' "$SRC"; echo "$E"; } >> "$tmp"
cp -p "$DST" "$DST.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true
cat "$tmp" > "$DST"; rm -f "$tmp"
echo "applied groot.lab block to $DST:"
awk -v b="$B" -v e="$E" 'BEGIN{s=0} $0==b{s=1} s{print "  "$0} $0==e{s=0}' "$DST"
