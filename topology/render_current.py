#!/usr/bin/env python3
"""Render editable SVGs in the original topology/ architecture and bus layouts.

Uses only the standard library. Does not open or modify the historical PNGs.
Run from any directory: python3 -B topology/render_current.py
Operational evidence and observation times: ../infra/diagrams/README.md.
"""

from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COLORS = {
    "attack": "#dc2626", "management": "#606060", "logs": "#2465b5",
    "llm": "#7360e6", "mcp": "#cc8a19", "approval": "#478b2d",
    "internal": "#cf5389", "external": "#ef9848", "training": "#168577",
}


class Diagram:
    def __init__(self, width, height, title, description):
        self.parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
            f'<title id="title">{escape(title)}</title>',
            f'<desc id="desc">{escape(description)}</desc>',
            '<style>text{font-family:"Apple SD Gothic Neo","Noto Sans CJK KR",'
            '"Malgun Gothic",sans-serif;fill:#262626}</style>', '<defs>',
        ]
        for name, color in COLORS.items():
            self.parts.append(
                f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" '
                f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                f'<path d="M0 0L10 5L0 10Z" fill="{color}"/></marker>'
            )
        self.parts.append('</defs>')
        self.rect(0, 0, width, height, "#ffffff", "none", radius=0)

    def rect(self, x, y, w, h, fill="white", stroke="#555555", radius=10, dash=False):
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2"'
            + (' stroke-dasharray="9 7"' if dash else '') + '/>'
        )

    def text(self, x, y, value, size=22, color="#262626", bold=False, center=False):
        self.parts.append(
            f'<text x="{x}" y="{y}" font-size="{size}" style="fill:{color}" '
            f'text-anchor="{"middle" if center else "start"}"'
            + (' font-weight="700"' if bold else '') + f'>{escape(value)}</text>'
        )

    def lines(self, x, y, lines, size=21, color="#4b5563", center=False, gap=31):
        for i, value in enumerate(lines):
            self.text(x, y + i * gap, value, size, color, center=center)

    def box(self, x, y, w, h, title, lines, fill="white", stroke="#999999",
            title_color="#262626", size=21, title_size=25):
        self.rect(x, y, w, h, fill, stroke)
        self.text(x + w / 2, y + 38, title, title_size, title_color, True, True)
        self.lines(x + w / 2, y + 75, lines, size, center=True)

    def line(self, d, kind="management", arrow=False, both=False, dashed=False, width=3,
             edge_id=None):
        self.parts.append(
            '<path' + (f' id="{edge_id}"' if edge_id else '')
            + f' d="{d}" fill="none" stroke="{COLORS[kind]}" stroke-width="{width}" '
            'stroke-linejoin="round"'
            + (f' marker-end="url(#{kind})"' if arrow else '')
            + (f' marker-start="url(#{kind})"' if both else '')
            + (' stroke-dasharray="9 7"' if dashed else '') + '/>'
        )

    def dot(self, x, y, kind, radius=6):
        self.parts.append(f'<circle cx="{x}" cy="{y}" r="{radius}" fill="{COLORS[kind]}"/>')

    def write(self, filename):
        (ROOT / filename).write_text('\n'.join(self.parts + ['</svg>']) + '\n')


def architecture():
    d = Diagram(2600, 1780, "Groot Agentic SOC — 네트워크 토폴로지",
                "기존 topology 상세형 배치: 외부 시험 호스트, ESXi 내 상단 보안 게이트웨이, "
                "중앙 vSwitch, 하단 SIEM과 웹 서버. Thor 추론과 DGX 학습을 구분한다.")
    d.text(55, 52, "Groot Agentic SOC — 네트워크 토폴로지", 38, bold=True)
    d.text(55, 88, "구성 확인: 2026-11-01 21:53~21:55 KST · MCP 계약: 14:24 KST · 물리 배선이 아닌 논리 흐름", 22, "#666666")
    d.box(55, 148, 550, 160, "로컬 Mac / Codex", ["수집·정제·검수·학습 대화 구성", "검수된 정제본 → DGX 학습"],
          "#f4f5f6", "#aaaaaa")
    d.rect(865, 120, 490, 210, "#faf9f5", "#bab5aa", dash=True)
    d.text(888, 149, "EXT · 승인된 실습망", 21, "#666666", True)
    d.box(890, 166, 440, 135, "공격 시험 호스트 / Kali", ["승인된 시험 출발지 · IP는 시험별 지정"],
          "#fce9eb", "#e34b50", "#c7252d", 20, 27)
    d.line("M1110 302V396", "attack", True, width=14)
    d.text(1190, 357, "공격·웹 요청", 21, COLORS["attack"], True)
    d.box(1665, 142, 430, 165, "Jetson Thor · Ollama", ["운영 추론 · qwen3.6:35b", "127.0.0.1:11434 · SSH 8022"],
          "#eeecfd", "#7b6adb", "#4e429e", 22, 28)
    d.box(2170, 142, 385, 165, "DGX Spark", ["학습·체크포인트 / 공유 추론 우선", "본학습 자동 운영 승격 없음"],
          "#e7f4ee", "#44947d", "#246b55", 20, 27)
    d.line("M2360 307C2360 365 2040 365 2040 307", "training", True, dashed=True)
    d.text(2070, 376, "가중치 검증 → 후보 적재·비교", 20, COLORS["training"])

    d.rect(45, 400, 2510, 1050, "#fcfcfb", "#555555", 22)
    d.text(1298, 432, "ESXi Host", 27, bold=True, center=True)
    d.rect(85, 464, 2430, 355, "#fbeee7", "#c95a35", 18)
    d.text(120, 501, "Groot-sec / A", 30, "#a84a27", True)
    d.text(380, 501, "보안 게이트웨이 · 192.168.16.230/25 ↔ 10.200.10.1/24", 23, "#a84a27")
    d.text(2080, 501, "외부 NIC ens192 · 내부 ens160", 22, "#a84a27")
    d.rect(895, 540, 1605, 246, "none", "#bd5634", 10, True)
    d.rect(920, 527, 203, 28, "white", "#bd5634", 8)
    d.text(1021, 548, "Security Group", 20, "#a84a27", True, True)
    d.box(115, 565, 365, 195, "nginx Reverse Proxy", ["채팅 → B 내부 TLS :8444", "Wazuh → B :443", "실습 관리 경로 → C"], stroke="#cf7757")
    d.box(510, 565, 365, 195, "A · MCP", ["resp · rule-a · rule-write-a", "FW 전체 조회 · 차단 · 승인형 변경", "3개 논리 서버 / 13도구"],
          "#fcf0d9", "#ce962d", "#80521d", 20)
    d.box(915, 565, 365, 195, "WAF ModSecurity + CRS", ["DetectionOnly", "DVWA / 공격 요청 프록시", "기본·커스텀 규칙 조회"], stroke="#cf7757", title_size=23)
    d.box(1320, 565, 365, 195, "Suricata IDS", ["PASSIVE · ens192 패킷 관측", "ET + local → all.rules", "인라인 차단 엔진 아님"], stroke="#cf7757")
    d.box(1725, 565, 365, 195, "Vector + Wazuh Agent", ["FW · WAF · IDS 로그", "정제·수집 → B Wazuh", "호스트 진단 근거"], stroke="#cf7757", title_size=24)
    d.box(2130, 565, 365, 195, "nftables Firewall", ["B/C 외부 통신 NAT", "정책·보호 주소·차단 TTL", "승인된 조치 실행·검증"], stroke="#cf7757")
    d.line("M2495 650C2560 650 2550 360 2450 360H1900Q1880 360 1880 340V307", "llm", True, True,
           edge_id="gateway-thor-inference")
    d.text(1628, 391, "B 추론 터널 → A 경유 → Thor", 20, COLORS["llm"])

    for x, kind in [(298, "management"), (692, "mcp"), (1097, "attack"), (1907, "logs")]:
        d.line(f"M{x} 760V872", kind, arrow=(kind == "mcp"), both=(kind == "mcp"))
    d.line("M2315 872V760", "llm", True, True, edge_id="switch-gateway-inference")
    d.rect(85, 872, 2430, 50, "#d8d6cf", "#85837c", 5)
    d.text(1300, 905, "vSwitch · 내부망 10.200.10.0/24", 25, bold=True, center=True)
    d.rect(85, 974, 1510, 440, "#e5f4ee", "#3d9b85", 18)
    d.rect(1645, 974, 870, 440, "#fbeaf0", "#c65381", 18)
    d.box(115, 1020, 430, 140, "Wazuh", ["manager · indexer · dashboard", "기본·커스텀·상관 규칙 / 사건 조회"], stroke="#4b9e89", size=20)
    d.box(575, 1020, 500, 140, "Mattermost + PostgreSQL", ["soc-alerts-agent · soc-review-agent", "soc-hermes · soc-ollama"],
          "#eef6df", "#7ca446", "#54782c", 20)
    d.box(1105, 1020, 460, 140, "soc-bot · 승인 브로커", ["정확 후보 승인·거부 / 실행 기록", "자동 보고 발신자: soc-report"],
          "#eef6df", "#7ca446", "#54782c", 20)
    d.box(115, 1210, 430, 140, "B · MCP", ["읽기 · 진단 · Wazuh 승인형 변경", "5개 논리 서버 / 28도구"],
          "#fcf0d9", "#ce962d", "#80521d", 20)
    d.box(575, 1210, 480, 140, "Hermes Agent", ["사건 조사·판단·제안·사후 확인", "MCP 공통 권한 · Thor 원본35B"],
          "#eeecfd", "#7b6adb", "#4e429e", 20)
    d.box(1085, 1210, 480, 140, "Ollama Agent", ["직접 요청·담당 조회·독립 재검토", "MCP 공통 권한 · Thor 원본35B"],
          "#eeecfd", "#7b6adb", "#4e429e", 20)
    d.text(115, 1390, "Groot-siem / B · 10.200.10.10 · 기본 GW A", 25, "#267361", True)
    d.box(1680, 1020, 355, 140, "Wazuh Agent", ["웹 · 호스트 로그 수집", "진단 스냅샷"], stroke="#c65381", size=20)
    d.box(2060, 1020, 420, 140, "DVWA", ["Apache 웹 서비스", "A WAF 경유"], stroke="#c65381", size=20)
    d.box(1680, 1210, 800, 140, "Log4Shell · CVE 콘솔 · 비웹 실습 터미널", ["공격 요청 경로와 실습 관리 프록시 구분", "실습 대상 컨테이너는 선택 기동"], stroke="#c65381", title_size=24)
    d.text(1680, 1390, "Groot-web / C · 10.200.10.20 · 기본 GW A", 25, "#a33162", True)
    for x, end, kind in [(200, 1020, "management"), (310, 1020, "logs"), (825, 1020, "management"),
                         (1335, 1020, "approval"), (2270, 1020, "attack")]:
        d.line(f"M{x} 922V{end}", kind, True)
    d.line("M1857 1020V922", "logs", True)
    d.line("M2500 922V1260Q2500 1280 2480 1280", "attack", True)
    d.line("M330 1210V1160", "mcp", True)
    # Preserve equipment geometry. Short bot branches meet one shared route
    # per protocol, avoiding duplicated zigzags. Gaps mark non-joining chat
    # crossings; colored dots mark actual schematic joins. These are logical
    # connections, not extra brokers, services or physical links.
    d.line("M560 1180H795M815 1180H1088M1110 1180H1590Q1606 1180 1606 1164V922",
           "mcp", True, edge_id="mcp-shared-to-a")
    d.line("M560 1180V1272Q560 1280 552 1280H545", "mcp", True,
           edge_id="mcp-shared-to-b")
    d.line("M1015 1210V1180", "mcp", both=True, width=2,
           edge_id="hermes-mcp-shared")
    d.line("M1470 1210V1180", "mcp", both=True, width=2,
           edge_id="ollama-mcp-shared")
    for x in [1015, 1470]:
        d.dot(x, 1180, "mcp", radius=3)
    d.line("M805 1160V1210", "approval", True, True, edge_id="mattermost-hermes")
    d.line("M1075 1145L1120 1210", "approval", True, True,
           edge_id="mattermost-ollama")
    d.line("M1105 1090H1075", "approval", True)
    d.line("M980 1372H1612Q1628 1372 1628 1356V922", "llm", True,
           edge_id="inference-shared-to-gateway")
    d.line("M980 1350V1372", "llm", both=True, width=2,
           edge_id="hermes-inference")
    d.line("M1510 1350V1372", "llm", both=True, width=2,
           edge_id="ollama-inference")
    for x in [980, 1510]:
        d.dot(x, 1372, "llm", radius=3)
    d.text(1240, 1404, "공통 하네스 · MCP 8서버 / 41도구", 21, "#4e429e", True, True)

    d.rect(45, 1490, 1085, 245, "white", "#c7c7c7", 12)
    d.text(70, 1528, "범례 · 원본 도식의 색상 구분 유지", 24, bold=True)
    items = [("attack", "공격·웹 요청"), ("management", "관리·프록시 연결"), ("logs", "로그 전달"),
             ("llm", "LLM 추론 (B 터널 → A → Thor)"), ("mcp", "MCP 호출 (제한 SSH stdio)"),
             ("approval", "채팅·사람 승인(HITL)")]
    for i, (kind, label) in enumerate(items):
        x = 75 + (i // 3) * 515
        y = 1574 + (i % 3) * 39
        d.line(f"M{x} {y-7}h60", kind)
        d.text(x + 75, y, label, 20)
    d.text(70, 1707, "vSwitch에서 끝난 선은 같은 색 논리 흐름. 실제 전용선·물리 배선을 뜻하지 않음.", 19, "#777777")
    d.rect(1170, 1490, 1385, 245, "#f3f8eb", "#83a552", 12)
    d.text(1200, 1528, "LLM 관제 → MCP 제안 → 정확 후보 승인 → 제한 실행 → 실제 결과 확인", 25, "#50752d", True)
    d.lines(1200, 1572, [
        "① 읽기·조사·상관분석은 MCP 근거로 수행. 두 봇은 필요할 때 독립 재조회·검토.",
        "② 보호 변경은 지정 관리자의 승인 카드·후보 해시·허용 대상에 결속.",
        "③ helper/worker가 승인·증거·보호 주소·TTL을 검사하고 적용·실패·원복 결과를 보고.",
        "④ 긴급 임시차단은 별도 제한 경로: LLM 판단·MCP 호출·증거 검증 후 짧은 TTL 적용.",
        "WAF DetectionOnly / IDS passive. 조사·승인 대기 동안 패킷을 붙잡는 INLINE 구조가 아님.",
    ], size=21, gap=32)
    d.write("groot_soc_network_architecture.svg")


def bus():
    d = Diagram(2900, 1100, "Groot Agentic SOC — Bus Topology",
                "기존 topology 버스형 배치: 상단 ESXi 서버·SVC·vNIC, 하단 INT/EXT 논리 버스. "
                "Thor 추론과 DGX 학습은 별도 노드이며 같은 물리망을 뜻하지 않는다.")
    d.text(35, 51, "Groot Agentic SOC — Bus Topology", 36, bold=True)
    d.text(35, 88, "2026-11-01 구성 · 기존 SVC/vNIC/INT/EXT 배치 유지 · 논리적 재배치이며 실제 버스 배선·동일 L2망이 아님", 22, "#666666")
    d.rect(30, 118, 2840, 935, "white", "#444444", 0)
    d.rect(65, 153, 1660, 470, "none", "#888888", 0, True)
    d.text(83, 183, "ESXi Host", 23, bold=True)

    def host(x, w, title, subtitle, services, nic):
        d.rect(x, 205, w, 385, "white", "#555555", 0)
        d.text(x + 18, 242, title, 27, bold=True)
        d.text(x + 18, 271, subtitle, 19, "#777777")
        sw = w - 155
        d.rect(x + 18, 295, sw, 270, "white", "#555555", 0)
        d.rect(x + 18 + sw / 2 - 34, 305, 68, 27, "white", "#777777", 0)
        d.text(x + 18 + sw / 2, 326, "SVC", 18, center=True)
        d.rect(x + 28, 344, sw - 20, 209, "none", "#555555", 0, True)
        for i, label in enumerate(services):
            d.rect(x + 38, 357 + 36 * i, sw - 40, 29, "white", "#777777", 0)
            d.text(x + 18 + sw / 2, 378 + 36 * i, label, 17, center=True)
        for i, (n, port) in enumerate(nic):
            nx = x + w - 125
            ny = 393 + 90 * i
            d.rect(nx, ny, 108, 70, "white", "#555555", 0)
            d.text(nx + 54, ny + 24, "vNIC" if title.startswith('Groot') else "NIC", 17, "#e34b50", True, True)
            d.text(nx + 54, ny + 52, n, 17, center=True)
            # NIC ports leave the host at distinct x values, no false join between EXT buses.
            if port is not None:
                px = nx + 25 + i * 50
                d.line(f"M{px} {ny+70}" + (f"H{nx-6}" if len(nic) > 1 and i == 0 else "") + f"V{port}", "internal" if n == "ens160" else "external")
                if len(nic) > 1 and i == 0:
                    px = nx - 6
                d.dot(px, port, "internal" if n == "ens160" else "external")
        return x + w - 100

    ax = host(85, 590, "Groot-sec / A", "GW · Security · 10.200.10.1", [
        "nginx / chatproxy · nftables FW/NAT", "WAF ModSecurity + CRS · DetectionOnly",
        "Suricata · passive / all.rules", "Vector · Wazuh Agent", "MCP A: resp / rule-a / rule-write-a",
    ], [("ens160", 710), ("ens192", 785)])
    host(700, 560, "Groot-siem / B", "SIEM · Agent · Chat · 10.200.10.10", [
        "Wazuh · Mattermost + PostgreSQL", "soc-bot / 승인 브로커 · soc-report", "Hermes + Ollama Agents",
        "MCP B 5서버 · 공통 전체 8서버/41도구", "추론 SSH 터널 B:11435 → A → Thor",
    ], [("ens160", 710)])
    host(1285, 420, "Groot-web / C", "서비스 · 10.200.10.20", [
        "Wazuh Agent", "Apache / DVWA", "Log4Shell", "CVE 콘솔 · 터미널", "선택 기동 실습 대상",
    ], [("ens160", 710)])
    host(1765, 340, "Kali / 시험 호스트", "승인된 시험 출발지", ["승인된 시험 요청", "대상: DVWA", "대상: Log4Shell"], [("시험 NIC", 785)])
    tx = host(2140, 340, "Jetson Thor", "현재 운영 추론 서버", ["Ollama", "qwen3.6:35b", "loopback:11434", "SSH 8022"], [("NIC", None)])
    dx = host(2515, 320, "DGX Spark", "학습 · 공유 추론 우선", ["검수본 학습", "체크포인트", "후보 산출물", "자동 승격 없음"], [("NIC", None)])
    # Long INT/EXT lines are conceptual paths, not separate real NICs or broadcast domains.
    for y, kind, label in [(710, "internal", "10.200.10.0/24"), (785, "external", "승인된 실습·관리 경로"),
                            (860, "external", "B → A → Thor SSH 8022"), (935, "training", "로컬 정제 → DGX 학습 → 검증 후 Thor 후보")]:
        d.line(f"M440 {y}H2820", kind if kind != "training" else "training", True)
        d.text(740 if y < 935 else 455, y - 15, label, 20, COLORS[kind])
    d.rect(70, 688, 130, 45, "white", COLORS["internal"], 0)
    d.text(135, 719, "INT", 22, bold=True, center=True)
    d.rect(235, 688, 180, 45, "white", COLORS["internal"], 0)
    d.text(325, 719, "vSwitch", 22, bold=True, center=True)
    d.line("M200 710H235M415 710H440", "internal")
    d.rect(70, 762, 130, 195, "white", COLORS["external"], 0)
    d.text(135, 864, "EXT", 22, bold=True, center=True)
    for y, label in [(785, "Attack / Admin"), (860, "LLM Inference"), (935, "Training")]:
        d.rect(235, y - 23, 180, 46, "white", COLORS["external"], 0)
        d.text(325, y + 8, label, 21, bold=True, center=True)
        d.line(f"M200 {y}H235M415 {y}H440", "external")
    # A ens192 carries routed external traffic; the stub is not an extra NIC.
    d.line(f"M{ax+50} 651H{ax+75}V860", "external")
    d.dot(ax + 75, 860, "external")
    d.line(f"M{tx} 463V860", "external"); d.dot(tx, 860, "external")
    d.line(f"M{dx} 463V935", "training"); d.dot(dx, 935, "training")
    d.text(70, 1000, "B/C는 A가 기본 게이트웨이. EXT 세 줄은 용도별 논리 경로이며 실제 별도 NIC·전용선·동일 네트워크를 의미하지 않는다.", 22, "#666666")
    d.text(70, 1032, "추론은 Thor 원본35B 유지. DGX 학습본은 무결성·품질·호환 검증 후 후보 적재/승격. 연결·관제 상세는 상세형 토폴로지 참조.", 22, "#666666")
    d.write("groot_soc_topology_bus.svg")


if __name__ == "__main__":
    architecture()
    bus()
