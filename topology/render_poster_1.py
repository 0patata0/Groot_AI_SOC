#!/usr/bin/env python3
"""포스터(Groot_포스터_편집가능_60x100cm, Architecture 영역)용 상세·버스 토폴로지.

원본 render_current.py / 토폴로지_상세·버스.svg 는 그대로 두고, 이 스크립트는
'_1' 접미사가 붙은 포스터 전용 버전만 생성한다. 표준 라이브러리만 사용.
두 도식 모두 라이트 테마(흰 배경, 상세형 vSwitch 회색). 다크 팔레트(DARK)는 보존.

적용한 변경:
  - 밝은 하늘색 배경에 맞춰 패널·카드·텍스트·의미색을 명도 반전/채도 조정(이전 다크 네이비 테마 대체).
  - 박스 간격·여백·비율을 넓혀 요소가 서로 딱 붙지 않게 재배치.
  - 공통 하네스 등 하단 연결선을 전용 레인으로 분리해 겹침 제거.
  - 라벨 수정: ESXi Host → SOC Server, 공격 시험 호스트 → 공격 호스트,
    EXT·승인된 실습망 → EXT.

실행: python3 -B topology/render_poster_1.py
"""

from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# 짙은 네이비 위에서도 또렷한 의미색(원본 의미 유지, 밝기만 상향).
COLORS = {
    "attack": "#ff6b6b", "management": "#9fb3c8", "logs": "#5bc0f0",
    "llm": "#b9a7ff", "mcp": "#f5b445", "approval": "#6fd48a",
    "internal": "#ff7bac", "external": "#ffb06b",
}

# 포스터 팔레트 (slide1.xml 추출값 기반).
PAGE = "#0d2841"          # 바탕 네이비
PANEL = "#14263d"         # 큰 그룹 패널
PANEL2 = "#102033"        # 한 단계 더 어두운 서브 패널
CARD = "#1b3350"          # 개별 카드
CARD_BORDER = "#2f5075"   # 카드 테두리
GRID = "#8aabd2"          # 보조 선/점선 테두리
TEXT = "#eaf3fc"          # 기본 텍스트(밝은 하늘)
SUBTEXT = "#9fbbdc"       # 보조 텍스트
MUTED = "#7f9cc0"         # 흐린 캡션

DARK = {"colors": COLORS, "page": PAGE, "card": CARD, "card_border": CARD_BORDER,
        "text": TEXT, "subtext": SUBTEXT}

# 라이트 테마: 흰 배경(이전 하늘색 #E2EDF9에서 변경). vSwitch는 중립 회색.
# 밝은 배경 위 대비를 위해 의미색은 같은 색상 계열에서 명도를 낮추고,
# 박스는 흰색/연한 틴트 + 의미색 테두리, 제목은 진한 같은 계열색으로 바꾼다.
LIGHT_COLORS = {
    "attack": "#d94141", "management": "#6b86a6", "logs": "#1b93cf",
    "llm": "#7656dc", "mcp": "#d08608", "approval": "#2f9e55",
    "internal": "#d6497f", "external": "#d97a2b",
}
L = {
    "page": "#ffffff",        # 바탕 흰색
    "panel": "#f4f8fd",       # SOC Server 큰 패널
    "panel_border": "#6f93bf",
    "panel2": "#f7fafe",      # 범례·운영 흐름·EXT 서브 패널
    "card": "#ffffff",        # 개별 카드
    "card_border": "#9db8d8",
    "grid": "#7f9fc6",        # 점선 테두리
    "text": "#12304f",        # 기본 텍스트(진한 네이비)
    "subtext": "#3e5c7e",     # 보조 텍스트
    "muted": "#67819f",       # 흐린 캡션
    "attack_fill": "#fdeded", "attack_title": "#b52f2f",
    "llm_fill": "#f0ecfe", "llm_title": "#5839bd",
    "mcp_fill": "#fdf3de", "mcp_title": "#955e00",
    "ok_fill": "#e9f6ec", "ok_border": "#4fa65f", "ok_title": "#2b7a3c",
    "a_fill": "#fbf1ec", "a_border": "#c96a4a", "a_title": "#a3452a", "a_sub": "#93604c",
    "vs_fill": "#e3e5e8", "vs_border": "#8c939c",
    "b_fill": "#e7f5f1", "b_border": "#3aa58c", "b_title": "#1d7661",
    "c_fill": "#fbebf2", "c_border": "#c05a84", "c_title": "#983962",
}
LIGHT = {"colors": LIGHT_COLORS, "page": L["page"], "card": L["card"],
         "card_border": L["card_border"], "text": L["text"], "subtext": L["subtext"]}


class Diagram:
    def __init__(self, width, height, title, description, theme=DARK):
        self.t = theme
        self.colors = theme["colors"]
        self.parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
            f'<title id="title">{escape(title)}</title>',
            f'<desc id="desc">{escape(description)}</desc>',
            '<style>text{font-family:"Apple SD Gothic Neo","Noto Sans CJK KR",'
            f'"Malgun Gothic",sans-serif;fill:{theme["text"]}}}</style>', '<defs>',
        ]
        for name, color in self.colors.items():
            self.parts.append(
                f'<marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" '
                'markerUnits="userSpaceOnUse" markerWidth="15" markerHeight="15" '
                'orient="auto-start-reverse">'
                f'<path d="M0 0L10 5L0 10Z" fill="{color}"/></marker>'
            )
        self.parts.append('</defs>')
        self.rect(0, 0, width, height, theme["page"], "none", radius=0)

    def rect(self, x, y, w, h, fill=None, stroke=None, radius=12, dash=False, sw=2):
        fill = self.t["card"] if fill is None else fill
        stroke = self.t["card_border"] if stroke is None else stroke
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"'
            + (' stroke-dasharray="9 7"' if dash else '') + '/>'
        )

    def text(self, x, y, value, size=22, color=None, bold=False, center=False):
        color = self.t["text"] if color is None else color
        self.parts.append(
            f'<text x="{x}" y="{y}" font-size="{size}" style="fill:{color}" '
            f'text-anchor="{"middle" if center else "start"}"'
            + (' font-weight="700"' if bold else '') + f'>{escape(value)}</text>'
        )

    def lines(self, x, y, lines, size=21, color=None, center=False, gap=32):
        color = self.t["subtext"] if color is None else color
        for i, value in enumerate(lines):
            self.text(x, y + i * gap, value, size, color, center=center)

    def box(self, x, y, w, h, title, lines, fill=None, stroke=None,
            title_color=None, size=21, title_size=25):
        self.rect(x, y, w, h, fill, stroke)
        self.text(x + w / 2, y + 42, title, title_size, title_color, True, True)
        self.lines(x + w / 2, y + 80, lines, size, center=True)

    def line(self, d, kind="management", arrow=False, both=False, dashed=False, width=3,
             edge_id=None):
        self.parts.append(
            '<path' + (f' id="{edge_id}"' if edge_id else '')
            + f' d="{d}" fill="none" stroke="{self.colors[kind]}" stroke-width="{width}" '
            'stroke-linejoin="round" stroke-linecap="round"'
            + (f' marker-end="url(#{kind})"' if arrow else '')
            + (f' marker-start="url(#{kind})"' if both else '')
            + (' stroke-dasharray="9 7"' if dashed else '') + '/>'
        )

    def dot(self, x, y, kind, radius=6):
        self.parts.append(f'<circle cx="{x}" cy="{y}" r="{radius}" fill="{self.colors[kind]}"/>')

    def vertical(self, x, start, end, kind, crossings=()):
        path = f"M{x} {start}"
        for y in sorted(crossings):
            if start + 8 < y < end - 8:
                path += f"V{y-10}M{x} {y+10}"
        self.line(path + f"V{end}", kind)

    def write(self, filename):
        (ROOT / filename).write_text('\n'.join(self.parts + ['</svg>']) + '\n')


def architecture():
    """포스터 Architecture 영역 비율(약 1.84:1)에 맞춘 2800x1520 캔버스."""
    W, H = 2800, 1540
    d = Diagram(W, H, "Groot Agentic SOC — 네트워크 토폴로지",
                "포스터용 상세형: 상단 외부 공격 호스트·Thor, SOC Server 내 보안 게이트웨이, "
                "중앙 vSwitch, 하단 SIEM·웹 서버. 라이트 블루 테마 · 논리 흐름.", LIGHT)
    C = LIGHT_COLORS

    # ── 제목 (한 줄) · EXT 박스 최상단(윗변 y=118)과 맞춤 ────────────────
    d.text(60, 155, "Groot Agentic SOC", 45, L["text"], bold=True)

    # ── 상단 외부 노드 (EXT) ─────────────────────────────────────────────
    # 공격 호스트 EXT 박스를 SOC Server 글자 중앙(SX+SW/2 = 1400) 기준으로 정렬.
    soc_cx = 1400
    aext_w = 540
    aext_x = soc_cx - aext_w / 2         # = 1130
    d.rect(aext_x, 118, aext_w, 182, L["panel2"], L["grid"], dash=True)
    d.text(aext_x + 25, 148, "EXT", 21, L["subtext"], bold=True)
    atk_x = aext_x + 28
    d.box(atk_x, 162, aext_w - 56, 122, "공격 호스트 / Kali",
          ["승인된 시험 출발지 · IP는 시험별 지정"],
          L["attack_fill"], C["attack"], L["attack_title"], 19, 26)

    # Thor 박스: EXT 점선 박스 없이 박스만, 우측을 SOC Server 패널 우측(2740)에 정렬.
    ext_r = 2740                         # 우측 기준선
    ext_w = 540
    ext_x = ext_r - ext_w                # = 2200
    thor_x = ext_x + 28
    d.box(thor_x, 162, ext_w - 56, 122, "Jetson Thor · Ollama",
          ["운영 추론 · qwen3.6:35b"],
          L["llm_fill"], C["llm"], L["llm_title"], 18, 25)

    # ── SOC Server 바깥 패널 ─────────────────────────────────────────────
    SX, SW, SY, SH = 60, 2680, 370, 920
    d.rect(SX, SY, SW, SH, L["panel"], L["panel_border"], 20)
    d.text(SX + SW / 2, SY + 40, "SOC Server", 27, L["text"], bold=True, center=True)

    # 공격 요청: 공격 호스트 중앙 → SOC Server 상단(수직 직선)
    d.line(f"M{soc_cx} 284V{SY - 4}", "attack", True)
    d.text(soc_cx + 26, 346, "공격·웹 요청", 20, C["attack"])
    # 추론 터널: Thor ↔ 게이트웨이. 진입 x를 Thor 박스 중심에 맞춰 수직 직선으로.
    thor_cx = thor_x + (ext_w - 56) / 2
    thor_top, thor_bot = 284, SY - 4
    d.line(f"M{thor_cx:.0f} {thor_top}V{thor_bot}", "llm", True, True)
    # 라벨은 선 가운데 높이의 왼쪽에 붙임(글자 끝이 선 바로 왼쪽).
    label = "B 추론 터널 → A → Thor"
    d.text(thor_cx - 18 - len(label) * 11, (thor_top + thor_bot) / 2 + 6,
           label, 19, C["llm"])

    # ── Groot-sec / A (상단 보안 게이트웨이) ─────────────────────────────
    AX, AY, AW, AH = 100, SY + 60, 2600, 268
    d.rect(AX, AY, AW, AH, L["a_fill"], L["a_border"], 16)
    d.text(AX + 30, AY + 38, "Groot-sec / A", 26, L["a_title"], bold=True)
    d.text(AX + 300, AY + 38, "보안 게이트웨이 · 192.168.16.230/25 ↔ 10.200.10.1/24",
           20, L["a_sub"])

    # 상단 카드 6개
    card_y, card_h = AY + 66, 170
    cw, gap, start_x = 390, 42, 120
    # 보안 그룹 점선: WAF·IDS·Vector·FW (카드 3~6) 둘러쌈
    sg_x = start_x + 2 * (cw + gap) - 18
    sg_w = 4 * cw + 3 * gap + 36
    d.rect(sg_x, card_y - 30, sg_w, card_h + 44, "none", L["a_border"], 10, True)
    d.rect(sg_x + 20, card_y - 42, 190, 25, L["a_fill"], L["a_border"], 8)
    d.text(sg_x + 115, card_y - 24, "Security Group", 18, L["a_title"], bold=True, center=True)
    # Security Group 점선 윗변과 겹치므로 A 패널색 바탕판을 점선 위에 깔아 글자를 분리.
    d.rect(AX + AW - 532, AY + 17, 262, 30, L["a_fill"], "none", 6)
    d.text(AX + AW - 520, AY + 38, "외부 NIC ens192 · 내부 ens160", 19, L["a_sub"])

    cards = [
        ("nginx Reverse Proxy", ["채팅 → B 내부 TLS :8444", "Wazuh → B :443", "실습 관리 경로 → C"],
         L["card"], L["card_border"], L["text"], 19, 22),
        ("A · MCP", ["resp · rule-a · rule-write-a", "FW 조회·차단·승인형 변경", "3개 논리 서버 / 13도구"],
         L["mcp_fill"], C["mcp"], L["mcp_title"], 18, 23),
        ("WAF ModSecurity + CRS", ["DetectionOnly", "DVWA / 공격 요청 프록시", "기본·커스텀 규칙 조회"],
         L["card"], L["card_border"], L["text"], 19, 21),
        ("Suricata IDS", ["PASSIVE · ens192 패킷 관측", "ET + local → all.rules", "인라인 차단 엔진 아님"],
         L["card"], L["card_border"], L["text"], 19, 22),
        ("Vector + Wazuh Agent", ["FW · WAF · IDS 로그", "정제·수집 → B Wazuh", "호스트 진단 근거"],
         L["card"], L["card_border"], L["text"], 19, 21),
        ("nftables Firewall", ["B/C 외부 통신 NAT", "정책·보호 주소·차단 TTL", "승인된 조치 실행·검증"],
         L["card"], L["card_border"], L["text"], 19, 22),
    ]
    a_card_x = []
    for i, (t, ls, fill, st, tc, sz, ts) in enumerate(cards):
        x = start_x + i * (cw + gap)
        a_card_x.append(x + cw / 2)
        d.box(x, card_y, cw, card_h, t, ls, fill, st, tc, sz, ts)

    # ── vSwitch 바 ───────────────────────────────────────────────────────
    vs_y = AY + AH + 40           # 게이트웨이 아래로 띄움
    d.rect(100, vs_y, 2600, 46, L["vs_fill"], L["vs_border"], 8)
    d.text(1400, vs_y + 31, "vSwitch · 내부망 10.200.10.0/24", 23, L["text"], bold=True, center=True)

    # 상단 카드 → vSwitch (색상별 수직선)
    up_kinds = ["management", "mcp", "attack", "management", "logs", "management"]
    for cx, kind in zip(a_card_x, up_kinds):
        d.line(f"M{cx:.0f} {card_y+card_h}V{vs_y}", kind,
               arrow=(kind == "mcp"), both=(kind == "mcp"))

    # ── 하단: Groot-siem / B (좌), Groot-web / C (우) ─────────────────────
    #  bh는 SOC Server 높이와 분리해 고정(외곽 하단선만 늘려도 B/C 크기는 유지).
    by = vs_y + 88
    bh = SY + 900 - by - 22        # 기준 높이(900)로 고정
    BX, BW = 100, 1700
    CX, CW = 1840, 860
    d.rect(BX, by, BW, bh, L["b_fill"], L["b_border"], 16)
    d.rect(CX, by, CW, bh, L["c_fill"], L["c_border"], 16)

    # 패널 라벨을 맨 위에 두고, 그 아래 2행 카드. 바닥에는 공통 하네스 레인만.
    # 라벨을 박스 시작선에 맞춰 당겨 좌측 MCP 상향선(mcp_up)과 겹치지 않게 한다.
    d.text(BX + 56, by + 34, "Groot-siem / B · 10.200.10.10 · 기본 GW A",
           21, L["b_title"], bold=True)
    d.text(CX + 35, by + 34, "Groot-web / C · 10.200.10.20 · 기본 GW A",
           21, L["c_title"], bold=True)

    card_h2 = 120
    row1_y = by + 54
    row2_y = row1_y + card_h2 + 60     # 행 사이 60px = 승인/MCP 레인
    llm_lane = row2_y + card_h2 + 34   # 하단 공통 추론 레인

    # B 상단 행
    waz_x, waz_w = BX + 48, 436
    d.box(waz_x, row1_y, waz_w, card_h2, "Wazuh",
          ["manager · indexer · dashboard", "기본·커스텀·상관 규칙 조회"],
          L["card"], L["b_border"], L["text"], 18, 23)
    mm_x, mm_w = BX + 520, 540
    d.box(mm_x, row1_y, mm_w, card_h2, "Mattermost + PostgreSQL",
          ["soc-alerts-agent · soc-review-agent", "soc-hermes · soc-ollama"],
          L["ok_fill"], L["ok_border"], L["ok_title"], 18, 23)
    sb_x, sb_w = BX + 1100, 560
    d.box(sb_x, row1_y, sb_w, card_h2, "soc-bot · 승인 브로커",
          ["정확 후보 승인·거부 / 실행 기록", "자동 보고 발신자: soc-report"],
          L["ok_fill"], L["ok_border"], L["ok_title"], 18, 23)

    # B 하단 행 (B·MCP는 좌측 상향 레인 공간 확보를 위해 살짝 오른쪽에 둠)
    bmcp_x, bmcp_w = BX + 48, 436
    d.box(bmcp_x, row2_y, bmcp_w, card_h2, "B · MCP",
          ["읽기 · 진단 · Wazuh 승인형 변경", "5개 논리 서버 / 28도구"],
          L["mcp_fill"], C["mcp"], L["mcp_title"], 18, 23)
    her_x, her_w = BX + 520, 540
    d.box(her_x, row2_y, her_w, card_h2, "Hermes Agent",
          ["사건 조사·판단·제안·사후 확인", "MCP 공통 · Thor 원본35B"],
          L["llm_fill"], C["llm"], L["llm_title"], 18, 23)
    oll_x, oll_w = BX + 1100, 560
    d.box(oll_x, row2_y, oll_w, card_h2, "Ollama Agent",
          ["직접 요청·담당 조회·독립 재검토", "MCP 공통 · Thor 원본35B"],
          L["llm_fill"], C["llm"], L["llm_title"], 18, 23)

    # C 카드
    wca_x, wca_w = CX + 24, 390
    d.box(wca_x, row1_y, wca_w, card_h2, "Wazuh Agent",
          ["웹 · 호스트 로그 수집", "진단 스냅샷"], L["card"], L["c_border"], L["text"], 18, 23)
    dvwa_x, dvwa_w = CX + 440, 390
    d.box(dvwa_x, row1_y, dvwa_w, card_h2, "DVWA",
          ["Apache 웹 서비스", "A WAF 경유"], L["card"], L["c_border"], L["text"], 18, 23)
    log_x, log_w = CX + 24, 806
    d.box(log_x, row2_y, log_w, card_h2, "Log4Shell · CVE 콘솔 · 비웹 실습 터미널",
          ["공격 요청 경로와 실습 관리 프록시 구분", "실습 대상 컨테이너는 선택 기동"],
          L["card"], L["c_border"], L["text"], 18, 22)

    # ── vSwitch → 상단 행 카드 (수직선, 색상별) ──────────────────────────
    vs_b = vs_y + 46
    down = [
        (mm_x + mm_w / 2, "management", False),      # Mattermost
        (sb_x + sb_w / 2, "approval", False),        # soc-bot
        (dvwa_x + dvwa_w / 2, "attack", False),      # DVWA
    ]
    for cx, kind, up in down:
        if up:
            d.line(f"M{cx:.0f} {row1_y}V{vs_b}", kind, True)
        else:
            d.line(f"M{cx:.0f} {vs_b}V{row1_y}", kind, True)
    # Wazuh(관리): 윗변 중심은 패널 라벨과 겹치므로, Wazuh·Mattermost 사이 틈으로
    # 내려와 Wazuh 우측변으로 직각 측면 진입(라벨과 완전 분리).
    waz_gap = (waz_x + waz_w + mm_x) / 2
    waz_in_y = row1_y + 34
    d.line(f"M{waz_gap:.0f} {vs_b}V{waz_in_y:.0f}H{waz_x+waz_w:.0f}", "management", True)
    # Wazuh Agent(C, 로그 상향): 윗변 중심은 C 패널 라벨과 겹치므로, Wazuh Agent·DVWA
    # 사이 틈으로 올려 우측변에서 직각 측면 진출(라벨과 완전 분리).
    wca_gap = wca_x + wca_w + 16                    # Wazuh Agent 우측변 바로 바깥
    wca_out_y = row1_y + 34
    d.line(f"M{wca_x+wca_w:.0f} {wca_out_y:.0f}H{wca_gap:.0f}V{vs_b}", "logs", True)
    # Log4Shell: DVWA 중심 x가 Log4Shell 윗변 범위 안에 있으므로 수직 직선 직결.
    dvwa_cx = dvwa_x + dvwa_w / 2
    d.line(f"M{dvwa_cx:.0f} {row1_y+card_h2}V{row2_y}", "attack", True)

    # ── 하단 공통 하네스: 인접은 직선, 막히면 직각(패널 여백 레인)으로만 ────
    # 열 정렬: Wazuh↕B·MCP(1열) / Mattermost↕Hermes(2열) / soc-bot↕Ollama(3열)
    her_cx = her_x + her_w / 2
    oll_cx = oll_x + oll_w / 2
    bmcp_cx = bmcp_x + bmcp_w / 2
    mm_cx = mm_x + mm_w / 2
    gap_her_oll = (her_x + her_w + oll_x) / 2      # Hermes와 Ollama 사이 빈 공간

    # (1) 승인(초록): 인접 박스끼리 직선만 사용
    #  soc-bot → Mattermost (같은 행, 수평 직선)
    d.line(f"M{sb_x} {row1_y+card_h2/2:.0f}H{mm_x+mm_w}", "approval", True)
    #  Mattermost → (한 가닥) → 분기점 → (두 가닥) → Hermes / Ollama 각각.
    #  공통 줄기·분기 가로구간엔 화살표 없이, 각 에이전트 끝에만 화살표를 둬 깔끔하게.
    fork_y = (row1_y + card_h2 + row2_y) / 2       # 상·하 행 사이 분기 레인
    #  공통 줄기는 분기점→Mattermost 방향으로 그려 Mattermost 쪽에만 화살표(봇→챗).
    #  분기 두 가닥은 에이전트 끝에만 화살표(챗→봇). 양방향이되 분기점 뭉침 없음.
    d.line(f"M{mm_cx:.0f} {fork_y:.0f}V{row1_y+card_h2}", "approval", arrow=True)
    d.line(f"M{mm_cx:.0f} {fork_y:.0f}H{her_cx:.0f}V{row2_y}", "approval", arrow=True)
    d.line(f"M{mm_cx:.0f} {fork_y:.0f}H{oll_cx:.0f}V{row2_y}", "approval", arrow=True)

    # 상향 레인·공통 레인을 모두 박스 '바깥 빈 공간'에만 두어 관통을 차단:
    #   - MCP(주황) 상향: 패널 좌측 여백(BX~bmcp_x)
    #   - 추론(보라) 상향: Hermes·Ollama 사이 세로 틈(우측)
    #   - 봇 아래 가로 레인 2개(MCP/추론)를 서로 다른 y로 분리
    mcp_up = BX + 22                               # 좌측 여백 수직 레인
    bot_bottom = row2_y + card_h2
    mcp_lane = bot_bottom + 29                     # 봇 아랫변 아래 MCP 가로 레인(노란선 +5)
    llm_row = bot_bottom + 54                      # 추론 가로 레인(보라, -2 위로)

    # 봇 아랫변 접점을 색깔별로 좌우 분리: 주황(MCP)은 왼쪽, 보라(추론)는 오른쪽.
    her_mcp_x = her_cx - 70       # Hermes 아랫변 MCP 접점(좌)
    her_llm_x = her_cx + 70       # Hermes 아랫변 추론 접점(우)
    oll_mcp_x = oll_cx - 70       # Ollama 아랫변 MCP 접점(좌)
    oll_llm_x = oll_cx + 70       # Ollama 아랫변 추론 접점(우)

    # (2) MCP(주황): 두 봇 아랫변 → 공통 MCP 레인 → B·MCP, B·MCP → vSwitch(A·MCP)
    #  Hermes·Ollama 모두 아랫변 좌측 접점에서 내려 같은 레인에 모은 뒤 B·MCP로.
    d.line(f"M{her_mcp_x:.0f} {bot_bottom}V{mcp_lane:.0f}", "mcp", both=True)
    d.line(f"M{oll_mcp_x:.0f} {bot_bottom}V{mcp_lane:.0f}", "mcp", both=True)
    #  공통 레인 → B·MCP 아랫변
    d.line(f"M{oll_mcp_x:.0f} {mcp_lane:.0f}H{bmcp_cx:.0f}V{bot_bottom}", "mcp", True)
    #  B·MCP → A·MCP(vSwitch): 좌변 → 좌측 여백 레인으로 수직 상향
    d.line(f"M{bmcp_x} {row2_y+card_h2*0.5:.0f}H{mcp_up:.0f}V{vs_b}", "mcp", True)

    # (3) 추론(보라): 두 봇 아랫변 우측 접점 → 공통 레인 → Ollama 우측 여백 수직 상향
    llm_up = oll_x + oll_w + 20                     # Ollama 우측 바깥 수직 레인(패널 안쪽)
    d.line(f"M{her_llm_x:.0f} {bot_bottom}V{llm_row:.0f}", "llm", both=True)
    d.line(f"M{oll_llm_x:.0f} {bot_bottom}V{llm_row:.0f}", "llm", both=True)
    d.line(f"M{her_llm_x:.0f} {llm_row:.0f}H{llm_up:.0f}V{vs_b}", "llm", True)
    #  라벨은 추론 가로선의 중앙쯤 아래에 배치(center 정렬).
    d.text((her_llm_x + llm_up) / 2, llm_row + 32,
           "공통 하네스 · MCP 8서버 / 41도구", 19, L["llm_title"], bold=True, center=True)

    # ── 범례 (SOC Server 패널 아래 한 줄) ────────────────────────────────
    # ── 하단: 범례 박스(좌) + 운영 흐름 박스(우) ────────────────────────
    leg_y = SY + SH + 26
    leg_h = 188
    # 좌측: 범례 박스
    lgx, lgw = 60, 1180
    d.rect(lgx, leg_y, lgw, leg_h, L["panel2"], L["panel_border"], 12)
    d.text(lgx + 30, leg_y + 38, "범례", 22, L["text"], bold=True)
    items = [("attack", "공격·웹 요청"), ("management", "관리·프록시 연결"),
             ("logs", "로그 전달"), ("approval", "채팅·사람 승인(HITL)"),
             ("mcp", "MCP 호출 (SSH stdio)"), ("llm", "LLM 추론 (B→A→Thor)")]
    for i, (kind, label) in enumerate(items):
        col = i % 3
        row = i // 3
        x = lgx + 30 + col * 390
        y = leg_y + 86 + row * 46
        d.line(f"M{x} {y-7}h52", kind)
        d.text(x + 64, y, label, 19, L["text"])
    d.text(lgx + 30, leg_y + leg_h - 18,
           "vSwitch에서 끝난 선은 같은 색 논리 흐름 · 실제 전용선·물리 배선이 아님", 17, L["muted"])

    # 우측: 운영 흐름 박스 (범례 박스와 동일 색상)
    opx = 1280
    opw = SX + SW - opx            # 우측을 SOC Server 패널 우측에 정렬
    d.rect(opx, leg_y, opw, leg_h, L["panel2"], L["panel_border"], 12)
    d.text(opx + 30, leg_y + 38,
           "LLM 관제 → MCP 제안 → 정확 후보 승인 → 제한 실행 → 결과 확인",
           22, L["text"], bold=True)
    d.lines(opx + 30, leg_y + 74, [
        "① 읽기·조사·상관분석은 MCP 근거로 수행. 두 봇은 필요할 때 독립 재조회·검토.",
        "② 보호 변경은 지정 관리자의 승인 카드·후보 해시·허용 대상에 결속.",
        "③ helper/worker가 승인·증거·보호 주소·TTL을 검사하고 적용·실패·원복 보고.",
        "WAF DetectionOnly / IDS passive · 조사·승인 대기 중 패킷을 붙잡는 INLINE 구조가 아님.",
    ], size=19, gap=30, color=L["subtext"])

    # 상단 여백을 하단(≈36px)과 비슷하게: viewBox 상단을 잘라 여백을 줄인다.
    top_crop = 82
    new_h = H - top_crop
    d.parts[0] = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{new_h}" '
        f'viewBox="0 {top_crop} {W} {new_h}" role="img" aria-labelledby="title desc">'
    )
    d.write("토폴로지_상세_1.svg")


def bus():
    """버스형 라이트 블루 버전. 가로로 긴 참조용(비율 유지). 선 교차는 틈으로 분리."""
    W, H = 2530, 1000
    d = Diagram(W, H, "Groot Agentic SOC — Bus Topology",
                "버스형: 상단 SOC Server 호스트·SVC·vNIC, 하단 INT/EXT 논리 버스. "
                "라이트 블루 테마 · 논리적 재배치이며 실제 버스 배선·동일 L2망이 아니다.", LIGHT)
    HOST_FILL, HOST_BORDER = "#ffffff", "#8eaacb"
    SVC_FILL, SVC_BORDER = "#dce8f6", "#9db8d8"
    SVC_BOX = "#f4f8fd"
    ROW_FILL, ROW_BORDER = "#ffffff", "#c3d4e8"
    NIC_FILL = "#eaf2fb"
    NIC_TX = "#c43c3c"

    d.text(35, 58, "Groot Agentic SOC", 36, L["text"], bold=True)
    d.rect(30, 118, 2470, 860, L["panel"], L["panel_border"], 14)
    d.rect(65, 153, 1740, 470, "none", L["grid"], 10, dash=True)
    d.text(83, 183, "SOC Server", 23, L["text"], bold=True)

    def host(x, w, title, subtitle, services, nic):
        d.rect(x, 205, w, 385, HOST_FILL, HOST_BORDER, 10)
        d.text(x + 18, 242, title, 25, L["text"], bold=True)
        d.text(x + 18, 271, subtitle, 18, L["subtext"])
        horizontal_nic = len(nic) > 1   # NIC 2개(Groot-sec/A)는 가로 나란히 배치
        # 가로 NIC는 SVC 오른쪽에 2개가 들어감. SVC~NIC 간격을 세로 NIC 호스트
        # (Groot-siem, 약 12px)와 맞추도록 SVC 폭을 조금 더 줄인다.
        sw = w - (257 if horizontal_nic else 155)
        d.rect(x + 18, 295, sw, 270, SVC_BOX, SVC_BORDER, 8)
        d.rect(x + 18 + sw / 2 - 34, 305, 68, 27, SVC_FILL, SVC_BORDER, 6)
        d.text(x + 18 + sw / 2, 326, "SVC", 17, L["text"], center=True)
        d.rect(x + 28, 344, sw - 20, 209, "none", SVC_BORDER, 6, dash=True)
        for i, label in enumerate(services):
            d.rect(x + 38, 357 + 36 * i, sw - 40, 29, ROW_FILL, ROW_BORDER, 5)
            d.text(x + 18 + sw / 2, 378 + 36 * i, label, 16, L["text"], center=True)
        for i, (n, port) in enumerate(nic):
            if horizontal_nic:
                # 두 vNIC를 좌우로 나란히 배치하되, 가장 오른쪽 vNIC의 우측 끝을
                # 다른 호스트 NIC와 같은 간격(호스트 우측 끝에서 17px 안쪽)에 맞춤.
                nw = 100
                gap = 10
                right_edge = x + w - 17            # 다른 NIC와 동일 간격
                # i=마지막이 가장 오른쪽. 오른쪽 기준으로 왼쪽으로 배치.
                slot = (len(nic) - 1 - i)          # 0=가장 오른쪽
                nx = right_edge - nw - slot * (nw + gap)
                ny = 393
            else:
                nw = 108
                nx = x + w - 125
                ny = 393 + 90 * i
            d.rect(nx, ny, nw, 70, NIC_FILL, HOST_BORDER, 6)
            d.text(nx + nw / 2, ny + 24, "vNIC" if title.startswith('Groot') else "NIC",
                   16, NIC_TX, True, True)
            d.text(nx + nw / 2, ny + 52, n, 16, L["text"], center=True)
            last_nic_cx = nx + nw / 2            # 마지막 NIC 박스 중심 x
            if port is not None:
                # 각 NIC 중심에서 자기 x로 수직 하강(가로 배치면 좌우로 분리되어 깔끔).
                px = nx + nw / 2
                if n == "ens160":
                    d.vertical(px, ny + 70, port, "internal")
                    d.dot(px, port, "internal")
                elif n == "ens192" and horizontal_nic:
                    # Groot-sec/A의 ens192는 EXT 버스 두 줄(Attack/Admin 785,
                    # LLM Inference 860)에 각각 별도 가닥으로 수직 직선 하강.
                    lx, rx = px - 22, px + 22
                    d.vertical(lx, ny + 70, 785, "external")
                    d.dot(lx, 785, "external")
                    d.vertical(rx, ny + 70, 860, "external")
                    d.dot(rx, 860, "external")
                else:
                    d.vertical(px, ny + 70, port, "external")
                    d.dot(px, port, "external")
        return last_nic_cx       # 마지막 NIC 박스 중심 x (Thor 세로선 정렬용)

    # Groot-sec/A는 vNIC 2개를 가로로 두므로 폭을 넓힘. 뒤 호스트는 그만큼 밀림.
    ax = host(85, 700, "Groot-sec / A", "GW · Security · 10.200.10.1", [
        "nginx / chatproxy · nftables FW/NAT", "WAF ModSecurity + CRS · DetectionOnly",
        "Suricata · passive / all.rules", "Vector · Wazuh Agent",
        "MCP A: resp / rule-a / rule-write-a",
    ], [("ens160", 710), ("ens192", 785)])
    host(810, 540, "Groot-siem / B", "SIEM · Agent · Chat · 10.200.10.10", [
        "Wazuh · Mattermost + PostgreSQL", "soc-bot / 승인 브로커 · soc-report",
        "Hermes + Ollama Agents", "MCP B 5서버 · 공통 전체 8서버/41도구",
        "추론 SSH 터널 B:11435 → A → Thor",
    ], [("ens160", 710)])
    host(1375, 410, "Groot-web / C", "서비스 · 10.200.10.20", [
        "Wazuh Agent", "Apache / DVWA", "Log4Shell", "CVE 콘솔 · 터미널", "선택 기동 실습 대상",
    ], [("ens160", 710)])
    host(1810, 320, "공격 호스트 / Kali", "승인된 시험 출발지",
         ["승인된 시험 요청", "대상: DVWA", "대상: Log4Shell"], [("ens192", 785)])
    tx = host(2155, 320, "Jetson Thor", "현재 운영 추론 서버",
              ["Ollama", "qwen3.6:35b", "loopback:11434", "SSH 8022"], [("enP2p1s0", None)])

    for y, kind, label in [(710, "internal", "10.200.10.0/24"),
                            (785, "external", "승인된 실습·관리 경로"),
                            (860, "external", "B → A → Thor SSH 8022")]:
        d.line(f"M440 {y}H2460", kind, True)
        # 라벨을 세로선(696·740 등)을 피해 빈 공간(Groot-siem 아래)으로 이동.
        d.text(850, y - 15, label, 20, LIGHT_COLORS[kind])
    d.rect(70, 688, 130, 45, L["panel"], LIGHT_COLORS["internal"], 6)
    d.text(135, 719, "INT", 22, L["text"], bold=True, center=True)
    d.rect(235, 688, 180, 45, L["panel"], LIGHT_COLORS["internal"], 6)
    d.text(325, 719, "vSwitch", 22, L["text"], bold=True, center=True)
    d.line("M200 710H235M415 710H440", "internal")
    d.rect(70, 762, 130, 120, L["panel"], LIGHT_COLORS["external"], 6)
    d.text(135, 830, "EXT", 22, L["text"], bold=True, center=True)
    for y, label in [(785, "Attack Segment"), (860, "LLM Inference")]:
        d.rect(235, y - 23, 180, 46, L["panel"], LIGHT_COLORS["external"], 6)
        d.text(325, y + 8, label, 21, L["text"], bold=True, center=True)
        d.line(f"M200 {y}H235M415 {y}H440", "external")
    # ens192의 두 EXT 가닥은 host() 안에서 직접 그린다(위 참조). Thor만 아래 처리.
    d.vertical(tx, 463, 860, "external")
    d.dot(tx, 860, "external")
    d.text(70, 925,
           "B/C는 A가 기본 게이트웨이. EXT 두 줄은 용도별 논리 경로이며 실제 별도 NIC·전용선·동일 네트워크가 아니다.",
           22, L["muted"])
    d.text(70, 957,
           "점은 연결, 틈은 연결 없는 교차. 추론은 Thor 원본35B. 두 봇·MCP·승인·보안장비 연결은 상세형 참조.",
           22, L["muted"])
    d.write("토폴로지_버스_1.svg")


if __name__ == "__main__":
    architecture()
    bus()
