#!/usr/bin/env python3
"""Build deterministic OpenSearch Dashboards 2.19.6 saved objects; no API writes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

PREFIX = "groot-soc-20261019-"
INDEX_PATTERN = "wazuh-alerts-*"
INDEX_REFERENCE = "kibanaSavedObjectMeta.searchSourceJSON.index"
TITLE = "Groot SOC | 통합 탐지 현황"
COMMON_QUERY = "NOT rule.groups:(capstone_vector_evidence OR capstone_observation OR capstone_vector_canary OR capstone_validation OR package_shadow)"
WAF_QUERY = "rule.groups:(waf OR modsecurity)"
IDS_QUERY = "rule.groups:suricata"
OTHER_QUERY = "NOT rule.groups:(waf OR modsecurity OR suricata)"
HIGH_QUERY = "rule.level:[7 TO *]"
SUPPORTED_FIELDS = {
    "timestamp", "rule.id", "rule.description", "rule.groups", "rule.level",
    "agent.name", "agent.id", "data.src_ip", "data.dest_ip", "data.dest_port",
    "data.alert.signature", "data.alert.category", "data.transaction.client_ip",
    "data.transaction.request.uri", "data.transaction.response.http_code",
}
NOTICE = """**최근 7일 · 30초 자동 갱신** — WAF·Suricata·Wazuh 통합 알림. 시각은 브라우저 기준입니다.

**알림은 고유 공격이나 차단 성공 건수가 아닙니다.** 실습·관리 트래픽에 따른 오탐이 포함되며 WAF는 DetectionOnly입니다.

정규화 관측·합성 검증은 집계에서 제외합니다. 상단에서 기간과 필터를 조정할 수 있습니다.
"""


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def query(extra=None):
    return COMMON_QUERY if not extra else "(" + COMMON_QUERY + ") AND (" + extra + ")"


def search_source(extra=None, index=True, discover=False):
    source = {"query": {"language": "lucene", "query": query(extra)}, "filter": []}
    if index:
        source["indexRefName"] = INDEX_REFERENCE
    if discover:
        source.update({"highlightAll": True, "version": True})
    return {"searchSourceJSON": encoded(source)}


def index_reference():
    return {"id": INDEX_PATTERN, "name": INDEX_REFERENCE, "type": "index-pattern"}


def count():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {"customLabel": "알림 수"}}


def terms(field, schema, size=8, agg_id="2"):
    labels = {"data.transaction.client_ip": "출발지 IP", "data.src_ip": "출발지 IP",
              "data.alert.signature": "탐지 시그니처", "rule.description": "탐지 내용"}
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "customLabel": labels[field], "orderBy": "1", "order": "desc", "size": size,
                       "otherBucket": False, "otherBucketLabel": "Other",
                       "missingBucket": False, "missingBucketLabel": "Missing"}}


def filters(items, schema, agg_id="2"):
    return {"id": agg_id, "enabled": True, "type": "filters", "schema": schema,
            "params": {"filters": [{"input": {"query": expression, "language": "lucene"},
                                     "label": label} for label, expression in items]}}


def metric_params():
    return {"addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                       "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                       "labels": {"show": True}, "invertColors": False,
                       "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                 "subText": "", "fontSize": 30}}}


def histogram_params(horizontal=False, series=False):
    return {
        "type": "histogram", "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                          "position": "left" if horizontal else "bottom", "show": True, "style": {},
                          "scale": {"type": "linear"},
                          "labels": {"show": True, "filter": True, "truncate": 45 if horizontal else 80}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                       "position": "bottom" if horizontal else "left", "show": True, "style": {},
                       "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": horizontal, "truncate": 100},
                       "title": {"text": "알림 수"}}],
        "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked" if series else "normal",
                          "data": {"label": "알림 수", "id": "1"}, "valueAxis": "ValueAxis-1",
                          "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
        "addTooltip": True, "addLegend": series, "legendPosition": "bottom", "times": [],
        "addTimeMarker": False, "labels": {"show": False},
        "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
    }


def visualization(key, title, kind, params, aggs, extra=None, description=""):
    return {"id": PREFIX + key, "type": "visualization", "references": [index_reference()],
            "attributes": {"title": title, "description": description, "version": 1,
                           "visState": encoded({"title": title, "type": kind, "params": params, "aggs": aggs}),
                           "uiStateJSON": "{}", "kibanaSavedObjectMeta": search_source(extra)}}


def build_objects():
    objects = []
    layout = []

    def add(obj, x, y, w, h):
        objects.append(obj)
        layout.append((obj, x, y, w, h))

    add(visualization("notice", "데이터 읽는 기준", "markdown",
                      {"fontSize": 13, "openLinksInNewTab": True, "markdown": NOTICE}, []), 0, 0, 48, 7)
    metrics = (
        ("metric-total", "전체 탐지 알림", None, 0, 10),
        ("metric-waf", "WAF 알림", WAF_QUERY, 10, 10),
        ("metric-suricata", "Suricata IDS 알림", IDS_QUERY, 20, 10),
        ("metric-other", "Wazuh 기타 알림", OTHER_QUERY, 30, 9),
        ("metric-high", "위험도 7 이상", HIGH_QUERY, 39, 9),
    )
    for key, title, expression, x, width in metrics:
        add(visualization(key, title, "metric", metric_params(), [count()], expression,
                          "선택 기간의 알림 문서 수입니다. 고유 공격 수가 아닙니다."), x, 7, width, 8)

    engines = [("WAF", WAF_QUERY), ("Suricata IDS", IDS_QUERY), ("Wazuh 기타", OTHER_QUERY)]
    date_histogram = {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                      "params": {"field": "timestamp", "customLabel": "시간", "useNormalizedOpenSearchInterval": True,
                                 "scaleMetricValues": False, "interval": "auto", "drop_partials": False,
                                 "min_doc_count": 0, "extended_bounds": {}}}
    add(visualization("trend-network-web", "네트워크·웹 탐지 추이", "histogram", histogram_params(series=True),
                      [count(), date_histogram, filters(engines[:2], "group", "3")],
                      "(" + WAF_QUERY + ") OR (" + IDS_QUERY + ")",
                      "WAF와 Suricata의 시간별 알림 수입니다. 상단 선택 기간을 사용합니다."), 0, 15, 32, 16)
    add(visualization("source-share", "탐지 원천 비중", "pie",
                      {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "bottom",
                       "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
                      [count(), filters(engines, "segment")], description="그룹 기준 WAF · Suricata IDS · Wazuh 기타 알림입니다."),
        32, 15, 16, 16)
    add(visualization("suricata-signatures", "Suricata 시그니처 상위 8", "histogram", histogram_params(horizontal=True),
                      [count(), terms("data.alert.signature", "segment")], IDS_QUERY,
                      "Suricata 그룹의 원본 탐지 시그니처별 알림 수입니다."), 0, 31, 28, 17)
    classifications = [("100101 · CRS 탐지", 'rule.id:"100101"'),
                       ("100102 · 높은 이상 점수", 'rule.id:"100102"'),
                       ("100103 · 반복 탐지", 'rule.id:"100103"')]
    add(visualization("waf-classification", "WAF 규칙 분류", "histogram", histogram_params(horizontal=True),
                      [count(), filters(classifications, "segment")], WAF_QUERY,
                      "Wazuh 규칙 ID 기준 분류입니다. DetectionOnly의 탐지 기록이며 차단 수가 아닙니다."),
        28, 31, 20, 17)
    table_params = {"perPage": 8, "showPartialRows": False, "showMetricsAtAllLevels": False,
                    "showTotal": False, "totalFunc": "sum", "percentageCol": ""}
    add(visualization("waf-sources", "WAF 출발지 상위 8", "table", copy.deepcopy(table_params),
                      [count(), terms("data.transaction.client_ip", "bucket")], WAF_QUERY,
                      "WAF transaction.client_ip별 알림 수입니다. 필드가 존재하는 문서만 집계합니다."), 0, 48, 24, 15)
    add(visualization("suricata-sources", "Suricata 출발지 상위 8", "table", copy.deepcopy(table_params),
                      [count(), terms("data.src_ip", "bucket")], IDS_QUERY,
                      "Suricata src_ip별 알림 수입니다. 필드가 존재하는 문서만 집계합니다."), 24, 48, 24, 15)
    add(visualization("other-rules", "Wazuh 기타 탐지 상위 8", "histogram", histogram_params(horizontal=True),
                      [count(), terms("rule.description", "segment")], OTHER_QUERY,
                      "WAF·Suricata 그룹을 제외한 Wazuh 알림의 규칙 설명별 집계입니다."), 0, 63, 48, 15)
    saved_search = {
        "id": PREFIX + "recent-high", "type": "search", "references": [index_reference()],
        "attributes": {"title": "최근 위험도 7 이상 알림", "description": "선택 기간 안에서 최신 알림부터 표시합니다.",
                       "hits": 0, "columns": ["timestamp", "agent.name", "rule.level", "rule.description"],
                       "sort": [["timestamp", "desc"]], "version": 1,
                       "kibanaSavedObjectMeta": search_source(HIGH_QUERY, discover=True)},
    }
    add(saved_search, 0, 78, 48, 19)

    references, panels = [], []
    for offset, (obj, x, y, width, height) in enumerate(layout):
        panel_id, reference_name = str(offset + 1), "panel_" + str(offset)
        references.append({"name": reference_name, "type": obj["type"], "id": obj["id"]})
        panels.append({"panelIndex": panel_id, "panelRefName": reference_name, "version": "7.3.0",
                       "gridData": {"x": x, "y": y, "w": width, "h": height, "i": panel_id},
                       "embeddableConfig": {}})
    objects.append({
        "id": PREFIX + "dashboard", "type": "dashboard", "references": references,
        "attributes": {"title": TITLE, "description": "WAF·Suricata·Wazuh 원본 알림의 통합 현황. 최근 7일 / 30초 갱신.",
                       "hits": 0, "version": 1, "panelsJSON": encoded(panels),
                       "optionsJSON": encoded({"hidePanelTitles": False, "useMargins": True}),
                       "timeRestore": True, "timeFrom": "now-7d", "timeTo": "now",
                       "refreshInterval": {"pause": False, "value": 30000},
                       "kibanaSavedObjectMeta": search_source(index=False)},
    })
    validate(objects)
    return objects


def validate(objects):
    """Check the deployment contract and independent saved-object references."""
    if len(objects) != 15:
        raise ValueError("expected_15_saved_objects")
    by_id = {obj["id"]: obj for obj in objects}
    if len(by_id) != len(objects) or any(not key.startswith(PREFIX) for key in by_id):
        raise ValueError("duplicate_or_foreign_saved_object_id")
    type_counts = {kind: sum(obj["type"] == kind for obj in objects) for kind in ("visualization", "search", "dashboard")}
    if type_counts != {"visualization": 13, "search": 1, "dashboard": 1}:
        raise ValueError("saved_object_type_count")
    for obj in objects:
        attributes = obj["attributes"]
        source = json.loads(attributes["kibanaSavedObjectMeta"]["searchSourceJSON"])
        if source["query"]["language"] != "lucene" or COMMON_QUERY not in source["query"]["query"] or source["filter"] != []:
            raise ValueError("missing_common_exclusion")
        if obj["type"] != "dashboard":
            if source.get("indexRefName") != INDEX_REFERENCE or obj["references"] != [index_reference()]:
                raise ValueError("index_pattern_reference_mismatch")
        if obj["type"] == "visualization":
            state = json.loads(attributes["visState"])
            if state["type"] not in {"markdown", "metric", "histogram", "pie", "table"}:
                raise ValueError("unsupported_visualization_type")
            if state["title"] != attributes["title"] or len({agg["id"] for agg in state["aggs"]}) != len(state["aggs"]):
                raise ValueError("visualization_title_or_aggregation_ids")
            for agg in state["aggs"]:
                field = agg["params"].get("field")
                if field and field not in SUPPORTED_FIELDS:
                    raise ValueError("unsupported_aggregation_field")
                if "script" in agg["params"]:
                    raise ValueError("scripts_not_allowed")
        for reference in obj["references"]:
            if reference["type"] == "index-pattern":
                if reference["id"] != INDEX_PATTERN:
                    raise ValueError("unexpected_index_pattern")
            elif reference["id"] not in by_id or by_id[reference["id"]]["type"] != reference["type"]:
                raise ValueError("dangling_saved_object_reference")
    dashboard = by_id[PREFIX + "dashboard"]
    attributes = dashboard["attributes"]
    if (attributes["timeRestore"], attributes["timeFrom"], attributes["timeTo"], attributes["refreshInterval"]) != (
            True, "now-7d", "now", {"pause": False, "value": 30000}):
        raise ValueError("dashboard_time_defaults_mismatch")
    panels = json.loads(attributes["panelsJSON"])
    if len(panels) != 14 or {panel["panelRefName"] for panel in panels} != {ref["name"] for ref in dashboard["references"]}:
        raise ValueError("dashboard_panel_reference_mismatch")
    occupied = set()
    for panel in panels:
        grid = panel["gridData"]
        if grid["i"] != panel["panelIndex"] or min(grid["x"], grid["y"]) < 0 or min(grid["w"], grid["h"]) <= 0 or grid["x"] + grid["w"] > 48:
            raise ValueError("invalid_48_column_grid")
        cells = {(x, y) for x in range(grid["x"], grid["x"] + grid["w"]) for y in range(grid["y"], grid["y"] + grid["h"])}
        if occupied.intersection(cells):
            raise ValueError("overlapping_dashboard_panels")
        occupied.update(cells)
    serialized = encoded(objects)
    if "event_type" in serialized or '"script"' in serialized or "script_fields" in serialized:
        raise ValueError("unexpected_event_type_restriction_or_script")


def artifacts(objects):
    return {
        "soc-dashboard.ndjson": ("\n".join(encoded(obj) for obj in objects) + "\n").encode("utf-8"),
        "soc-dashboard.json": (json.dumps(objects, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent / "generated")
    parser.add_argument("--check", action="store_true", help="Validate checked-in artifacts without modifying files")
    args = parser.parse_args()
    objects = build_objects()
    generated = artifacts(objects)
    if args.check:
        for name, data in generated.items():
            if (args.output_dir / name).read_bytes() != data:
                raise ValueError("generated_artifact_differs: " + name)
    else:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name, data in generated.items():
            (args.output_dir / name).write_bytes(data)
    print(json.dumps({"dashboard_id": PREFIX + "dashboard", "title": TITLE, "index_pattern_id": INDEX_PATTERN,
                      "saved_objects": len(objects), "panels": 14, "time_from": "now-7d", "refresh_ms": 30000,
                      "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in generated.items()}},
                     ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print("soc_dashboard_build_failed: " + str(error), file=sys.stderr)
        raise SystemExit(1)
