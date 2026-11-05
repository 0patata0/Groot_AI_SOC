"""Load the single SOC output skill; no tools, dispatch or status decisions."""
from pathlib import Path
import importlib.util
import re


def policy(directory=None):
    here = Path(__file__).resolve().parent if directory is None else Path(directory)
    candidates = [p for p in (here / 'skills/soc-output/SKILL.md', here / 'SKILL.md') if p.is_file()]
    if len(candidates) != 1:
        raise ValueError('soc_output_skill_missing_or_ambiguous')
    raw = candidates[0].read_bytes()
    return policy_text(raw)


def policy_text(raw):
    if not 1 <= len(raw) <= 16384:
        raise ValueError('soc_output_skill_size')
    text = raw.decode('utf-8')
    parts = text.split('---\n', 2)
    if (len(parts) != 3 or parts[0] or
            not re.search(r'^name: soc-output$', parts[1], re.M) or
            not re.search(r'^description: \S[^\r\n]+$', parts[1], re.M)):
        raise ValueError('soc_output_skill_frontmatter')
    body = parts[2].strip()
    markers = ('<!-- soc-output-policy:start -->', '<!-- soc-output-policy:end -->', 'SOC_OUTPUT_CONTRACT_V1')
    if (any(body.count(m) != 1 for m in markers) or
            not body.startswith(markers[0]) or not body.endswith(markers[1]) or
            not body.index(markers[0]) < body.index(markers[2]) < body.index(markers[1])):
        raise ValueError('soc_output_skill_contract')
    return body


def normalize_tables(text):
    path = Path(__file__).resolve().with_name('chat_markdown.py')
    spec = importlib.util.spec_from_file_location('_soc_output_markdown', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.normalize_tables(text)


def incident_failure(detail):
    """A controller-observed incomplete run, never an incident verdict."""
    reasons = {
        'model_outer_timeout': '조사·보고 검증의 제한 시간 초과',
        'model_subprocess_timeout_requires_review': '모델 실행의 제한 시간 초과',
        'model_process_failure': '모델 실행 실패',
        'model_trace_limit': '조사 기록의 허용 크기 초과',
        'model_prompt_too_large': '조사 입력의 허용 크기 초과',
        'interrupted_run_requires_review': '진행 중이던 조사 실행이 중단됨',
        'model_interrupted_requires_review': '모델 실행이 중단됨',
        'incomplete_model_run_requires_review': '검증 가능한 최종 보고를 확보하지 못함',
        'model_tool_failure_requires_review': '도구 조회 또는 입력 검증 오류',
        'silent_model_result_requires_review': '검증 가능한 조사 보고가 없음',
        'diagnostic_run_incomplete': '조회 또는 보고 검증이 완료되지 않음',
    }
    key = detail if detail in reasons else 'diagnostic_run_incomplete'
    return ('자동 조사를 완료하지 못해 추가 검토가 필요합니다.\n\n'
            '| 확인 항목 | 현재 결과 | 다음 조치·범위 |\n| --- | --- | --- |\n'
            '| 조사 상태 | 미완료·추가 검토 필요 | 정상·종결로 판단하지 않음 |\n'
            '| 확인된 원인 | ' + reasons[key] + ' | 진단 참조: `' + key + '` |\n'
            '| 실제 조치 | 이 보고서로 실행·승인·차단 결과를 확인할 수 없음 | 실제 상태·승인 기록을 별도로 확인 |\n'
            '| 다음 확인 | 실패한 조회·필요 근거와 현재 상태 재확인 | 알림 재전송은 조사·조치를 재실행하지 않음 |')
