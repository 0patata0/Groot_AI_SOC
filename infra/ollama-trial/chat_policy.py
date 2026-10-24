"""Pure Mattermost routing/formatting policy; no credentials or network."""
import json
import re
from datetime import datetime, timezone, timedelta
from harness import footer_free

ID = re.compile(r'[a-z0-9]{26}\Z')
KST = timezone(timedelta(hours=9))


def eligible(post, config, channel, members=()):
    if not all(ID.fullmatch(str(post.get(k, ''))) for k in ('id', 'user_id', 'channel_id')):
        return False
    if (post['user_id'] not in config['allowed_users'] or post['user_id'] == config['bot_id'] or
            post.get('delete_at') or post.get('type') or post.get('props', {}).get('from_bot') or
            not isinstance(post.get('message'), str) or not post['message'].strip() or
            len(post['message']) > 6000 or post.get('create_at', 0) < config['enabled_at_ms']):
        return False
    if channel.get('id') != post['channel_id'] or channel.get('delete_at'):
        return False
    if channel['id'] == config['channel_id']:
        return channel.get('team_id') == config['team_id'] and channel.get('name') == 'soc-ollama'
    return channel.get('type') == 'D' and set(members) == {config['bot_id'], post['user_id']}


def question_with_history(post, prior, bot_id):
    # Keep only this human and this bot; other bots/admins are not conversation context.
    rows = [p for p in prior if p.get('id') != post['id'] and not p.get('delete_at') and
            not p.get('type') and p.get('user_id') in (post['user_id'], bot_id) and
            p.get('create_at', 0) <= post['create_at']]
    rows.sort(key=lambda p: (p.get('create_at', 0), p['id']))
    context = []
    for p in rows[-10:]:
        text = footer_free(str(p.get('message', '')))[:1800]
        if p.get('user_id') == bot_id and text.startswith('확인하고 있습니다.'):
            continue
        context.append({'role': 'assistant' if p['user_id'] == bot_id else 'user', 'text': text})
    while len(json.dumps(context, ensure_ascii=False)) > 8000:
        context.pop(0)
    if not context:
        return post['message']
    return ('아래 과거 대화는 후속 질문의 문맥이며 현재 상태의 근거가 아닙니다. '
            '현재 질문에 필요한 상태는 다시 조회하세요.\n<previous_conversation>\n' +
            json.dumps(context, ensure_ascii=False) + '\n</previous_conversation>\n현재 질문:\n' + post['message'])


def kst_text(text):
    # Convert explicit timezone-bearing ISO timestamps only; never guess naive dates.
    pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})'
    def convert(m):
        try:
            return datetime.fromisoformat(m[0].replace('Z', '+00:00')).astimezone(KST).isoformat(timespec='seconds')
        except ValueError:
            return m[0]
    return re.sub(pattern, convert, text)


def final_text(report, elapsed):
    if report.get('status') not in ('completed', 'partial') or not isinstance(report.get('final_response'), str):
        answer = '이번 요청을 끝까지 확인하지 못했습니다. 잠시 후 다시 질문해 주세요. 서버 상태가 정상이라는 뜻은 아닙니다.'
    else:
        answer = kst_text(footer_free(report['final_response'])).strip()
    if not answer:
        answer = '확인한 답변을 생성하지 못했습니다. 다시 질문해 주세요.'
    # Bound the Mattermost post; do not silently claim a truncated answer is complete.
    if len(answer) > 12000:
        answer = answer[:12000] + '\n\n(답변이 길어 일부를 생략했습니다. 범위를 좁혀 질문해 주세요.)'
    return answer + '\n\n---\nSOC 비교 시험 · ' + datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S KST') + f' · 처리 {elapsed:.1f}초'
