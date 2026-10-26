"""Provision the distinct, non-admin publisher for automated SOC reports.

The caller owns the authenticated local Mattermost session. Returned hook IDs
are credentials: keep them in server configuration, never print this result.
"""
import re

USERNAME = 'soc-report'
DESCRIPTION = 'SOC 자동 보고·승인 카드 발행 전용. 판단 주체와 승인자는 각 보고 본문에 표시합니다.'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def provision(call, team_id, channel_id):
    """call(method, path, body=None, absent=False) returns (JSON, headers)."""
    require(all(re.fullmatch(r'[a-z0-9]{26}', x) for x in (team_id, channel_id)), 'publisher_ids')
    channel, _ = call('GET', '/channels/' + channel_id)
    require(channel['team_id'] == team_id and channel['name'] in ('soc-alerts', 'soc-alerts-agent') and
            not channel.get('delete_at'), 'publisher_channel_identity')
    user, _ = call('GET', '/users/username/' + USERNAME, absent=True)
    if user is None:
        bot, _ = call('POST', '/bots', {'username': USERNAME, 'display_name': USERNAME,
                                      'description': DESCRIPTION})
        user, _ = call('GET', '/users/' + bot['user_id'])
    require(user.get('username') == USERNAME and user.get('is_bot') is True and
            user.get('roles', '').split() == ['system_user'] and not user.get('delete_at'),
            'publisher_must_be_active_nonadmin_bot')
    uid = user['id']
    bot, _ = call('GET', '/bots/' + uid)
    require(bot.get('description') == DESCRIPTION and bot.get('display_name') == USERNAME,
            'existing_publisher_identity_requires_review')
    call('POST', '/teams/' + team_id + '/members', {'team_id': team_id, 'user_id': uid})
    call('POST', '/channels/' + channel_id + '/members', {'user_id': uid})
    hooks = []
    for page in range(100):
        values, _ = call('GET', '/hooks/incoming?team_id=' + team_id + '&per_page=100&page=' + str(page))
        hooks.extend(h for h in values if h.get('user_id') == uid)
        if len(values) < 100:
            break
    else:
        raise ValueError('publisher_hook_inventory_limit')
    require(len(hooks) <= 1, 'publisher_duplicate_hooks')
    if hooks:
        hook = hooks[0]
    else:
        hook, _ = call('POST', '/hooks/incoming', {
            'channel_id': channel_id, 'user_id': uid, 'channel_locked': True,
            'display_name': USERNAME, 'description': DESCRIPTION, 'username': USERNAME})
    require(hook.get('user_id') == uid and hook.get('channel_id') == channel_id and
            hook.get('channel_locked') is True and hook.get('display_name') == USERNAME and
            re.fullmatch(r'[a-z0-9]{26}', hook.get('id', '')), 'publisher_hook_identity')
    actual, _ = call('GET', '/hooks/incoming/' + hook['id'])
    require(all(actual.get(k) == hook.get(k) for k in ('id', 'user_id', 'channel_id', 'channel_locked')),
            'publisher_hook_readback')
    return {'bot_id': uid, 'username': USERNAME, 'hook': actual}
