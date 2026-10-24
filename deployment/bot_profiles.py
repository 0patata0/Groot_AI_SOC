"""Set bundled SOC bot avatars through the local Mattermost API; no model access."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import struct
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def asset(brand, directory=None):
    require(brand in ('hermes', 'ollama'), 'unknown_bot_brand')
    root = Path(directory) if directory else Path(__file__).parent / 'bot-icons'
    manifest = json.loads((root / 'sources.json').read_text())
    expected = manifest['assets'][brand]
    path = root / (brand + '.png')
    require(not path.is_symlink(), 'avatar_symlink')
    data = path.read_bytes()
    require(len(data) <= 1048576 and data.startswith(b'\x89PNG\r\n\x1a\n') and
            struct.unpack('>II', data[16:24]) == (256, 256), 'avatar_png_shape')
    require(hashlib.sha256(data).hexdigest() == expected['sha256'], 'avatar_source_hash')
    return data


def set_profile_image(base_url, token, user_id, brand, directory=None):
    """Administrator-only provisioning; verifies the bot identity before upload."""
    url = urlsplit(base_url)
    require(url.scheme == 'http' and url.port == 8065 and not url.username and
            not url.password and not url.path and not url.query and not url.fragment,
            'local_mattermost_url_required')
    address = ipaddress.ip_address(url.hostname)
    local = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address']))
    require(address.version == 4 and str(address) in
            {a['local'] for interface in local for a in interface.get('addr_info', [])},
            'mattermost_must_be_on_this_host')
    require(re.fullmatch(r'[a-z0-9]{26}', user_id) is not None, 'bot_id_format')
    image = asset(brand, directory)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(method, path, body=None, content_type=None):
        headers = {'Authorization': 'Bearer ' + token}
        if content_type:
            headers['Content-Type'] = content_type
        req = urllib.request.Request(base_url + '/api/v4' + path, data=body,
                                     headers=headers, method=method)
        try:
            with opener.open(req, timeout=20) as response:
                require(response.status == 200, 'profile_http_status')
                data = response.read(2097153)
                require(len(data) <= 2097152, 'profile_response_limit')
                return data
        except urllib.error.HTTPError as exc:
            raise ValueError('profile_http_' + str(exc.code)) from None

    before = json.loads(request('GET', '/users/' + user_id))
    allowed = ('hermes', 'capstone-assistant') if brand == 'hermes' else ('ollama',)
    require(before.get('id') == user_id and before.get('username') in allowed and
            before.get('is_bot') is True and not before.get('delete_at') and
            'system_admin' not in before.get('roles', '').split(), 'bot_identity_mismatch')
    boundary = 'capstone-avatar-' + secrets.token_hex(16)
    body = (('--' + boundary + '\r\nContent-Disposition: form-data; name="image"; '
             'filename="' + brand + '.png"\r\nContent-Type: image/png\r\n\r\n').encode()
            + image + ('\r\n--' + boundary + '--\r\n').encode())
    request('POST', '/users/' + user_id + '/image', body,
            'multipart/form-data; boundary=' + boundary)
    after = json.loads(request('GET', '/users/' + user_id))
    readback = request('GET', '/users/' + user_id + '/image')
    require(after['id'] == before['id'] and after['username'] == before['username'] and
            after.get('last_picture_update', 0) > before.get('last_picture_update', 0) and
            readback.startswith(b'\x89PNG\r\n\x1a\n'), 'profile_readback_failed')
    return {'brand': brand, 'user_id': user_id, 'username': after['username'],
            'source_sha256': hashlib.sha256(image).hexdigest(),
            'readback_sha256': hashlib.sha256(readback).hexdigest(),
            'last_picture_update': after['last_picture_update'],
            'readback_size': list(struct.unpack('>II', readback[16:24]))}
