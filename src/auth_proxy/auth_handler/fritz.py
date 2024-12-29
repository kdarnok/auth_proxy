import re
from hashlib import md5

from mitmproxy.http import HTTPFlow

from .api import AuthHandler
from .api import ResponseHandler


class FritzBox(AuthHandler):
    def handle_response(self, parent: HTTPFlow) -> ResponseHandler:
        assert parent.response
        if parent.request.path == '/' and (m := re.search(r'"challenge":"(.+?)"', parent.response.text or '')):
            request = parent.request.copy()
            request.path = '/index.lua'
            request.method = 'POST'
            request.urlencoded_form['username'] = self.config['username']
            request.urlencoded_form['lp'] = ''
            request.urlencoded_form['response'] = make_challenge_response(m.group(1), self.config['password'])

            response = yield request

            parent.response = response.copy()


def make_challenge_response(challenge: str, pwd: str) -> str:
    p = (challenge + '-' + pwd).encode('utf-16-le')
    return challenge + '-' + md5(p).hexdigest()
