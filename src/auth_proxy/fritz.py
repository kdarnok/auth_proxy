from typing import Optional
import re
from hashlib import md5

from mitmproxy.http import HTTPFlow

from .api import AuthHandler
from .api import ResponseHandler


class FritzBox(AuthHandler):
    @ResponseHandler(state='pwd')
    def handle_pwd_response(self, flow: HTTPFlow, parent: HTTPFlow) -> HTTPFlow:
        assert flow.response
        parent.response = flow.response.copy()
        return parent

        # XXX if returned flow is parent: parent.resume(); also not state should be present

    @ResponseHandler(path='/')
    def handle_root_response(self, flow: HTTPFlow) -> Optional[tuple[HTTPFlow, str]]:
        assert flow.response
        if (m := re.search(r'"challenge":"(.+?)"', flow.response.text or '')):
            response = make_challenge_response(m.group(1), self.config['password'])

            flow = flow.copy()
            flow.request.path = '/index.lua'
            flow.request.method = 'POST'
            flow.request.urlencoded_form['username'] = 'fritz.box'
            flow.request.urlencoded_form['lp'] = ''
            flow.request.urlencoded_form['response'] = response
            flow.response = None

            return flow, 'pwd'

            # XXX returned flow is not flow --> intercept
            # flow.intercept()
            # XXX has no response, so need to inject new flow
            # ctx.master.commands.call("replay.client", [auth_flow])

        return None
        # XXX not return flow --> continue with flow


def make_challenge_response(challenge: str, pwd: str) -> str:
    # dotted = ''.join('.' if ord(c) > 255 else c for c in pwd)
    p = (challenge + '-' + pwd).encode('utf-16-le')
    return challenge + '-' + md5(p).hexdigest()
