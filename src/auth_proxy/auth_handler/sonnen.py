from copy import deepcopy
from hashlib import sha512
from mitmproxy.http import HTTPFlow
from passlib.utils.pbkdf2 import pbkdf2

from .api import AuthHandler
from .api import RequestHandler
from .api import ResponseHandler


class Sonnen(AuthHandler):
    token = None

    @RequestHandler()
    def handle_request(self, flow: HTTPFlow):
        # after authentication, attach token to every request
        if self.token:
            flow.request.cookies['authenticationToken'] = self.token
            flow.request.headers['Auth-Token'] = self.token

    @ResponseHandler(path='/api/challenge', state='pwd')
    def handle_challenge(self, flow, parent):
        challenge = flow.response.json()
        response = make_challenge_response(challenge, self.config['password'])
        auth_flow = copy_request(parent)
        auth_flow.request.path = '/api/session'
        auth_flow.request.method = 'POST'
        auth_flow.request.urlencoded_form['user'] = 'User'
        auth_flow.request.urlencoded_form['challenge'] = challenge.encode()
        auth_flow.request.urlencoded_form['response'] = response.encode()
        return auth_flow, 'session'

    @ResponseHandler(path='/api/session', state='session')
    def handle_session(self, flow, parent):
        token = flow.response.json()['authentication_token']
        repeat = copy_request(parent)
        repeat.request.cookies['authenticationToken'] = token
        repeat.request.headers['Auth-Token'] = token
        self.token = token
        return repeat, 'token'

    @ResponseHandler(state='token')
    def handle_token(self, flow, parent):
        repeat = copy_request(parent)
        repeat.request.cookies['authenticationToken'] = self.token
        repeat.request.headers['Auth-Token'] = self.token
        return repeat, 'repeat'

    @ResponseHandler(state='repeat')
    def handle_repeat(self, flow, parent):
        parent.response = flow.response.copy()
        return parent

    @ResponseHandler()
    def handle_root(self, flow):
        if self.token:
            flow.response.headers['Set-Cookie'] = f'authenticationToken={self.token}'

        if flow.request.path.startswith('/api/') and flow.response.status_code == 401:
            # or ('authenticationToken' not in flow.request.cookies and 'Auth-Token' not in flow.request.headers):
            auth_flow = flow.copy()
            auth_flow.request.path = '/api/challenge'
            auth_flow.request.method = 'GET'
            auth_flow.request.text = ''
            auth_flow.response = None
            auth_flow = copy_request(auth_flow)
            return auth_flow, 'pwd'
        return flow


def copy_request(flow):
    new_flow = HTTPFlow(flow.client_conn, flow.server_conn)
    new_flow.request = deepcopy(flow.request)
    return new_flow


def make_challenge_response(challenge: str, password: str) -> str:
    return pbkdf2(sha512(password.encode()).hexdigest(), challenge, 7500, keylen=64, prf='hmac-sha512').hex()
