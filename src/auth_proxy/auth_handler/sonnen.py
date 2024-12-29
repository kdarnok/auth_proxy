from hashlib import sha512
from mitmproxy.http import HTTPFlow
from mitmproxy.http import Request
from mitmproxy.http import Response
from passlib.utils.pbkdf2 import pbkdf2

from .api import AuthHandler
from .api import ResponseHandler


class Sonnen(AuthHandler):
    token = None

    def handle_request(self, request: Request):
        # after authentication, attach token to every request
        if self.token:
            request.cookies['authenticationToken'] = self.token
            request.headers['Auth-Token'] = self.token

    def handle_response(self, parent: HTTPFlow) -> ResponseHandler:
        if self.token:
            parent.response.headers['Set-Cookie'] = f'authenticationToken={self.token}'

        if parent.request.path == '/':
            parent.response = Response.make(302, '', {'Location': '/dash/login'})  # index html has hard-coded hostname
            return

        assert parent.response
        if (
            (parent.request.path.startswith('/api/') and parent.response.status_code == 401)
            or parent.request.path == '/dash/login'
        ):
            auth = parent.request.copy()
            auth.path = '/api/challenge'
            auth.method = 'GET'
            auth.text = ''

            auth_response = yield auth

            challenge = auth_response.json()
            response = make_challenge_response(challenge, self.config['password'])
            session_request = parent.request.copy()
            session_request.path = '/api/session'
            session_request.method = 'POST'
            session_request.urlencoded_form['user'] = 'User'
            session_request.urlencoded_form['challenge'] = challenge
            session_request.urlencoded_form['response'] = response

            session_response = yield session_request

            self.token = session_response.json()['authentication_token']

            if parent.request.path == '/dash/login':
                parent.response = Response.make(302, '', {'Location': '/dash/dashboard'})
            else:
                repeat_request = parent.request.copy()
                repeat_response = yield repeat_request  # authentication via request handler
                parent.response = repeat_response.copy()


def make_challenge_response(challenge: str, password: str) -> str:
    return pbkdf2(sha512(password.encode()).hexdigest(), challenge, 7500, keylen=64, prf='hmac-sha512').hex()
