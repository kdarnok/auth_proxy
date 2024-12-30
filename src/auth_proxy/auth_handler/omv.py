from json import dumps

from mitmproxy.http import HTTPFlow

from .api import AuthHandler
from .api import ResponseHandler


class OpenMediaVault(AuthHandler):
    def handle_response(self, parent: HTTPFlow) -> ResponseHandler:
        assert parent.response

        if (
            (
                parent.request.path == '/'
                and parent.response.text
                and 'Ext.create("OMV.window.Login"' in parent.response.text
            )
            or parent.response.status_code == 401
        ):
            auth = parent.request.copy()
            auth.path = '/rpc.php'
            auth.method = 'POST'
            auth.text = dumps({
                'service': 'Session',
                'method': 'login',
                'params': {'username': 'admin', 'password': self.config['password'], 'options': None},
            })
            auth.headers['Content-Type'] = 'aplication/json'

            auth_response = yield auth
            cookies = get_set_cookies(auth_response)  # new session cookies

            repeat = parent.request.copy()
            set_cookies(repeat, cookies)  # use session cookies

            response = yield repeat

            parent.response = response.copy()
            # set session cookies
            parent.response.headers.set_all('Set-Cookie', auth_response.headers.get_all('Set-Cookie'))


def get_set_cookies(response):
    return dict(
        cookie.split(';', 1)[0].split('=', 1)
        for cookie in response.headers.get_all('Set-Cookie')
    )


def get_cookies(request):
    if not (cookies := request.headers.get('Cookie')):
        return {}
    return {
        kv[0].strip(): kv[1].strip()
        for cookie in cookies.split(';')
        if (kv := cookie.split('=', 1))
    }


def set_cookies(request, cookies):
    new_cookies = {**get_cookies(request), **cookies}
    request.headers['Cookie'] = ';'.join(map('='.join, new_cookies.items()))
