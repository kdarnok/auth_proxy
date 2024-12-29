import re
from time import time

from mitmproxy.http import HTTPFlow
from mitmproxy.http import Response

from .api import AuthHandler
from .api import ResponseHandler


class ZyxelGS1900(AuthHandler):
    def handle_response(self, parent: HTTPFlow) -> ResponseHandler:
        pwd = '/cgi-bin/dispatcher.cgi?cmd=0'

        assert parent.response and parent.response.text
        if (is_login := parent.request.path in (pwd, f'{pwd}.html')) or (
            # redirects due to timeout (e.g. `?session_chk=1`)
            parent.request.path.startswith('/cgi-bin/dispatcher.cgi?')
            and 'top.location.replace("/cgi-bin/dispatcher.cgi?cmd=4")' in parent.response.text
        ):
            scramble = scramble_password(self.config['password'])

            request = parent.request.copy()
            request.path = f'/cgi-bin/dispatcher.cgi?login=1&username=admin&password={scramble}&dummy={int(time())}'
            request.method = 'GET'
            yield request

            if is_login:  # explicit authentication via login page: forward to main UI page
                parent.response = Response.make(302, '', {'Location': '/cgi-bin/dispatcher.cgi?cmd=1'})
            else:  # intercepted redirect (e.g. due to timeout): extract session id and repeat request
                main_screen = parent.request.copy()
                main_screen.path = '/cgi-bin/dispatcher.cgi?cmd=1'
                main_screen.method = 'GET'
                session_response = yield main_screen

                assert session_response.text
                if (m := re.search(r'setCookie\("XSSID", "(.+?)"\);', session_response.text)):
                    session_id = m.group(1)

                    repeat = parent.request.copy()
                    repeat.cookies['XSSID'] = session_id
                    repeat_response = yield repeat

                    parent.response = repeat_response.copy()
                    parent.response.headers['Set-Cookie'] = session_id


def scramble_password(password: str) -> str:
    # passwords are transmitted in plain text!
    length = len(password)

    scramble = ''
    for idx, c in enumerate(reversed(password)):
        scramble += 'A' * 6 + c
    scramble += 'A' * (320 - length * 7)
    return scramble[:122] + str(length // 10) + scramble[123:288] + str(length % 10) + scramble[289:]
