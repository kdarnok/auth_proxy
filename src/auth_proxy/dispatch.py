from __future__ import annotations

from importlib import import_module
from mitmproxy.http import Response

from .auth_handler import AuthHandler
from .data_models import HandlerDefinition
from .data_models import AuthConfig


class AuthDispatch:
    """
    The main `mitmproxy` addon. This provides a landing page
    linking out to all configured services and dispatches intercepted HTTP requests and
    responses to `AuthHandler` instances.
    """
    handlers: dict[str, AuthHandler]

    def __init__(self, config: AuthConfig):
        self.handlers = {
            name: make_auth_handler(host_definition.handler)
            for name, host_definition in config.hosts.items()
        }
        self.config = config

    def request(self, flow):
        tld = self.config.tld
        if flow.request.host == tld:
            # landing page with links to all services
            menu = ''.join(
                f'<li><a href="http://{name}.{tld}/{host.path}">{host.description}</a></li>\n'
                for name, host in self.config.hosts.items()
            )
            flow.response = Response.make(
                200,
                f'<html><body><ul>{menu}</ul></body></html>',
                {'content-type': 'text/html'},
            )
            return

        elif flow.request.host.endswith(f'.{tld}'):
            # generic proxying of our services to `tld`-subdomains
            hostname = flow.request.host[:-(len(tld) + 1)]
            if hostname not in self.config.hosts:
                flow.response = Response.make(
                    404,
                    f'<html><body>No host <code>{hostname}</code> configured.</body></html>',
                    {'content-type': 'text/html'},
                )
                return
            flow.request.host = hostname

            if (handler := self.handlers.get(flow.request.host)):
                handler.request(flow)

    def response(self, flow):
        if (handler := self.handlers.get(flow.request.host)):
            handler.response(flow)


def make_auth_handler(handler: HandlerDefinition) -> AuthHandler:
    return get_cls(handler.cls)(handler.config)


def get_cls(path: str) -> type[AuthHandler]:
    mod, func = path.rsplit('.', 1)
    return getattr(import_module(mod), func)
