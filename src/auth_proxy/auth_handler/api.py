from typing import Callable
from typing import TypeVar
from typing import Sequence
from typing import Generator
from functools import partial
from inspect import signature

from mitmproxy import ctx
from mitmproxy.http import HTTPFlow
from mitmproxy.http import Request
from mitmproxy.http import Response


T = TypeVar('T')
ResponseHandler = Generator[Request, Response, None]


class AuthHandler:
    """
    Per-service authentication handling keeping track of session states. Sub-classes need to implement
    request and response handlers. They get passed the current `mitmproxy.flow.HTTPFlow`
    based on conditions about the request path and the session state.
    Handlers can make decisions to pause the flow by returning a new flow, resume the parent flow
    (return `parent`) and to re-send a request (set `flow.response = None`). Besides the flow,
    a handler may return a new session state string.

    Handlers are declared using the `@RequestHandler` and `@ResponseHandler` decorators, both
    of which can be passed a `path` and a `state`.
    """
    dependencies: dict

    def __init__(self, config: dict):
        ctx.options.client_replay_concurrency = -1
        self.dependencies = {}
        self.config = config

    def request(self, flow: HTTPFlow) -> HTTPFlow:
        # don't need more complex request handling for now
        self.handle_request(flow.request)
        return flow

    def response(self, flow: HTTPFlow) -> None:
        if flow in self.dependencies:
            parent, active_handler = self.dependencies.pop(flow)
            next_request = partial(active_handler.send, flow.response)
        else:
            parent = flow
            active_handler = self.handle_response(flow)
            next_request = partial(next, active_handler)

        flow.intercept()
        try:
            new_request = next_request()
        except StopIteration:
            parent.resume()
            return

        new_flow = make_request(parent, new_request)
        ctx.master.commands.call('replay.client', [new_flow])
        self.dependencies[new_flow] = (parent, active_handler)

    def handle_request(self, request: Request):
        pass

    def handle_response(self, parent: HTTPFlow) -> ResponseHandler:
        return
        yield


def make_request(flow, request):
    new_flow = HTTPFlow(flow.client_conn, flow.server_conn)
    new_flow.request = request.copy()
    return new_flow


def call_with_args(func: Callable[..., T], args: Sequence) -> T:
    sig = signature(func)
    for i in range(len(args), -1, -1):
        _args = args[:i]
        try:
            sig.bind(*_args)
        except TypeError:
            continue
        else:
            break
    else:
        raise TypeError

    return func(*_args)
