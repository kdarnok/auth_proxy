from typing import Callable
from typing import TypeVar
from typing import Sequence
from typing import Optional
from typing import ClassVar
from typing_extensions import Self
from types import MethodType
from dataclasses import dataclass
from inspect import signature

from mitmproxy import ctx
from mitmproxy.http import HTTPFlow


T = TypeVar('T')


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
    handlers: Optional[dict[str, dict[tuple[str | None, str | None], str]]] = None
    dependencies: dict

    def __init__(self, config: dict):
        self.dependencies = {}
        if not self.handlers:
            self.handlers = {}
        self.config = config

    def request(self, flow: HTTPFlow) -> HTTPFlow:
        # don't need more complex request handling for now
        if not self.handlers:
            return flow
        rh = self.handlers.get('request', {})
        if (handler := rh.get((None, None))):
            getattr(self, handler)(flow)
        return flow

    def response(self, flow: HTTPFlow) -> HTTPFlow:
        if flow in self.dependencies:
            parent, state = self.dependencies[flow]
        else:
            parent, state = None, None

        if not self.handlers:
            return flow

        rh = self.handlers.get('response', {})
        for key in ((None, state), (flow.request.path, state)):
            if (handler := rh.get(key)):
                break
        else:
            return

        flow.intercept()  # A1
        handler_func = getattr(self, handler)
        _res = call_with_args(handler_func, (flow, parent))

        if isinstance(_res, tuple):
            new_flow, state = _res
        else:
            new_flow, state = _res, None

        if new_flow is not flow:
            self.dependencies[new_flow] = (parent or flow, state)
        else:
            new_flow.resume()

        if new_flow is parent:
            new_flow.resume()
        if new_flow.response is None:
            new_flow.request.is_custom = True
            new_flow.is_replay = None
            new_flow.resume()
            ctx.options.client_replay_concurrency = -1
            ctx.master.commands.call('replay.client', [new_flow])

        return new_flow


@dataclass
class HandlerRegistration:
    path: Optional[str] = None
    state: Optional[str] = None
    event: ClassVar[str]

    def __post_init__(self):
        self.func = None

    def __set_name__(self, cls: AuthHandler, name: str):
        if cls.handlers is None:
            cls.handlers = {}
        cls.handlers.setdefault(self.event, {})[(self.path, self.state)] = name

    def __call__(self, func: Callable) -> Self:
        assert not self.func
        self.func = func
        return self

    def __get__(self, obj: AuthHandler, objtype: Optional[type[AuthHandler]] = None) -> MethodType:
        assert self.func
        return MethodType(self.func, obj)


class RequestHandler(HandlerRegistration):
    event = 'request'


class ResponseHandler(HandlerRegistration):
    event = 'response'


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
