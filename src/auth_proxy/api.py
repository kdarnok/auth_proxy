from typing import Callable
from typing import TypeVar
from typing import Sequence
from typing import Optional
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
    response_handlers: Optional[dict] = None  # XXX typing
    dependencies: dict

    def __init__(self, config: dict):
        self.dependencies = {}
        self.config = config

    def response(self, flow: HTTPFlow) -> HTTPFlow:
        if flow in self.dependencies:
            parent, state = self.dependencies[flow]
        else:
            parent, state = None, None

        rh = self.response_handlers or {}
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
            # flow.intercept()  # A1
            self.dependencies[new_flow] = (flow, state)
        if new_flow is parent:
            new_flow.resume()
        if new_flow.response is None:
            new_flow.resume()  # A1
            ctx.master.commands.call('replay.client', [new_flow])

        return new_flow


@dataclass
class ResponseHandler:
    path: Optional[str] = None
    state: Optional[str] = None

    def __post_init__(self):
        self.func = None

    def __set_name__(self, cls: AuthHandler, name: str):
        if cls.response_handlers is None:
            cls.response_handlers = {}
        cls.response_handlers[(self.path, self.state)] = name

    def __call__(self, func: Callable) -> Self:
        assert not self.func
        self.func = func
        return self

    def __get__(self, obj: AuthHandler, objtype: Optional[type[AuthHandler]] = None) -> MethodType:
        assert self.func
        return MethodType(self.func, obj)


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
