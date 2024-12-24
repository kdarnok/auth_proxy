from __future__ import annotations
from typing import Any
from pydantic import BaseModel


class HandlerDefinition(BaseModel):
    cls: str
    config: dict[str, Any] = {}


class HostDefinition(BaseModel):
    handler: HandlerDefinition
    host: str | None = None
    path: str = ''
    description: str | None = None


class AuthProxyConfig(BaseModel):
    proxy: dict[str, Any]
    auth: AuthConfig


class AuthConfig(BaseModel):
    tld: str
    hosts: dict[str, HostDefinition]
