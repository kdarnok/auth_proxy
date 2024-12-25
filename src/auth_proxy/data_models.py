from __future__ import annotations
from typing import Any
from typing import Optional
from pydantic import BaseModel


class HandlerDefinition(BaseModel):
    cls: str
    config: dict[str, Any] = {}


class HostDefinition(BaseModel):
    handler: HandlerDefinition
    host: Optional[str] = None
    path: str = ''
    description: Optional[str] = None


class AuthProxyConfig(BaseModel):
    proxy: dict[str, Any]
    auth: AuthConfig


class AuthConfig(BaseModel):
    tld: str
    hosts: dict[str, HostDefinition]
