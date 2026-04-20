from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.core.http_client import HttpClient
    from scanner.report.models import Finding


class Form:
    """Lightweight container for a discovered HTML form."""

    def __init__(
        self,
        action: str,
        method: str,
        fields: dict[str, str],
    ) -> None:
        self.action = action
        self.method = method.upper()
        self.fields = fields

    def __repr__(self) -> str:
        return f"Form(action={self.action!r}, method={self.method!r}, fields={list(self.fields.keys())!r})"


class BaseModule(ABC):
    """Abstract base class that every scan module must inherit from."""

    name: str = ""
    description: str = ""

    def __init__(self, client: "HttpClient") -> None:
        self.client = client

    @abstractmethod
    def run(
        self,
        urls: list[str],
        forms: list[Form],
    ) -> list["Finding"]:
        ...
