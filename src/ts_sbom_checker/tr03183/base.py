"""Building blocks of the TR tests."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..detect import Format
from ..model import Model


@dataclass
class Finding:
    message: str
    path: list | None = None  # None: the subject's own path


@dataclass
class Context:
    model: Model
    format: Format
    reachable: set[str] | None  # None: the graph has no root


@dataclass(frozen=True)
class TrTest:
    id: str
    tr: str  # section(s) of the TR
    category: str  # "required" | "additional"
    scope: str  # "document" | "component"
    title: str
    check: Callable[[Any, Context], Finding | None]
    # "additional" tests: the test only applies if the field is present
    present: Callable[[Any, Context], bool] | None = None
    # referenced components (TR 3.2.5) only run tests with for_referenced=True
    for_referenced: bool = False
