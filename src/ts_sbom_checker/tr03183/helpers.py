from __future__ import annotations

from ..model import Contact, Property, Value
from ..syntax import is_email, is_url, non_empty, q
from .base import Context, Finding


def with_hints(message: str, hints) -> str:
    hints = [h for h in hints or () if h]
    return f"{message} (hint: {'; '.join(hints)})" if hints else message


def creator_finding(creators: list[Contact], hints, anchor, mapping_text: str) -> Finding | None:
    """TR 5.2.1 / 5.2.2: email address of the creator, or a URL if no email is available."""
    if not creators:
        return Finding(with_hints(f"no creator with email address or URL ({mapping_text})", hints), anchor)
    if any(is_email(c.value) if c.kind == "email" else is_url(c.value) for c in creators):
        return None
    c = creators[0]
    if c.kind == "email":
        message = f"creator email {q(c.value)} is not a valid email address"
    else:
        message = f"creator URL {q(c.value)} is not a valid absolute URL"
    return Finding(with_hints(message, hints), c.path)


def text_finding(field: Value, label: str) -> Finding | None:
    if field.value is None:
        return Finding(f"{label} is missing", field.path[:-1])
    if not non_empty(field.value):
        return Finding(f"{label} is empty", field.path)
    return None


def property_finding(prop: Property, name: str, allowed: tuple[str, ...], ctx: Context) -> Finding | None:
    """BSI property with fixed values (executable / archive / structured)."""
    if prop.mode in ("unsupported", "unavailable"):
        return Finding(prop.problem)
    if prop.mode == "present":
        return None if prop.ok else Finding(prop.problem)
    allowed_text = ", ".join(f'"{a}"' for a in allowed)
    values = prop.values
    if not values:
        return Finding(f'property "{name}" is missing (allowed values: {allowed_text})')
    if ctx.model.exactly_one_property and len(values) > 1:
        return Finding(f'property "{name}" occurs {len(values)} times, it must occur exactly once', values[1].path)
    bad = next((v for v in values if v.value not in allowed), None)
    if bad:
        return Finding(f'property "{name}" has value {q(bad.value)}, allowed: {allowed_text}', bad.path)
    return None


def mapping(ctx: Context, cyclonedx: str, spdx3: str, spdx2: str) -> str:
    """The field mapping of the format, for messages."""
    if ctx.format.type == "CycloneDX":
        return cyclonedx
    return spdx2 if ctx.format.is_spdx2 else spdx3
