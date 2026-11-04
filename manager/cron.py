"""A small 5-field cron matcher: minute hour day-of-month month day-of-week.

Enough to run a schedule while `serve` is up, and strict enough that what it
accepts is safe to print into a crontab: only the characters a field can hold,
so neither a newline nor a `%` (crontab's own newline) gets through.

Follows Vixie cron where it matters: when both day fields are restricted a day
matches either one, and a field starting with `*` (`*/2` too) counts as
unrestricted. Day-of-week 0 and 7 are both Sunday.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from .paths import UsageError

_FIELDS = [("minute", 0, 59, {}), ("hour", 0, 23, {}), ("day-of-month", 1, 31, {}),
           ("month", 1, 12, {n: i + 1 for i, n in enumerate(
               "jan feb mar apr may jun jul aug sep oct nov dec".split())}),
           ("day-of-week", 0, 7, {n: i for i, n in enumerate(
               "sun mon tue wed thu fri sat".split())})]
_SAFE = re.compile(r"[A-Za-z0-9*/,\- ]+")


@dataclass(frozen=True)
class Cron:
    minute: frozenset
    hour: frozenset
    dom: frozenset
    month: frozenset
    dow: frozenset
    dom_any: bool
    dow_any: bool

    def matches(self, when: datetime) -> bool:
        if when.minute not in self.minute or when.hour not in self.hour \
                or when.month not in self.month:
            return False
        dom, dow = when.day in self.dom, (when.weekday() + 1) % 7 in self.dow
        if self.dom_any or self.dow_any:
            return dom and dow
        return dom or dow


def _value(text: str, label: str, low: int, high: int, names: dict) -> int:
    value = names.get(text.lower())
    if value is None:
        if not text.isdigit():
            raise UsageError(f"cron {label}: '{text}' is not a value")
        value = int(text)
    if not low <= value <= high:
        raise UsageError(f"cron {label}: {value} is out of range {low}-{high}")
    return value


def _field(text: str, label: str, low: int, high: int, names: dict) -> frozenset:
    values = set()
    for part in text.split(","):
        span, slash, step_text = part.partition("/")
        step = 1
        if slash:
            if not step_text.isdigit() or int(step_text) == 0:
                raise UsageError(f"cron {label}: bad step in '{part}'")
            step = int(step_text)
        if span == "*":
            first, last = low, high
        elif "-" in span:
            a, _, b = span.partition("-")
            first = _value(a, label, low, high, names)
            last = _value(b, label, low, high, names)
            if first > last:
                raise UsageError(f"cron {label}: range '{span}' runs backwards")
        else:
            first = _value(span, label, low, high, names)
            last = high if slash else first
        values.update(range(first, last + 1, step))
    return frozenset(values)


def parse(expression: object) -> Cron:
    if not isinstance(expression, str):
        raise UsageError("cron: expected a string of 5 fields")
    fields = expression.split()
    if len(fields) != 5 or not _SAFE.fullmatch(expression.strip()):
        raise UsageError(f"cron {expression!r}: expected 5 fields: minute hour day month weekday")
    parsed = [_field(text, label, low, high, names)
              for text, (label, low, high, names) in zip(fields, _FIELDS)]
    dow = frozenset(0 if d == 7 else d for d in parsed[4])
    return Cron(parsed[0], parsed[1], parsed[2], parsed[3], dow,
                fields[2].startswith("*"), fields[4].startswith("*"))


def normalize(expression: str) -> str:
    """Validate, and collapse the spacing: this form is what gets stored and printed."""
    parse(expression)
    return " ".join(expression.split())
