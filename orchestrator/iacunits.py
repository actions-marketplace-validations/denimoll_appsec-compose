"""Which resource an IaC finding is about: the unit equivalent policies merge in.

A Dockerfile is one image, so the engines' equivalent findings merge per file.
A Terraform file or a Kubernetes manifest holds many resources: two S3 buckets
without versioning in one file are two findings, and Checkov (the resource
block), Trivy (the attribute) and KICS (its own line) place each one on a
different line. The unit is the resource the line falls in, named by its own
text — `resource "aws_s3_bucket" "data"`, `Deployment/web` — so it is stable
when lines move, and usable in a fingerprint.

Anything else (CloudFormation JSON, an unparseable file, a line outside every
resource) has no unit: its findings keep their own identity rather than merge
on a guess.
"""
from __future__ import annotations

import re

_HCL_BLOCK = re.compile(r'^(resource|data|module)\s+((?:"[^"]*"\s*)+)\{')
_YAML_KIND = re.compile(r"^kind:\s*['\"]?([\w.-]+)")
_YAML_NAME = re.compile(r"^\s{2}name:\s*['\"]?([^'\"#\s]+)")
_YAML_NAMESPACE = re.compile(r"^\s{2}namespace:\s*['\"]?([^'\"#\s]+)")


def _hcl_units(lines: list[str]) -> list[tuple[int, int, str]]:
    units, start, label, depth = [], 0, "", 0
    for n, text in enumerate(lines, 1):
        code = text.split("#", 1)[0] if not label else text
        if not label:
            m = _HCL_BLOCK.match(code.strip())
            if not m:
                continue
            start, depth = n, 0
            label = f"{m.group(1)} " + " ".join(m.group(2).split())
        depth += text.count("{") - text.count("}")
        if depth <= 0:
            units.append((start, n, label))
            label = ""
    return units


def _yaml_units(lines: list[str]) -> list[tuple[int, int, str]]:
    units, start = [], 1
    bounds = [n for n, text in enumerate(lines, 1) if text.strip() == "---"]
    for end in [*bounds, len(lines) + 1]:
        kind = name = namespace = ""
        in_metadata = False
        for text in lines[start - 1:end - 1]:
            if not kind and (m := _YAML_KIND.match(text)):
                kind = m.group(1)
            if text.startswith("metadata:"):
                in_metadata = True
                continue
            if in_metadata:
                if text and not text[0].isspace():
                    in_metadata = False
                elif not name and (m := _YAML_NAME.match(text)):
                    name = m.group(1)
                elif not namespace and (m := _YAML_NAMESPACE.match(text)):
                    namespace = m.group(1)
        if kind and name:
            units.append((start, end - 1,
                          f"{kind}/{namespace + '/' if namespace else ''}{name}"))
        start = end + 1
    return units


class Units:
    """Resource units per file, read once, from the scanned tree."""

    def __init__(self, source):
        self._source = source          # baseline._Source: confined to the repo
        self._cache: dict[str, list[tuple[int, int, str]]] = {}

    def _units(self, path: str) -> list[tuple[int, int, str]]:
        if path not in self._cache:
            lines = self._source.lines(path) if self._source else None
            lower = path.lower()
            if not lines:
                units = []
            elif lower.endswith(".tf"):
                units = _hcl_units(lines)
            elif lower.endswith((".yaml", ".yml")):
                units = _yaml_units(lines)
            else:
                units = []
            self._cache[path] = units
        return self._cache[path]

    def label(self, path: str, line: int | None) -> str | None:
        if not path or not line:
            return None
        for start, end, label in self._units(path):
            if start <= line <= end:
                return label
        return None
