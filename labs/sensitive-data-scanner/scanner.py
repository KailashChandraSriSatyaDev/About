#!/usr/bin/env python3
"""Educational sensitive-data pattern scanner.

Scans authorized text files, reports rule matches without printing matched values,
and exits with code 1 when findings are present.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


MAX_FILE_BYTES = 2 * 1024 * 1024
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
SCANNABLE_SUFFIXES = {
    ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".conf", ".env", ".py", ".js", ".ts", ".jsx", ".tsx", ".html",
    ".xml", ".csv", ".sql",
}
PLACEHOLDERS = {
    "changeme", "change_me", "example123", "dummysecret", "test_secret",
    "replace_me", "your_api_key", "your_token", "password123",
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    description: str
    pattern: re.Pattern[str]
    value_group: int | None = None


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule_id: str
    severity: str
    description: str


RULES = [
    Rule(
        "PRIVATE_KEY_HEADER",
        "CRITICAL",
        "Private-key PEM header detected",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    Rule(
        "AWS_ACCESS_KEY_ID",
        "HIGH",
        "AWS access-key ID pattern detected",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    Rule(
        "CREDENTIAL_ASSIGNMENT",
        "HIGH",
        "Credential-like assignment detected",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|secret[_-]?key|password)\b\s*[:=]\s*['"]?([A-Za-z0-9_./+=-]{8,})['"]?"""
        ),
        value_group=1,
    ),
    Rule(
        "EMAIL_ADDRESS",
        "MEDIUM",
        "Email address pattern detected",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    ),
]


def iter_candidate_files(paths: Iterable[Path]) -> Iterable[Path]:
    """Yield supported, reasonably sized files from input paths."""
    seen: set[Path] = set()

    for input_path in paths:
        if not input_path.exists():
            raise FileNotFoundError(f"Path does not exist: {input_path}")

        if input_path.is_file():
            candidates = [input_path]
        elif input_path.is_dir():
            candidates = (
                child
                for child in input_path.rglob("*")
                if child.is_file() and not any(part in SKIP_DIRS for part in child.parts)
            )
        else:
            continue

        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)

            if candidate.suffix.lower() not in SCANNABLE_SUFFIXES:
                continue
            try:
                if candidate.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield candidate


def scan_file(path: Path) -> list[Finding]:
    """Scan one text file and return metadata-only findings."""
    findings: list[Finding] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return findings

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                if rule.value_group is not None:
                    value = match.group(rule.value_group).strip().lower()
                    if value in PLACEHOLDERS or value.startswith("example_"):
                        continue

                findings.append(
                    Finding(
                        path=path.as_posix(),
                        line=line_number,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        description=rule.description,
                    )
                )

    return findings


def scan_paths(paths: Iterable[Path]) -> list[Finding]:
    """Scan all supported files under the specified paths."""
    findings: list[Finding] = []
    for path in iter_candidate_files(paths):
        findings.extend(scan_file(path))
    return sorted(findings, key=lambda item: (item.path, item.line, item.rule_id))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan authorized text files for selected sensitive-data patterns."
    )
    parser.add_argument("paths", nargs="+", help="File or directory paths to scan")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    args = parser.parse_args()

    try:
        findings = scan_paths([Path(item) for item in args.paths])
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    elif findings:
        for finding in findings:
            print(
                f"{finding.path}:{finding.line} "
                f"[{finding.severity}] {finding.rule_id}: {finding.description}"
            )
        print(f"\n{len(findings)} finding(s). Matched values were not printed.")
    else:
        print("No findings detected.")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
