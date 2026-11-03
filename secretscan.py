#!/usr/bin/env python3
"""Scan a repository for committed secrets before they reach a remote.

Built for a pre-commit hook: fast, zero dependencies, exits non-zero on a hit.
Every rule is a named regex, so a false positive is one line to fix, and
`--ignore` plus inline `# secretscan: ignore` handle the rest.
"""
from __future__ import annotations

import argparse
import base64
import math
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Name -> pattern. Deliberately narrow: a rule that fires on every long string
# gets disabled by the team within a day, which is worse than no rule at all.
RULES: dict[str, re.Pattern[str]] = {
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS secret key": re.compile(r"(?i)aws.{0,20}?secret.{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "Stripe secret key": re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "OpenAI/Anthropic key": re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"),
    "SendGrid key": re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    "Twilio SID": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
    "JSON Web Token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    "Database URL with password": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s:/@]+@"
    ),
    "Hardcoded password assignment": re.compile(
        r"(?i)\b(?:password|passwd|secret|api_?key|token)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
    ),
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build", ".next"}
SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".lock", ".min.js", ".map",
}
# Values that look like secrets but are obviously examples. Three cheap checks,
# because every one of these shapes shows up in real README and config files.
PLACEHOLDER_SHAPE = re.compile(r"(?i)^(?:x{3,}|\*{3,}|\.{3,}|<[^>]+>|\$\{[^}]+\}|%\([^)]+\)s)$")
PLACEHOLDER_WORD = re.compile(
    r"(?i)change[-_]?me|your[-_]?|placeholder|example|dummy|sample|redacted|fake|"
    r"insert[-_]?|todo|replace[-_]?|xxxx|s3cr3t"
)
PLACEHOLDER_EXACT = {
    "password", "passwd", "secret", "token", "apikey", "api_key", "test", "testing",
    "none", "null", "undefined", "1234567890", "qwertyuiop", "hunter2",
}


@dataclass
class Finding:
    path: Path
    line_no: int
    rule: str
    snippet: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line_no}: {self.rule}: {self.snippet}"


def entropy(value: str) -> float:
    """Shannon entropy in bits per character. Random keys sit above ~3.5."""
    if not value:
        return 0.0
    total = 0.0
    for char in set(value):
        p = value.count(char) / len(value)
        total -= p * math.log2(p)
    return total


def looks_like_a_real_secret(value: str) -> bool:
    value = value.strip()
    if value.lower() in PLACEHOLDER_EXACT:
        return False
    if PLACEHOLDER_SHAPE.match(value) or PLACEHOLDER_WORD.search(value):
        return False
    if len(set(value)) <= 3:  # 'aaaaaaaa', '12341234'
        return False
    return entropy(value) >= 2.6


def scan_text(text: str, path: Path, rules: dict[str, re.Pattern[str]]) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if "secretscan: ignore" in line:
            continue
        if len(line) > 4000:  # minified bundle, not source anyone wrote
            continue
        for name, pattern in rules.items():
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(1) if match.groups() else match.group(0)
            if match.groups() and not looks_like_a_real_secret(value):
                continue
            findings.append(Finding(path, line_no, name, redact(value)))
            break  # one finding per line is enough to fail the commit
    return findings


def redact(value: str) -> str:
    """Never print a secret in full - the log it lands in is the next leak."""
    if len(value) <= 8:
        return value[0] + "*" * (len(value) - 1)
    return f"{value[:4]}...{value[-2:]} ({len(value)} chars)"


def iter_files(root: Path, ignore: list[str]) -> list[Path]:
    out: list[Path] = []
    if root.is_file():
        return [root]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            if any(path.name.endswith(s) for s in SKIP_SUFFIXES):
                continue
            rel = path.relative_to(root).as_posix()
            if any(pat in rel for pat in ignore):
                continue
            out.append(path)
    return sorted(out)


def scan(root: Path, ignore: list[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root, ignore or []):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable: nothing a human typed a key into
        findings.extend(scan_text(text, path, RULES))
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secretscan", description="Scan for committed secrets.")
    ap.add_argument("path", nargs="?", type=Path, default=Path("."))
    ap.add_argument("--ignore", action="append", default=[], metavar="SUBSTRING",
                    help="skip paths containing this; repeatable")
    ap.add_argument("--list-rules", action="store_true", help="print rule names and exit")
    args = ap.parse_args(argv)

    if args.list_rules:
        for name in RULES:
            print(name)
        return 0
    if not args.path.exists():
        print(f"secretscan: no such path: {args.path}", file=sys.stderr)
        return 2

    findings = scan(args.path, args.ignore)
    for finding in findings:
        print(finding)
    if findings:
        print(f"\n{len(findings)} potential secret(s). "
              f"Add '# secretscan: ignore' to a line that is a false positive.",
              file=sys.stderr)
        return 1
    print("No secrets found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
