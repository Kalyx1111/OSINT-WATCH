"""OSINT Watch - keyword vocabulary (max 50 entries) and matcher.

Entry syntax (one per line):
  word                 whole word, case-insensitive
  "south china sea"    phrase (quotes optional)
  missil*              wildcard: missile, missiles, missilery ...
  cs:PLA               case-sensitive term
  a + b                ALL terms must appear (spaces around +)
  !hypersonic          urgent: bypasses quiet hours, max priority push
  -friday sale         exclusion: any post matching it never alerts

Patterns are built from escaped literals only - user text is never compiled as regex.
By Aryan / @EPureNest
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

MAX_ENTRY_LEN = 100
TEXT_SCAN_LIMIT = 20000


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Term:
    pattern: re.Pattern
    case_sensitive: bool
    text: str


@dataclass(frozen=True)
class Rule:
    raw: str
    label: str
    terms: tuple
    urgent: bool
    exclude: bool


def _unspaced(ch: str) -> bool:
    """Scripts written without spaces: word boundaries make no sense there."""
    o = ord(ch)
    return (0x3040 <= o <= 0x30FF or 0x3400 <= o <= 0x9FFF or 0xF900 <= o <= 0xFAFF or 0xAC00 <= o <= 0xD7AF
            or 0x0E00 <= o <= 0x0EFF or 0x1780 <= o <= 0x17FF or 0x20000 <= o <= 0x2FA1F)


def _norm(s: str, fold: bool) -> str:
    s = unicodedata.normalize("NFKC", s)
    return s.casefold() if fold else s


_AND = re.compile(r"\s+\+\s+")


def _compile_term(part: str) -> Term:
    cs = False
    part = part.strip()
    if part.lower().startswith("cs:"):
        cs, part = True, part[3:].strip()
    if len(part) >= 2 and part[0] == part[-1] and part[0] in "\"'":
        part = part[1:-1].strip()
    if len(part.replace("*", "").strip()) < 2:
        raise RuleError("needs at least 2 characters besides wildcards")
    text = _norm(part, fold=not cs)
    lead, trail = text.startswith("*"), text.endswith("*")
    words = text.strip("*").split()
    if not words:
        raise RuleError("empty term")
    pieces = [r"\w*".join(re.escape(x) for x in w.split("*")) for w in words]
    body = r"\s+".join(pieces)
    if lead:
        body = r"\w*" + body
    if trail:
        body = body + r"\w*"
    if not any(_unspaced(ch) for ch in text):
        body = r"(?<!\w)" + body + r"(?!\w)"
    return Term(re.compile(body), cs, part)


def parse_entry(raw: str) -> Rule:
    s = (raw or "").strip()
    if not s:
        raise RuleError("empty")
    if len(s) > MAX_ENTRY_LEN:
        raise RuleError(f"too long (max {MAX_ENTRY_LEN} characters)")
    urgent = exclude = False
    while s[:1] in ("!", "-"):
        if s[0] == "!":
            urgent = True
        else:
            exclude = True
        s = s[1:].lstrip()
    if urgent and exclude:
        raise RuleError("cannot be both urgent (!) and an exclusion (-)")
    if not s:
        raise RuleError("nothing after the prefix")
    terms = tuple(_compile_term(p) for p in _AND.split(s))
    if exclude and len(terms) > 1:
        raise RuleError("an exclusion takes a single term")
    return Rule(raw=raw.strip(), label=" + ".join(t.text for t in terms), terms=terms, urgent=urgent, exclude=exclude)


def validate_entries(entries: list[str]) -> tuple[list[Rule], list[tuple[str, str]]]:
    rules, errors = [], []
    for e in entries:
        try:
            rules.append(parse_entry(e))
        except RuleError as ex:
            errors.append((e, str(ex)))
    return rules, errors


class Matcher:
    def __init__(self, rules: list[Rule]):
        self.rules = [r for r in rules if not r.exclude]
        self.excludes = [r for r in rules if r.exclude]

    @classmethod
    def from_entries(cls, entries: list[str]) -> "Matcher":
        rules, _ = validate_entries(entries)
        return cls(rules)

    def match(self, text: str) -> list[Rule]:
        """Rules that hit. Empty list if any exclusion hits."""
        text = (text or "")[:TEXT_SCAN_LIMIT]
        fold, cs = _norm(text, True), _norm(text, False)

        def hit(rule: Rule) -> bool:
            return all(t.pattern.search(cs if t.case_sensitive else fold) for t in rule.terms)

        if any(hit(x) for x in self.excludes):
            return []
        return [r for r in self.rules if hit(r)]

    def excluded(self, text: str) -> bool:
        text = (text or "")[:TEXT_SCAN_LIMIT]
        fold, cs = _norm(text, True), _norm(text, False)
        return any(all(t.pattern.search(cs if t.case_sensitive else fold) for t in x.terms) for x in self.excludes)
