"""String normalization and fuzzy matching helpers.

Kept dependency-free (stdlib ``difflib``) so that vendor matching still works
when optional analysis dependencies are unavailable.
"""

from __future__ import annotations

import difflib
import re
import unicodedata

# Legal-entity suffixes that carry no identifying information. Stripped before
# comparison so "Mozilla Corporation" and "Mozilla" normalize alike.
_LEGAL_SUFFIXES = {
    "inc", "incorporated", "corp", "corporation", "co", "company",
    "llc", "llp", "ltd", "limited", "plc", "gmbh", "ag", "sa", "sas",
    "bv", "nv", "ab", "oy", "as", "srl", "spa", "kk", "pty", "pte",
    "foundation", "software", "technologies", "technology", "systems",
    "group", "holdings", "international", "worldwide", "usa", "america",
}

# Trademark / copyright noise commonly embedded in CompanyName fields.
_NOISE_CHARS = "®™©"

_NON_ALNUM = re.compile(r"[^a-z0-9+]+")

# difflib.SequenceMatcher is quadratic in the input length, and VERSIONINFO
# strings are attacker-controlled: a single 15,000-character CompanyName made
# one file take over a hundred times longer to analyse than a normal one. No
# real company or product name comes anywhere near this length, so truncating
# before the fuzzy comparison costs nothing in accuracy.
_MAX_FUZZY_CHARS = 256


def normalize(value: str | None) -> str:
    """Fold a VERSIONINFO string to a comparable canonical form.

    Lowercases, strips accents and trademark glyphs, collapses punctuation to
    single spaces. ``+`` is preserved so that "Notepad++" stays distinct.
    """
    if not value:
        return ""
    text = unicodedata.normalize("NFKD", value)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = "".join(c for c in text if c not in _NOISE_CHARS)
    text = text.lower()
    # "(r)" / "(tm)" / "(c)" written out in ASCII
    text = re.sub(r"\((r|tm|c)\)", " ", text)
    text = _NON_ALNUM.sub(" ", text)
    return " ".join(text.split())


def tokens(value: str | None, *, drop_legal: bool = True, min_length: int = 1) -> list[str]:
    """Normalized word tokens, optionally without legal-entity suffixes."""
    words = normalize(value).split()
    if drop_legal:
        words = [w for w in words if w not in _LEGAL_SUFFIXES]
    return [w for w in words if len(w) >= min_length]


def core_name(value: str | None) -> str:
    """Normalized name with legal suffixes removed - the identifying core."""
    return " ".join(tokens(value))


def ratio(a: str | None, b: str | None) -> float:
    """difflib similarity of two normalized strings, 0.0 - 1.0."""
    na, nb = normalize(a), normalize(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    na, nb = na[:_MAX_FUZZY_CHARS], nb[:_MAX_FUZZY_CHARS]
    return difflib.SequenceMatcher(None, na, nb).ratio()


def contains_name(haystack: str | None, needle: str | None, *, min_token_length: int = 3) -> bool:
    """True when every meaningful token of ``needle`` appears in ``haystack``.

    This is the check that keeps "Mozilla Corporation" (signer CN) matching a
    "Mozilla" (CompanyName) claim without needing a high fuzzy ratio.
    """
    needle_tokens = [t for t in tokens(needle) if len(t) >= min_token_length]
    if not needle_tokens:
        return False
    haystack_tokens = set(tokens(haystack, drop_legal=False))
    if not haystack_tokens:
        return False
    return all(t in haystack_tokens for t in needle_tokens)


def best_match(value: str | None, candidates: list[str], *, threshold: float,
               min_token_length: int = 3,
               single_token_exact_only: bool = False) -> tuple[str | None, float, str]:
    """Match ``value`` against ``candidates``.

    Returns ``(matched_candidate, confidence, method)`` where method is one of
    ``exact``, ``containment`` or ``fuzzy``. Returns ``(None, best_ratio, "none")``
    when nothing clears ``threshold``.

    ``single_token_exact_only`` restricts one-word candidates to exact matches.
    Use it when ``value`` is phrase-shaped: a ProductName of "Quicken for
    Windows" contains the token "Windows", and containment would otherwise read
    that as a Microsoft claim. Company names are not phrase-shaped, so the
    default keeps containment everywhere -- that is what lets a CompanyName of
    "Mozilla Corporation" match the alias "Mozilla".
    """
    if not value:
        return None, 0.0, "none"

    normalized_value = normalize(value)
    value_core = core_name(value)

    # Pass 1: exact match on the normalized or suffix-stripped form.
    for candidate in candidates:
        if normalized_value == normalize(candidate) or (
            value_core and value_core == core_name(candidate)
        ):
            return candidate, 1.0, "exact"

    # Pass 2: token containment in either direction. "Mozilla Firefox Installer"
    # contains the "mozilla" claim; "Mozilla Corporation" contains "Mozilla".
    #
    # Same semantics as contains_name(), but the value's tokens are computed
    # once here rather than once per candidate: normalising a long, attacker-
    # controlled string over a hundred times is what made oversized VERSIONINFO
    # fields slow even after the fuzzy pass was bounded.
    value_haystack = set(tokens(value, drop_legal=False))
    value_needle = [t for t in tokens(value) if len(t) >= min_token_length]
    for candidate in candidates:
        candidate_tokens = tokens(candidate)
        if single_token_exact_only and len(candidate_tokens) <= 1:
            continue
        candidate_needle = [t for t in candidate_tokens if len(t) >= min_token_length]
        candidate_haystack = set(tokens(candidate, drop_legal=False))
        candidate_in_value = bool(candidate_needle and value_haystack
                                  and all(t in value_haystack for t in candidate_needle))
        value_in_candidate = bool(value_needle and candidate_haystack
                                  and all(t in candidate_haystack for t in value_needle))
        if candidate_in_value or value_in_candidate:
            return candidate, 0.95, "containment"

    # Pass 3: fuzzy ratio, for typo-squatting and spacing variants.
    #
    # Compared on the identifying CORE only, never the raw string. Legal and
    # generic suffixes carry no identifying information but are long and shared,
    # so a raw-string ratio lets them dominate: "AVG Technologies" scores 0.88
    # against "ATI Technologies" purely on the suffix, which is high enough to
    # misattribute the vendor. Comparing "avg" against "ati" gives 0.33, which
    # is the answer we actually want.
    # The value is normalised and bounded once here; ratio() would otherwise
    # re-normalise the full-length string for every candidate.
    fuzzy_core = value_core[:_MAX_FUZZY_CHARS]
    fuzzy_full = normalized_value[:_MAX_FUZZY_CHARS]
    best_candidate, best_score = None, 0.0
    for candidate in candidates:
        candidate_core = core_name(candidate)
        # Fall back to the full normalized form only when stripping suffixes
        # leaves nothing to compare (a name that is entirely generic words).
        if value_core and candidate_core:
            score = ratio(fuzzy_core, candidate_core)
        else:
            score = ratio(fuzzy_full, candidate)
        if score > best_score:
            best_candidate, best_score = candidate, score

    if best_score >= threshold:
        return best_candidate, best_score, "fuzzy"
    return None, best_score, "none"


def compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    """Compile a list of regex strings.

    Raises ``ValueError`` naming the offending pattern. Silently dropping a bad
    pattern is worse than failing: a typo in a vendor's ``product_patterns``
    would shrink that vendor's allowlist and raise ``internal_name_mismatch``
    false positives with no diagnostic. The reference-data loader turns this
    into a ``ReferenceDataError`` before any file is analysed.
    """
    compiled: list[re.Pattern[str]] = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            raise ValueError(f"invalid regular expression {pattern!r}: {exc}") from exc
    return compiled


def any_fullmatch(patterns: list[re.Pattern[str]], value: str | None) -> re.Pattern[str] | None:
    """Return the first pattern that fullmatches ``value``, else None."""
    if not value:
        return None
    stripped = value.strip()
    for pattern in patterns:
        if pattern.fullmatch(stripped):
            return pattern
    return None


# ---------------------------------------------------------------------------
# PE section names
# ---------------------------------------------------------------------------
#
# Section names that legitimate toolchains emit. Seeded from the MSVC, MinGW,
# Delphi/Borland, Go and Windows-driver conventions, and cross-checked against a
# survey of real PE files (see tools/section_survey.py). Lowercase; matching is
# case-insensitive.
#
# This set has two jobs: it is the allowlist for the anomaly heuristic below,
# and it is the denylist for the reference-data integrity tests -- no entry here
# may ever appear in a packer's `section_names` list.

STANDARD_SECTION_NAMES: frozenset[str] = frozenset({
    # MSVC / PE core
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".xdata",
    ".reloc", ".rsrc", ".tls", ".debug", ".crt", ".sdata", ".srdata", ".sbss",
    ".didat", ".didata", ".gfids", ".giats", ".00cfg", ".retplne", ".voltbl",
    ".sxdata", ".textbss", ".rodata", ".const", ".cormeta", ".msvcjmc",
    ".detourc", ".detourd", ".imrsiv", ".shared", ".gehcont", ".fothk",
    "_rdata", ".drectve", ".mrdata", ".orpc",
    # Vowel-free Windows system sections. Every one of these trips the
    # "no_vowels" feature, so omitting them is a false positive on genuine
    # system DLLs -- .ndr64 (RPC NDR64 transfer syntax) and .wpp_sf (WPP
    # software tracing) were both found this way in real RPCRT4/WS2_32 images.
    ".ndr64", ".wpp_sf", ".gxfg", ".gljmp",
    # MinGW / GCC / binutils
    ".init", ".fini", ".comment", ".eh_fram", ".symtab", ".stab", ".stabstr",
    ".tbss", ".ctors", ".dtors", ".jcr", ".gcc_exc",
    # Delphi / Borland / Watcom
    "code", "data", "bss", "auto", "dgroup", ".itext", ".tls$",
    # Go
    ".noptrdata", ".noptrbss", ".typelink", ".itablink", ".gosymtab",
    ".gopclntab",
    # Windows drivers
    "init", "page", "pagelk", "pagekd", "pagevrf", "pagedata", "pagespec",
    ".pagelk",
    # Installer toolchains. These are LEGITIMATE and are deliberately not
    # treated as packer evidence: Firefox Setup is an NSIS installer, so a
    # Mozilla claim beside ".ndata" is entirely normal. Listing them here also
    # stops anyone adding them to a packer's section_names later -- the
    # reference-data integrity test rejects any overlap with this set.
    ".ndata", ".wixburn",
})

_VOWELS = frozenset("aeiouy")
# Letters that are rare in real section names; two or more in eight bytes is
# itself unusual.
_RARE_LETTERS = frozenset("jqxzkvw")

_COFF_LONG_NAME = re.compile(r"/\d+")
_DIGIT_BEFORE_LETTER = re.compile(r"\d[A-Za-z]")
_DIGIT_RUN = re.compile(r"[A-Za-z]\d{3}|\d{3}[A-Za-z]")


def _max_consonant_run(core: str) -> int:
    """Longest run of consecutive alphabetic non-vowels in ``core``.

    English-derived section names rarely stack four or more consonants in a
    row; a fully random lowercase string does it often. Safe only because
    every name on the known-toolchain list is excluded before this runs --
    ".rsrc" itself has a run of 4 and would otherwise misfire.
    """
    run = best = 0
    for c in core.lower():
        if c.isalpha() and c not in _VOWELS:
            run += 1
            best = max(best, run)
        elif c.isalpha():
            run = 0
    return best


def is_known_section_name(name: str, known: frozenset[str] | set[str] | None = None) -> bool:
    """True when ``name`` is a recognised toolchain or packer section name.

    Handles the three shapes a legitimate name can take beyond a plain literal:
    MSVC grouped sections (``.CRT$XCA``), COFF long-name references (``/19``),
    and the ``.debug_*`` / ``.zdebug_*`` families.
    """
    if not name:
        return False
    known = STANDARD_SECTION_NAMES if known is None else known
    base = name.split("$", 1)[0].strip()
    lowered = base.lower()
    if lowered in known:
        return True
    if _COFF_LONG_NAME.fullmatch(base):
        return True
    return lowered.startswith(".debug") or lowered.startswith(".zdebug")


def section_name_anomalies(name: str, *, known: frozenset[str] | set[str] | None = None,
                           has_raw_data: bool = False, duplicated: bool = False,
                           printable: bool = True, interior_nul: bool = False) -> list[str]:
    """Score how implausible a section name is, as a list of fired feature ids.

    A human reads "xk3jf9" as random from its *character-class structure*, not
    from entropy -- eight bytes carry far too little signal for an entropy test.
    Real section names are a dot-prefixed lowercase word, or an uppercase word,
    optionally with a TRAILING digit. Each departure from that shape is one
    feature; the caller decides how many constitute an anomaly.

    Returning the individual feature ids rather than a number is deliberate:
    PEguise reports why a check fired, and "no_vowels + rare_letters" is an
    explanation where "score 2.0" is not.

    Structural features (non-printable bytes, empty and duplicate names) are
    evaluated for every section. The lexical features are skipped for names on
    the known list -- ``.msvcjmc`` is vowel-free and rare-letter-heavy, and is
    also a perfectly ordinary MSVC section.
    """
    fired: list[str] = []

    if not printable or interior_nul:
        fired.append("non_printable")
    if not name and has_raw_data:
        fired.append("empty_name")
    if duplicated:
        fired.append("duplicate_name")

    if is_known_section_name(name, known):
        return fired

    core = name.split("$", 1)[0].lstrip(".")
    letters = [c for c in core if c.isalpha()]

    if len(letters) >= 3 and not any(c.lower() in _VOWELS for c in letters):
        fired.append("no_vowels")
    if _DIGIT_BEFORE_LETTER.search(core):
        fired.append("digit_before_letter")
    if sum(1 for a, b in zip(letters, letters[1:], strict=False) if a.islower() != b.islower()) >= 2:
        fired.append("case_alternation")
    if sum(1 for c in core.lower() if c in _RARE_LETTERS) >= 2:
        fired.append("rare_letters")
    if _DIGIT_RUN.search(core):
        fired.append("digit_run")
    if _max_consonant_run(core) >= 4:
        fired.append("consonant_run")
    fired.append("unknown_name")

    return fired


ANOMALY_FEATURE_DESCRIPTIONS: dict[str, str] = {
    "non_printable": "contains non-printable bytes or an interior NUL",
    "empty_name": "name is empty although the section carries raw data",
    "duplicate_name": "another section in this file has the same name",
    "no_vowels": "no vowel among its letters",
    "digit_before_letter": "a digit precedes a letter (real names suffix digits)",
    "case_alternation": "irregular alternation between upper and lower case",
    "rare_letters": "two or more of j/q/x/z/k/v/w in eight bytes",
    "digit_run": "a run of three or more digits beside letters",
    "consonant_run": "four or more consecutive consonants",
    "unknown_name": "matches no known toolchain or packer section name",
}
