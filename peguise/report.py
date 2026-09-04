"""Human-readable and JSON rendering of analysis results."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from typing import Any, TextIO

from .pe_metadata import VERSION_FIELDS
from .scoring import DISCLAIMER, AnalysisResult

_STATUS_GLYPH = {
    "fired": "[!]",
    "clear": "[ok]",
    "not_applicable": "[--]",
    "unavailable": "[??]",
    "suppressed": "[--]",
}

_BAND_ORDER = ("low", "moderate", "elevated", "high")


def _use_colour(stream: TextIO) -> bool:
    return bool(getattr(stream, "isatty", lambda: False)())


def _colour(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _band_colour(band: str) -> str:
    return {"low": "32", "moderate": "33", "elevated": "35", "high": "31"}.get(band, "0")


def _sanitize(text: object) -> str:
    """Escape characters a terminal could interpret as control input.

    VERSIONINFO strings, certificate names, resource ids and file paths are all
    attacker-controlled, and the text report is read in a terminal. An embedded
    ESC sequence can clear lines or repaint the SCORE line; a bidi override can
    reorder what the analyst sees. Anything that is not printable -- C0 and C1
    controls, format characters such as the bidi overrides, line and paragraph
    separators -- is rendered as its ``\\x`` / ``\\u`` escape, exactly as
    ``repr()`` would show it, so the analyst still sees that it was there.

    The JSON output is deliberately left alone: ``json.dumps`` escapes control
    characters itself, and tooling wants the raw value.
    """
    if text is None:
        return ""
    value = str(text)
    if value.isprintable():
        return value
    out: list[str] = []
    for ch in value:
        if ch.isprintable():
            out.append(ch)
            continue
        code = ord(ch)
        if code < 0x100:
            out.append(f"\\x{code:02x}")
        elif code < 0x10000:
            out.append(f"\\u{code:04x}")
        else:
            out.append(f"\\U{code:08x}")
    return "".join(out)


def render_text(result: AnalysisResult, stream: TextIO = sys.stdout, *,
                verbose: bool = False) -> None:
    """Print one file's result as an analyst-readable evidence breakdown."""
    colour = _use_colour(stream)
    meta = result.metadata
    write = stream.write

    write("\n" + "=" * 78 + "\n")
    write(f"{_sanitize(meta.path)}\n")
    write("=" * 78 + "\n")
    write(f"  sha256 : {meta.sha256 or '(unreadable)'}\n")
    write(f"  size   : {meta.size} bytes")
    if meta.machine:
        write(f"   machine: {meta.machine}{'  (DLL)' if meta.is_dll else ''}")
    write("\n")

    band_text = _colour(result.band.upper(), _band_colour(result.band), colour)
    write(f"  SCORE  : {result.score:g} / {result.score_cap:g}  ->  {band_text}\n")

    if meta.status != "ok":
        write(f"\n  !! PE metadata {meta.status}: {_sanitize(meta.status_reason)}\n")

    # -- claimed identity ----------------------------------------------------
    write("\n  VERSIONINFO\n")
    if not meta.has_version_resource and not meta.any_version_strings:
        write("    (no version resource)\n")
    else:
        for name in VERSION_FIELDS:
            value = meta.field(name)
            if value or verbose:
                write(f"    {name:<18} {_sanitize(value) if value else '-'}\n")
        if verbose and meta.extra_version_fields:
            for name, value in sorted(meta.extra_version_fields.items()):
                write(f"    {_sanitize(name):<18} {_sanitize(value)}   (non-standard)\n")

    if result.claim:
        claim = result.claim
        write(
            f"\n  VENDOR CLAIM  {claim.vendor.display_name}"
            f"  (from {claim.field_name}={claim.claimed_value!r};"
            f" matched {claim.matched_alias!r} by {claim.method},"
            f" confidence {claim.confidence:.2f})\n"
        )
    else:
        write("\n  VENDOR CLAIM  none detected - impersonation checks not applicable\n")

    # -- signature -----------------------------------------------------------
    signature = result.signature
    write("\n  SIGNATURE\n")
    if signature.status != "ok":
        write(f"    status            {signature.status}: "
              f"{_sanitize(signature.status_reason)}\n")
    elif not signature.signed:
        write("    status            no embedded Authenticode signature\n")
    else:
        write(f"    signatures        {signature.signature_count}\n")
        write(f"    signer CN         {_sanitize(signature.signer_common_name) or '-'}\n")
        if signature.signer_organization:
            write(f"    signer O          {_sanitize(signature.signer_organization)}\n")
        if verbose and signature.signer_subject_dn:
            write(f"    subject DN        {_sanitize(signature.signer_subject_dn)}\n")
            write(f"    issuer DN         {_sanitize(signature.signer_issuer_dn) or '-'}\n")
        write(f"    digest ({signature.digest_algorithm or '?'})    "
              f"{signature.digest_status}: {_sanitize(signature.digest_status_reason)}\n")
        if verbose:
            write(f"    embedded          {signature.embedded_digest or '-'}\n")
            write(f"    recomputed        {signature.computed_digest or '-'}\n")
    for warning in signature.warnings:
        write(f"    ! {_sanitize(warning)}\n")
    write("    NOT VERIFIED      " + "; ".join(signature.not_verified) + "\n")

    # -- sections ------------------------------------------------------------
    if verbose and meta.sections:
        write("\n  SECTIONS\n")
        write(f"    {'NAME':<12}{'VSIZE':>10}{'RAWSIZE':>10}  FLAGS\n")
        for section in meta.sections:
            name = section.name if section.name_is_printable and section.name else \
                f"<{section.raw_name_hex}>"
            write(f"    {_sanitize(name):<12}{section.virtual_size:>10}{section.raw_size:>10}"
                  f"  0x{section.characteristics:08x}\n")

    # -- icons ---------------------------------------------------------------
    icons = result.icons
    if verbose or icons.matches or icons.status in ("error", "unavailable"):
        write("\n  ICONS\n")
        write(f"    status            {icons.status}"
              f"{': ' + _sanitize(icons.status_reason) if icons.status_reason else ''}\n")
        if icons.icons:
            write(f"    RT_ICON count     {len(icons.icons)}"
                  f"   RT_GROUP_ICON: {len(icons.groups)}\n")
        for match in icons.matches:
            write(f"    ! default icon    {match.icon_name} ({match.icon_id}) "
                  f"sha256={match.sha256[:16]}...\n")
        if verbose:
            for icon in icons.icons:
                write(f"      id={_sanitize(icon.resource_id)} lang={icon.language} "
                      f"{icon.size}B sha256={icon.sha256}\n")

    # -- evidence ------------------------------------------------------------
    write("\n  EVIDENCE\n")
    fired = result.fired
    if not fired:
        write("    no checks fired\n")
    for finding in fired:
        glyph = _colour(_STATUS_GLYPH["fired"], "31", colour)
        write(f"    {glyph} +{finding.weight:g}  {finding.title}  [{finding.check}]\n")
        for line in _wrap(_sanitize(finding.detail), 68):
            write(f"          {line}\n")
        if finding.observed:
            write(f"          observed: {_sanitize(_compact(finding.observed))}\n")
        if finding.expected:
            write(f"          expected: {_sanitize(_compact(finding.expected))}\n")

    other = [f for f in result.findings if not f.fired]
    if verbose:
        write("\n  CHECKS THAT DID NOT FIRE\n")
        for finding in other:
            glyph = _STATUS_GLYPH.get(finding.status, "[--]")
            write(f"    {glyph} {finding.check}: {_sanitize(finding.detail)}\n")
    else:
        unavailable = [f for f in other if f.status == "unavailable"]
        if unavailable:
            write("\n  CHECKS UNAVAILABLE\n")
            for finding in unavailable:
                write(f"    [??] {finding.check}: {_sanitize(finding.detail)}\n")

    for warning in meta.warnings:
        write(f"\n  ! {_sanitize(warning)}\n")


def _compact(mapping: dict[str, Any], limit: int = 240) -> str:
    text = json.dumps(mapping, default=str, ensure_ascii=False)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def render_summary(results: list[AnalysisResult], stream: TextIO = sys.stdout) -> None:
    """One-line-per-file table, printed after a multi-file scan."""
    if len(results) < 2:
        return
    colour = _use_colour(stream)
    stream.write("\n" + "=" * 78 + "\n")
    stream.write(f"SUMMARY  ({len(results)} files)\n")
    stream.write("=" * 78 + "\n")
    stream.write(f"{'SCORE':>6}  {'BAND':<9} {'CLAIM':<14} FILE\n")
    for result in sorted(results, key=lambda r: -r.score):
        band = _colour(f"{result.band:<9}", _band_colour(result.band), colour)
        claim = result.claim.vendor.display_name if result.claim else "-"
        stream.write(f"{result.score:>6g}  {band} {claim[:14]:<14} "
                     f"{_sanitize(result.metadata.path)}\n")


def render_json(results: Iterable[AnalysisResult], stream: TextIO = sys.stdout) -> None:
    """Machine-readable output: one object with a results array."""
    payload = {
        "tool": "peguise",
        "analysis_type": "static-offline",
        "disclaimer": DISCLAIMER,
        "results": [result.to_dict() for result in results],
    }
    json.dump(payload, stream, indent=2, default=str, ensure_ascii=False)
    stream.write("\n")
