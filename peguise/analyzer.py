"""Pipeline orchestration: file/directory discovery and per-file analysis."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from . import authenticode, icon_fingerprint, pe_metadata
from .scoring import AnalysisResult, score_file
from .vendor_db import ReferenceData


def analyze_file(path: str | os.PathLike[str], data: ReferenceData) -> AnalysisResult:
    """Run every check against one file. Never raises on a bad sample."""
    file_path = Path(path)

    meta = pe_metadata.extract(file_path)

    # Both remaining checks need a parsable PE; skip them cleanly if it is not.
    if meta.is_pe:
        signature = authenticode.inspect(file_path)
        icons = icon_fingerprint.fingerprint(file_path, data.icon_hash_index)
    else:
        reason = meta.status_reason or "file is not a parsable PE"
        signature = authenticode.SignatureInfo(status="unavailable", status_reason=reason)
        icons = icon_fingerprint.IconReport(status="unavailable", status_reason=reason)

    return score_file(meta, signature, icons, data)


def iter_targets(root: str | os.PathLike[str], *, recursive: bool = False,
                 pe_only: bool = True) -> Iterator[Path]:
    """Yield the files to analyse under ``root``.

    A file argument is always yielded, even if it does not sniff as a PE, so the
    analyst gets an explicit "not a PE" result rather than silence. Directory
    walks filter on the MZ/PE signature so scans do not depend on extensions.
    """
    root_path = Path(root)

    if root_path.is_file():
        yield root_path
        return

    if not root_path.is_dir():
        return

    if recursive:
        walker: Iterator[Path] = (
            Path(dirpath) / name
            for dirpath, _dirnames, filenames in os.walk(root_path)
            for name in filenames
        )
    else:
        walker = (p for p in sorted(root_path.iterdir()) if p.is_file())

    for candidate in walker:
        try:
            if candidate.is_symlink() and not candidate.exists():
                continue
            if not candidate.is_file():
                continue
        except OSError:
            continue
        if pe_only and not pe_metadata.looks_like_pe(candidate):
            continue
        yield candidate


def analyze_path(root: str | os.PathLike[str], data: ReferenceData, *,
                 recursive: bool = False, pe_only: bool = True) -> list[AnalysisResult]:
    """Analyse a file or a directory of files."""
    return [analyze_file(target, data) for target in iter_targets(
        root, recursive=recursive, pe_only=pe_only)]
