#!/usr/bin/env python3
"""PEguise - static, offline detection of vendor impersonation via VERSIONINFO.

Flags Windows PE files whose VERSIONINFO resource claims to be a well-known
product while other static evidence contradicts that claim.

This tool is READ-ONLY and OFFLINE. It never executes, unpacks, emulates or
modifies an analysed file, and it makes no network requests. It produces a
weighted suspicion score with an itemised evidence breakdown -- never a
malicious/clean verdict.

Usage:
    analyze.py sample.exe
    analyze.py ./samples --recursive --json
    analyze.py ./samples -r --min-score 40
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from peguise import __version__, report, vendor_db
from peguise.analyzer import analyze_path

# Exit codes, so the tool can be driven from a triage pipeline.
EXIT_OK = 0
EXIT_FINDINGS = 1        # at least one file met --fail-band
EXIT_USAGE = 2
EXIT_DATA_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "PEguise never validates certificate chains, revocation status, "
            "timestamps or certificate validity periods, and makes no network "
            "calls. See README.md for the full list of limitations."
        ),
    )
    parser.add_argument("target", help="PE file, or directory of PE files, to analyse")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit machine-readable JSON instead of a text report")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="walk subdirectories when the target is a directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show every check, including those that did not fire")
    parser.add_argument("--min-score", type=float, default=None, metavar="N",
                        help="only report files scoring at least N")
    parser.add_argument("--fail-band", default=None,
                        choices=["low", "moderate", "elevated", "high"],
                        help="exit with status 1 if any file reaches this band")
    parser.add_argument("--data-dir", default=None, metavar="DIR",
                        help="directory holding the reference data files "
                             "(default: ./data)")
    parser.add_argument("--config", default=None, metavar="FILE",
                        help="scoring configuration file (default: <data-dir>/weights.yaml)")
    parser.add_argument("--all-files", action="store_true",
                        help="in a directory scan, analyse every file rather than "
                             "only those with an MZ/PE signature")
    parser.add_argument("--version", action="version", version=f"PEguise {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    # Deliberate runtime guard: pyproject declares >=3.11, but nothing stops an
    # older interpreter from running this script directly.
    if sys.version_info < (3, 11):  # noqa: UP036  # pragma: no cover
        print("error: PEguise requires Python 3.11 or newer", file=sys.stderr)
        return EXIT_USAGE

    args = build_parser().parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        print(f"error: no such file or directory: {target}", file=sys.stderr)
        return EXIT_USAGE

    try:
        data = vendor_db.load(args.data_dir, args.config)
    except vendor_db.ReferenceDataError as exc:
        print(f"error: reference data: {exc}", file=sys.stderr)
        return EXIT_DATA_ERROR

    results = analyze_path(target, data,
                           recursive=args.recursive,
                           pe_only=not args.all_files)

    if not results:
        print(f"no PE files found under {target}"
              " (use --recursive to descend, --all-files to ignore the MZ check)",
              file=sys.stderr)
        if args.as_json:
            # A pipeline consumer must always receive a parsable document.
            report.render_json([], sys.stdout)
        return EXIT_OK

    shown = results
    if args.min_score is not None:
        shown = [r for r in results if r.score >= args.min_score]

    if args.as_json:
        report.render_json(shown, sys.stdout)
    else:
        for result in sorted(shown, key=lambda r: -r.score):
            report.render_text(result, sys.stdout, verbose=args.verbose)
        report.render_summary(shown, sys.stdout)
        if args.min_score is not None and len(shown) != len(results):
            print(f"\n({len(results) - len(shown)} file(s) below --min-score "
                  f"{args.min_score:g} not shown)")

    if args.fail_band:
        order = ["low", "moderate", "elevated", "high"]
        threshold = order.index(args.fail_band)
        if any(r.band in order and order.index(r.band) >= threshold for r in results):
            return EXIT_FINDINGS

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
