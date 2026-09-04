#!/usr/bin/env python3
"""Survey PE section names across a directory, and show what PEguise would flag.

The packer section-name weights in data/weights.yaml were calibrated against a
malware corpus, which is the positive class only. Nothing in this repository
establishes how often *legitimate* software from a tracked vendor ships packed
-- and that is precisely the number that decides whether the weights are right.

Run this against a CLEAN corpus (a Windows installation, a vendor download
mirror, your golden-image share) before trusting or retuning them:

    python tools/section_survey.py /mnt/clean-corpus

Any file it reports there is a false positive you can act on -- add the vendor
id to that packer entry's `benign_for_vendors` in data/packer_identities.yaml,
or lower the category weight.

Read-only: files are parsed, never executed.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from peguise import pe_metadata, scoring, util, vendor_db  # noqa: E402
from peguise.analyzer import analyze_file  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="section_survey.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("directory", help="directory of PE files to survey")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit the full result as JSON")
    parser.add_argument("--max-size", type=int, default=60_000_000, metavar="BYTES",
                        help="skip files larger than this (default 60MB)")
    parser.add_argument("--time-budget", type=float, default=900.0, metavar="SECONDS",
                        help="stop walking after this long (default 900)")
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--config", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.directory).expanduser()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2

    data = vendor_db.load(args.data_dir, args.config)
    packer_index = {
        name.lower(): tool
        for tool in data.generic_tools
        for name in tool.section_names
    }

    names: collections.Counter[str] = collections.Counter()
    parsed = claimed = packed = 0
    hits: list[dict] = []
    anomalies: list[dict] = []
    start = time.time()

    for path in root.rglob("*"):
        if time.time() - start > args.time_budget:
            print(f"note: time budget reached after {parsed} files", file=sys.stderr)
            break
        try:
            if not path.is_file() or path.stat().st_size > args.max_size:
                continue
        except OSError:
            continue
        if not pe_metadata.looks_like_pe(path):
            continue

        meta = pe_metadata.extract(path)
        if meta.status != "ok" or not meta.sections:
            continue
        parsed += 1
        names.update(meta.section_names)

        matched = {n: packer_index[n.strip().lower()].id
                   for n in meta.section_names
                   if n.strip().lower() in packer_index}
        if matched:
            packed += 1

        claim = scoring.detect_vendor_claim(meta, data)
        if claim:
            claimed += 1
        if not claim:
            continue

        if matched:
            result = analyze_file(path, data)
            hits.append({
                "path": str(path), "vendor": claim.vendor.id,
                "sections": meta.section_names, "matched": matched,
                "score": result.score, "band": result.band,
                "fired": sorted(f.check for f in result.fired),
            })

        odd = {
            s.name or "<empty>": util.section_name_anomalies(
                s.name, known=data.known_section_names,
                has_raw_data=s.raw_size > 0,
                duplicated=sum(1 for o in meta.sections if o.name == s.name) > 1,
                printable=s.name_is_printable, interior_nul=s.has_interior_nul)
            for s in meta.sections
        }
        odd = {k: v for k, v in odd.items()
               if len(v) >= int(data.matching("section_anomaly_min_features", 2))}
        if odd:
            anomalies.append({"path": str(path), "vendor": claim.vendor.id,
                              "flagged": odd})

    payload = {
        "root": str(root), "parsed": parsed, "distinct_section_names": len(names),
        "with_vendor_claim": claimed, "with_packer_sections": packed,
        "packer_check_would_fire": hits,
        "anomaly_check_would_fire": anomalies,
        "section_name_counts": names.most_common(),
    }

    if args.as_json:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    print(f"parsed {parsed} PE files; {len(names)} distinct section names")
    print(f"  with a tracked-vendor claim : {claimed}")
    print(f"  with packer section names   : {packed}")
    print(f"  packer check would fire on  : {len(hits)}")
    print(f"  anomaly check would fire on : {len(anomalies)}\n")
    for hit in sorted(hits, key=lambda h: -h["score"]):
        print(f"  {hit['score']:>5g} {hit['band']:<9} {hit['vendor']:<12} "
              f"{', '.join(sorted(set(hit['matched'].values())))}")
        print(f"        {hit['path']}")
    if anomalies:
        print("\n  anomalous section names:")
        for entry in anomalies:
            print(f"    {entry['vendor']:<12} {entry['flagged']}")
            print(f"        {entry['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
