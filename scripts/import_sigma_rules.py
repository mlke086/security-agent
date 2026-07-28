#!/usr/bin/env python3
"""One-shot Sigma rule importer (Phase 6 of monitoring plan).

Walks a directory of Sigma YAML files, parses each, and writes a
manifest + copies the .yml files into ``src/detection/rules/imported/``
so the live ``Detector`` picks them up on the next reload (or after
a process restart in dev; the ``re-init`` endpoint can hot-reload
in production).

Usage:
  python scripts/import_sigma_rules.py <path> [--copy] [--out <dir>]

Examples:
  # Import from a hand-cloned SigmaHQ checkout (rules-emerging-threats subtree)
  python scripts/import_sigma_rules.py /path/to/sigmaHQ/rules/linux/auditd

  # Import a single rule (smoke test)
  python scripts/import_sigma_rules.py /path/to/sigmaHQ/rules/linux/proc_creation.yml

  # Import without copying (dry run; useful to see counts first)
  python scripts/import_sigma_rules.py /path/to/sigmaHQ/rules/windows/process_creation --no-copy
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

# Repo root is the parent of this script; make src importable regardless of cwd.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from src.detection.rule_importer import (  # noqa: E402
    ImportResult,
    import_from_directory,
    write_manifest,
)


def _print_summary(result: ImportResult, *, copy: bool, copied: int) -> None:
    """Human-friendly report so the operator can see at a glance what happened."""
    print()
    print("=== Sigma import summary ===")
    print(f"  source:        {result.source_dir}")
    print(f"  total seen:    {result.total_seen}")
    print(f"  accepted:      {len(result.accepted)}")
    print(f"  skipped:       {len(result.skipped)}")
    if copy:
        print(f"  copied:        {copied}")
    print()
    print("  by category:")
    for k, v in sorted(result.by_category().items(), key=lambda kv: -kv[1]):
        print(f"    {k:30s}  {v}")
    print()
    print("  by OS:")
    for k, v in sorted(result.by_os().items(), key=lambda kv: -kv[1]):
        print(f"    {k:30s}  {v}")
    print()
    print("  by level:")
    for k, v in sorted(result.by_level().items(), key=lambda kv: -kv[1]):
        print(f"    {k:30s}  {v}")
    if result.skipped:
        print()
        print(f"  skipped reasons (showing first 10 of {len(result.skipped)}):")
        for s in result.skipped[:10]:
            print(f"    {s.path}: {s.reason}")


def _copy_imported(result: ImportResult, dest_dir: Path) -> int:
    """Copy each accepted .yml into ``dest_dir`` so the Detector picks them up.

    Returns the number of files actually copied. A second import over
    the same path is idempotent -- shutil.copy2 overwrites the dest.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for r in result.accepted:
        src = Path(r.path)
        if not src.is_file():
            continue
        dst = dest_dir / src.name
        shutil.copy2(src, dst)
        n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Import Sigma YAML rules into the detection engine.",
    )
    p.add_argument("path", help="Directory or single .yml file to import")
    p.add_argument(
        "--out",
        default=str(_REPO_ROOT / "src" / "detection" / "rules" / "imported"),
        help="Directory to copy accepted .yml files into (default: src/detection/rules/imported/)",
    )
    p.add_argument(
        "--manifest",
        default=str(_REPO_ROOT / "src" / "detection" / "rules" / "imported" / "manifest.json"),
        help="Path to write the import manifest (default next to --out)",
    )
    p.add_argument(
        "--no-copy",
        action="store_true",
        help="Dry run: do not copy .yml files into the rules directory",
    )
    args = p.parse_args(argv)

    src = Path(args.path)
    if not src.exists():
        print(f"error: path does not exist: {src}", file=sys.stderr)
        return 2

    result: ImportResult = import_from_directory(src)
    copied = 0
    if not args.no_copy:
        copied = _copy_imported(result, Path(args.out))
    manifest_path = write_manifest(result, Path(args.manifest))
    _print_summary(result, copy=not args.no_copy, copied=copied)
    print()
    print(f"manifest: {manifest_path}")
    # Skipped rules are NOT a fatal condition: the operator usually
    # points the script at a SigmaHQ subtree and expects a few rules
    # to be unsupported. Only a totally empty result is worth a
    # non-zero exit so cron / CI can notice.
    return 0 if result.total_seen > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
