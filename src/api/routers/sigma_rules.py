"""Sigma detection rule router (Phase 6 of monitoring plan).

Endpoints:
  GET /api/v1/sigma-rules/summary
      Returns the import manifest summary (counts by category / OS /
      level, skipped reasons, etc.). This is what the console's
      "detection rules" tab calls on mount.
  GET /api/v1/sigma-rules
      Returns the per-rule inventory (rule_id, title, level, OS,
      category, MITRE techniques, detector_supported). Filterable
      by category, level, os, and detector_supported.
  POST /api/v1/sigma-rules/import
      Dry-run an import without writing files: takes a path in the
      request body, returns the ImportResult, leaves the filesystem
      untouched. Useful for the console "test before commit" UX.
      (The actual import-and-copy is a CLI / cron job; we don't
      expose the write side over HTTP so a compromised operator
      token cannot plant a rule in the live detector without going
      through the audit log on the box.)

RBAC: admin/analyst/viewer can read; only admin can run the import
(dry-run is harmless but the audit trail is cleaner with admin only).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.api.auth.routes import require_role
from src.detection.rule_importer import (
    ImportResult,
    import_from_directory,
    read_manifest,
)

router = APIRouter(prefix="/api/v1/sigma-rules", tags=["sigma-rules"])


# Default location of the import manifest written by the CLI script.
# Kept in sync with scripts/import_sigma_rules.py; the operator can
# override by setting the env var SIGMA_RULES_MANIFEST.
MANIFEST_PATH = Path(
    os.environ.get(
        "SIGMA_RULES_MANIFEST",
        str(
            Path(__file__).resolve().parent.parent.parent
            / "detection"
            / "rules"
            / "imported"
            / "manifest.json"
        ),
    )
)


def _load_manifest() -> dict[str, Any] | None:
    """Read the manifest from disk, or return None if it does not exist yet."""
    return read_manifest(MANIFEST_PATH)


@router.get("/summary")
async def sigma_summary(
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> dict[str, Any]:
    """Import summary suitable for the console dashboard tab.

    Returns counts and the skipped-reason list. If no import has run
    yet, returns an empty placeholder so the UI can show a "no rules
    imported" state without a 404.
    """
    m = _load_manifest()
    if not m:
        return {
            "total_seen": 0,
            "accepted": 0,
            "skipped": 0,
            "by_category": {},
            "by_os": {},
            "by_level": {},
            "skipped_reasons": [],
            "imported_at": "",
        }
    return m


@router.get("")
async def list_sigma_rules(
    category: str | None = Query(default=None, description="process_creation / file_event / ..."),
    level: str | None = Query(
        default=None, description="critical / high / medium / low / informational"
    ),
    os: str | None = Query(default=None, description="linux / macos / windows"),
    detector_supported: bool | None = Query(default=None),
    q: str | None = Query(default=None, description="substring match on rule_id or title"),
    current_user=Depends(require_role("admin", "analyst", "viewer")),
) -> dict[str, Any]:
    """Filtered list of imported Sigma rules.

    Served straight from the manifest -- no DB, no walk of the rules
    directory on every request. If the manifest is missing we 404 so
    the operator notices the import never ran.
    """
    m = _load_manifest()
    if not m:
        raise HTTPException(
            status_code=404,
            detail="no sigma manifest yet -- run scripts/import_sigma_rules.py",
        )
    items: list[dict[str, Any]] = list(m.get("rules", []))
    if category:
        items = [r for r in items if r.get("category") == category]
    if level:
        items = [r for r in items if r.get("level") == level]
    if os:
        items = [r for r in items if os in (r.get("applicable_os") or [])]
    if detector_supported is not None:
        items = [r for r in items if bool(r.get("detector_supported")) == detector_supported]
    if q:
        ql = q.lower()
        items = [
            r
            for r in items
            if ql in (r.get("rule_id") or "").lower() or ql in (r.get("title") or "").lower()
        ]
    return {
        "total": len(items),
        "items": items,
    }


@router.post("/import")
async def import_sigma_dry_run(
    body: dict,
    current_user=Depends(require_role("admin")),
) -> dict[str, Any]:
    """Run the importer against ``body.path`` and return the result.

    Does NOT write the manifest or copy any .yml files. The operator
    is expected to use the CLI for the actual filesystem change so
    the change is auditable on the host rather than over HTTP.
    """
    src = (body or {}).get("path")
    if not src or not isinstance(src, str):
        raise HTTPException(status_code=400, detail="body.path (string) is required")
    p = Path(src)
    if not p.exists():
        raise HTTPException(status_code=400, detail=f"path does not exist: {src}")
    result: ImportResult = import_from_directory(p)
    return result.to_manifest()
