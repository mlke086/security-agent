"""Dump the FastAPI OpenAPI schema to frontend/openapi.json.

Used by the frontend type-generation pipeline:
    python scripts/gen_openapi.py   # -> frontend/openapi.json
    npm --prefix frontend run gen:types  # -> frontend/src/api/schema.ts
"""

import json
import os
import sys
from pathlib import Path

# Settings validation requires an API secret >= 16 chars at import time.
os.environ.setdefault("API_SECRET_KEY", "gen-types-secret-000000")
os.environ.setdefault("STORE_BACKEND", "memory")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import app  # noqa: E402

out = Path(__file__).resolve().parent.parent / "frontend" / "openapi.json"
schema = TestClient(app).get("/openapi.json").json()
out.write_text(json.dumps(schema, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"wrote {out} ({len(schema.get('paths', {}))} paths, "
      f"{len(schema.get('components', {}).get('schemas', {}))} schemas)")
