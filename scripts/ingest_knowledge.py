"""ingest_knowledge.py — Ingest CVE/threat intel data into Milvus with embeddings.

Usage:
    python scripts/ingest_knowledge.py                          # Ingest sample CVE data
    python scripts/ingest_knowledge.py --cve-file cves.json     # Ingest from CVE JSON file
    python scripts/ingest_knowledge.py --text "custom text" --source "report"

This script:
  1. Generates embeddings using BGE-small-en-v1.5 (or fallback mock)
  2. Inserts documents into the Milvus threat_intel collection
  3. Supports batch ingestion from various sources
"""

import json
import math
import sys
import hashlib
import httpx
from typing import Any

from src.common.config.settings import get_settings
from src.common.logging.logger import get_logger
from src.knowledge.graphrag.vector.milvus_client import MilvusVectorClient, VECTOR_DIM
from pymilvus import Collection

logger = get_logger(__name__)

# Sample CVE/Intel data for demonstration if no file provided
_SAMPLE_INTELLIGENCE: list[dict[str, str]] = [
    {"content": "CVE-2024-1234: Remote code execution in Apache Log4j 2.x versions 2.0 to 2.17.1. "
                "Allows unauthenticated attackers to execute arbitrary code via JNDI lookup.",
     "source": "cve", "cve_id": "CVE-2024-1234"},
    {"content": "CVE-2024-5678: SQL injection vulnerability in WordPress plugin XYZ 1.0-2.3. "
                "Authenticated attackers with subscriber access can execute SQL queries.",
     "source": "cve", "cve_id": "CVE-2024-5678"},
    {"content": "APT29 (Cozy Bear) targets government networks using phishing and credential theft. "
                "Techniques include T1566 (Phishing) and T1078 (Valid Accounts).",
     "source": "intel_report", "cve_id": ""},
    {"content": "Ransomware group LockBit uses double extortion model. Initial access via RDP brute-force (T1110). "
                "Deploys LockBit via scheduled tasks (T1053).",
     "source": "intel_report", "cve_id": ""},
    {"content": "CVE-2024-9012: Buffer overflow in OpenSSL 3.0.0-3.0.13. Remote attackers can cause denial of "
                "service or potentially execute code via crafted TLS handshake.",
     "source": "cve", "cve_id": "CVE-2024-9012"},
    {"content": "Mirai botnet scans port 23/TCP (Telnet) for default credentials on IoT devices. "
                "DDoS capability. Mitigation: disable Telnet, use SSH with key auth.",
     "source": "intel_report", "cve_id": ""},
]


def _mock_embedding(text: str) -> list[float]:
    """Generate a deterministic mock embedding for demo purposes.
    
    In production, replace with sentence-transformers or OpenAI embedding API:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("BAAI/bge-small-en-v1.5")
        return model.encode(text).tolist()
    """
    seed = int(hashlib.md5(text.encode()).hexdigest()[:8], 16)
    rng = __import__("random").Random(seed)
    vec = [rng.gauss(0, 0.01) for _ in range(VECTOR_DIM)]
    norm = math.sqrt(sum(x * x for x in vec))
    return [x / norm for x in vec]


def _generate_embedding(text: str) -> list[float]:
    """Use the project's BGE-large-zh-v1.5 embedding module, fall back to mock."""
    try:
        from src.knowledge.graphrag.vector.embedding import embed
        return embed(text)
    except Exception as exc:
        logger.warning("embedding_module_error", error=str(exc))
        return _mock_embedding(text)


def ingest_documents(docs: list[dict[str, Any]]) -> int:
    """Ingest documents into Milvus.
    
    Args:
        docs: List of dicts with keys 'doc_id', 'content', 'source'
    """
    client = MilvusVectorClient()
    
    # Generate embeddings and format for Milvus
    records = []
    for doc in docs:
        embedding = _generate_embedding(doc.get("content", ""))
        records.append({
            "doc_id": doc.get("doc_id", hashlib.md5(doc.get("content", "").encode()).hexdigest()[:16]),
            "content": doc.get("content", ""),
            "source": doc.get("source", "unknown"),
            "embedding": embedding,
        })

    # Insert in batches
    batch_size = 64
    total = 0
    for i in range(0, len(records), batch_size):
        batch = records[i : i + batch_size]
        client.insert(batch)
        total += len(batch)
        logger.info("batch_inserted", batch=i // batch_size, count=len(batch))

    logger.info("ingestion_complete", total=total)
    return total


def _load_cve_json(path: str) -> list[dict]:
    """Load and parse CVE JSON file.
    
    Supports NVD CVE JSON 2.0 format:
        {"vulnerabilities": [{"cve": {"id": "...", "descriptions": [...], ...}}]}
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = []
    vulns = data.get("vulnerabilities", [])
    for vuln in vulns:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        content = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )
        if content:
            docs.append({
                "doc_id": cve_id,
                "content": content,
                "source": "cve",
            })
    return docs


def main() -> None:
    args = sys.argv[1:]

    if "--cve-file" in args:
        idx = args.index("--cve-file")
        path = args[idx + 1] if idx + 1 < len(args) else None
        if not path:
            print("Error: --cve-file requires a file path")
            sys.exit(1)
        docs = _load_cve_json(path)
        print(f"Loaded {len(docs)} CVEs from {path}")

    elif "--text" in args:
        idx = args.index("--text")
        text = args[idx + 1] if idx + 1 < len(args) else ""
        source = args[args.index("--source") + 1] if "--source" in args else "manual"
        if not text:
            print("Error: --text requires text content")
            sys.exit(1)
        docs = [{
            "doc_id": hashlib.md5(text.encode()).hexdigest()[:16],
            "content": text,
            "source": source,
        }]

    else:
        # Use sample data
        docs = []
        for i, item in enumerate(_SAMPLE_INTELLIGENCE):
            doc_id = item.get("cve_id") or hashlib.md5(item["content"].encode()).hexdigest()[:16]
            docs.append({
                "doc_id": doc_id,
                "content": item["content"],
                "source": item["source"],
            })
        print(f"Using {len(docs)} sample intelligence documents")

    total = ingest_documents(docs)
    print(f"Ingestion complete: {total} documents inserted into Milvus")


if __name__ == "__main__":
    main()
