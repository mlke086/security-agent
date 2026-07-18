"""ingest_neo4j_to_milvus.py — Bulk-import ATT&CK techniques from Neo4j into Milvus with BGE embeddings.

This script batches SentenceTransformer.encode() for ~10x throughput vs per-text encoding.
"""

import hashlib
import sys
import time

from neo4j import GraphDatabase
from pymilvus import Collection, connections

from src.common.config.settings import get_settings
from src.knowledge.graphrag.vector.embedding import embed, _get_model, EMBEDDING_DIM
from src.knowledge.graphrag.vector.milvus_client import MilvusVectorClient


def load_techniques_from_neo4j() -> list[dict]:
    s = get_settings()
    driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))
    docs = []
    try:
        with driver.session() as session:
            result = session.run(
                "MATCH (n:Technique) "
                "WHERE n.name IS NOT NULL "
                "RETURN n.id AS id, n.name AS name, n.description AS description, "
                "       n.url AS url, n.x_mitre_tactic AS tactic"
            )
            for row in result:
                name = row.get("name", "")
                desc = row.get("description", "")
                tactic = row.get("tactic", "")
                mitre_id = row.get("id", "")
                text = f"{name} [{tactic}]: {desc}" if tactic else f"{name}: {desc}"
                docs.append({
                    "doc_id": hashlib.md5(mitre_id.encode()).hexdigest()[:16],
                    "content": text[:8000],
                    "source": "mitre_attack",
                })
    finally:
        driver.close()
    return docs


def main() -> None:
    print("=== Neo4j to Milvus Bulk Ingestion ===\n")

    print("Loading techniques from Neo4j...")
    t0 = time.time()
    docs = load_techniques_from_neo4j()
    print(f"  Loaded {len(docs)} techniques in {time.time()-t0:.1f}s")

    if not docs:
        print("ERROR: No techniques found in Neo4j.")
        sys.exit(1)

    print("Loading BGE model...")
    model = _get_model()
    print(f"  Model loaded, dim={EMBEDDING_DIM}")

    print("Ensuring Milvus collection...")
    client = MilvusVectorClient()

    # Batch encode and insert
    batch_size = 32
    total = 0
    t_start = time.time()

    for i in range(0, len(docs), batch_size):
        batch = docs[i : i + batch_size]
        texts = [d["content"] for d in batch]

        # Batch encoding: ~10x faster than per-text
        vecs = model.encode(texts, normalize_embeddings=True, batch_size=batch_size)

        records = []
        for j, d in enumerate(batch):
            records.append({
                "doc_id": d["doc_id"],
                "content": d["content"],
                "source": d["source"],
                "embedding": vecs[j].tolist(),
            })

        client.insert(records)
        total += len(records)
        elapsed = time.time() - t_start
        rate = total / elapsed if elapsed > 0 else 0
        pct = total * 100 // len(docs)
        print(f"  [{pct:3d}%] batch {i//batch_size}: +{len(records)}  total={total}  {rate:.0f} docs/s")

    # Verify
    connections.connect(host=get_settings().milvus_host, port=get_settings().milvus_port)
    col = Collection(get_settings().milvus_collection)
    col.load()
    count = col.num_entities
    col.release()
    print(f"\nIngestion complete: {count} entities in Milvus")
    print(f"Total time: {time.time()-t_start:.1f}s")


if __name__ == "__main__":
    main()