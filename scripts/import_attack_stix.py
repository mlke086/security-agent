"""import_attack_stix.py — Import MITRE ATT&CK STIX data into Neo4j.

Usage:
    python scripts/import_attack_stix.py              # Download latest from MITRE
    python scripts/import_attack_stix.py --local stix.json  # Use local file

The script:
1. Downloads the latest MITRE ATT&CK Enterprise STIX bundle
2. Parses techniques, mitigations, groups, and software
3. Creates Neo4j nodes and relationships (technique → mitigation, group → technique)
"""

import json
import sys
import httpx
from pathlib import Path
from neo4j import AsyncGraphDatabase
from src.common.config.settings import get_settings

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


async def main(local_path: str | None = None) -> None:
    # 1. Load STIX bundle
    if local_path:
        print(f"Loading local file: {local_path}")
        bundle = json.loads(Path(local_path).read_text(encoding="utf-8"))
    else:
        print(f"Downloading MITRE ATT&CK from: {ATTACK_STIX_URL}")
        async with httpx.AsyncClient(follow_redirects=True, timeout=120) as client:
            resp = await client.get(ATTACK_STIX_URL)
            resp.raise_for_status()
            bundle = resp.json()
        print(f"Downloaded: {len(bundle.get('objects', []))} objects")

    # 2. Parse STIX objects
    objects = bundle.get("objects", [])
    techniques: list[dict] = []
    mitigations: list[dict] = []
    groups: list[dict] = []
    software: list[dict] = []

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type == "attack-pattern":
            techniques.append(obj)
        elif obj_type == "course-of-action":
            mitigations.append(obj)
        elif obj_type == "intrusion-set":
            groups.append(obj)
        elif obj_type in ("malware", "tool"):
            software.append(obj)

    print(f"Parsed: {len(techniques)} techniques, {len(mitigations)} mitigations, "
          f"{len(groups)} groups, {len(software)} software items")

    # 3. Connect to Neo4j
    settings = get_settings()
    driver = AsyncGraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password),
    )

    try:
        async with driver.session() as session:
            # Create constraints
            for label in ["Technique", "Mitigation", "Group", "Software"]:
                await session.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE")

            # Insert techniques
            for t in techniques:
                await session.run(
                    """
                    MERGE (n:Technique {id: $id})
                    SET n.name = $name,
                        n.description = $description,
                        n.x_mitre_platforms = $platforms,
                        n.x_mitre_tactic = $tactic,
                        n.url = $url
                    """,
                    id=t.get("id", ""),
                    name=t.get("name", ""),
                    description=t.get("description", "")[:1000] if t.get("description") else "",
                    platforms=str(t.get("x_mitre_platforms", [])),
                    tactic=str(t.get("kill_chain_phases", [{}])[0].get("phase_name", "")) if t.get("kill_chain_phases") else "",
                    url=f"https://attack.mitre.org/techniques/{t.get('external_references', [{}])[0].get('external_id', '')}/" if t.get("external_references") else "",
                )

            # Insert mitigations
            for m in mitigations:
                await session.run(
                    """
                    MERGE (n:Mitigation {id: $id})
                    SET n.name = $name, n.description = $description
                    """,
                    id=m.get("id", ""),
                    name=m.get("name", ""),
                    description=m.get("description", "")[:1000] if m.get("description") else "",
                )

            # Insert groups
            for g in groups:
                await session.run(
                    """
                    MERGE (n:Group {id: $id})
                    SET n.name = $name, n.description = $description
                    """,
                    id=g.get("id", ""),
                    name=g.get("name", ""),
                    description=g.get("description", "")[:1000] if g.get("description") else "",
                )

            # Insert software
            for s in software:
                await session.run(
                    """
                    MERGE (n:Software {id: $id})
                    SET n.name = $name, n.type = $s_type, n.description = $description
                    """,
                    id=s.get("id", ""),
                    name=s.get("name", ""),
                    s_type=s.get("type", ""),
                    description=s.get("description", "")[:1000] if s.get("description") else "",
                )

            # Create relationships from STIX relationship objects
            for obj in objects:
                if obj.get("type") != "relationship":
                    continue
                source_ref = obj.get("source_ref", "")
                target_ref = obj.get("target_ref", "")
                rel_type = obj.get("relationship_type", "").upper().replace("-", "_")

                await session.run(
                    f"""
                    MATCH (a {{id: $source_ref}})
                    MATCH (b {{id: $target_ref}})
                    MERGE (a)-[r:{rel_type}]->(b)
                    SET r.description = $description
                    """,
                    source_ref=source_ref,
                    target_ref=target_ref,
                    rel_type=rel_type,
                    description=obj.get("description", "")[:500] if obj.get("description") else "",
                )

            # Count results
            result = await session.run("MATCH (n) RETURN count(n) AS total")
            count = await result.single()
            print(f"Neo4j import complete. Total nodes: {count['total']}")

    finally:
        await driver.close()


if __name__ == "__main__":
    import asyncio
    local = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "--local" else None
    if "--local" in sys.argv:
        idx = sys.argv.index("--local")
        local = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
    asyncio.run(main(local_path=local))
    print("Done.")
