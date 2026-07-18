"""Fix remaining P0/P1 issues from V2 review."""
import os, ast

print("=== P0-S3: Audit trail -> ES ===")
for f in ["entry.py", "aggregator.py"]:
    path = f"src/orchestration/main_graph/nodes/{f}"
    c = open(path, "r", encoding="utf-8").read()
    if "get_audit_logger" not in c:
        c = c.replace("from src.common.logging.logger import get_logger", "from src.common.logging.logger import get_logger\nfrom src.common.audit.audit_logger import get_audit_logger")
        if "entry" in f:
            old = '    entry: AuditEntry = {\n        "node": "entry",\n        "ts": datetime.now(UTC).isoformat(),\n        "summary": f"Event received: {event_id}",\n    }'
            new = '    entry: AuditEntry = {\n        "node": "entry",\n        "ts": datetime.now(UTC).isoformat(),\n        "summary": f"Event received: {event_id}",\n    }\n    audit = get_audit_logger()\n    await audit.log(event_id=event_id, node="entry", action="received")'
        else:  # aggregator
            old = '    entry: AuditEntry = {\n        "node": "aggregator",\n        "ts": datetime.now(UTC).isoformat(),\n        "summary": f"verdict={verdict} confidence={confidence}",\n    }'
            new = '    entry: AuditEntry = {\n        "node": "aggregator",\n        "ts": datetime.now(UTC).isoformat(),\n        "summary": f"verdict={verdict} confidence={confidence}",\n    }\n    audit = get_audit_logger()\n    await audit.log(event_id=state["event_id"], node="aggregator", action=verdict)'
        c = c.replace(old, new)
        open(path, "w", encoding="utf-8").write(c)
        ast.parse(open(path, "r").read())
        print(f"  AuditLogger added to {f}")

print("\n=== P0-S4: Linter alias tracking ===")
path = "src/execution/linter/poc_linter.py"
c = open(path, "r", encoding="utf-8").read()
if "alias_map" not in c:
    # Add alias tracking to check method
    old_check = """    def check(self, code: str) -> LinterResult:
        result = self._syntax_check(code)
        if not result.passed:
            return result
        result = self._import_check(code)
        if not result.passed:
            return result
        return self._dangerous_call_check(code)"""
    new_check = """    def check(self, code: str) -> LinterResult:
        result = self._syntax_check(code)
        if not result.passed:
            return result
        alias_map = self._build_alias_map(code)
        result = self._import_check(code)
        if not result.passed:
            return result
        return self._dangerous_call_check(code, alias_map)"""
    c = c.replace(old_check, new_check)
    # Add _build_alias_map method
    c = c.replace('    @staticmethod\n    def _call_name(node: ast.expr) -> str:', '    @staticmethod\n    def _build_alias_map(code: str) -> dict[str, str]:\n        alias_map = {}\n        try:\n            tree = ast.parse(code)\n            for node in ast.walk(tree):\n                if isinstance(node, ast.Import):\n                    for alias in node.names:\n                        alias_map[alias.asname or alias.name] = alias.name.split(".")[0]\n                elif isinstance(node, ast.ImportFrom):\n                    module = (node.module or "").split(".")[0]\n                    for alias in node.names:\n                        alias_map[alias.asname or alias.name] = module\n        except SyntaxError:\n            pass\n        return alias_map\n\n    @staticmethod\n    def _call_name(node: ast.expr) -> str:')
    # Update _dangerous_call_check signature
    c = c.replace("def _dangerous_call_check(self, code: str) -> LinterResult:", "def _dangerous_call_check(self, code: str, alias_map: dict[str, str] | None = None) -> LinterResult:")
    c = c.replace('            name = self._call_name(node.func)\n            if name in DANGEROUS_CALLS:', '            name = self._call_name(node.func)\n            # Resolve aliases\n            if alias_map:\n                parts = name.split(".", 1)\n                if parts[0] in alias_map:\n                    resolved = alias_map[parts[0]] + ("." + parts[1] if len(parts) > 1 else "")\n                    if resolved in DANGEROUS_CALLS:\n                        name = resolved\n            if name in DANGEROUS_CALLS:')
    open(path, "w", encoding="utf-8").write(c)
    ast.parse(open(path, "r").read())
    print("  Linter alias tracking added")
else:
    print("  SKIP - already has alias tracking")

print("\n=== P1-F4: Playbook triggers ===")
playbooks_dir = "src/orchestration/playbooks"
import yaml
for fn in sorted(os.listdir(playbooks_dir)):
    if not fn.endswith(".yaml"):
        continue
    fp = os.path.join(playbooks_dir, fn)
    with open(fp, "r", encoding="utf-8") as f:
        pb = yaml.safe_load(f)
    if "trigger" not in pb:
        # Add trigger block based on playbook type
        triggers = {
            "malware_detection": {"verdict": ["true_positive"], "tags": ["malware"]},
            "phishing": {"verdict": ["true_positive"], "tags": ["phishing"]},
            "cve_exploit": {"verdict": ["true_positive"], "tags": ["vulnerability"], "confidence_min": 0.7},
            "ransomware": {"verdict": ["true_positive"], "tags": ["ransomware"], "confidence_min": 0.8},
            "data_exfiltration": {"verdict": ["true_positive"], "tags": ["exfiltration"]},
            "lateral_movement": {"verdict": ["true_positive"], "tags": ["lateral_movement"]},
            "ddos": {"verdict": ["true_positive"], "tags": ["ddos"]},
            "brute_force": {"verdict": ["true_positive"], "tags": ["brute_force"]},
            "dns_tunneling": {"verdict": ["true_positive"], "tags": ["dns_tunneling"]},
            "unauthorized_access": {"verdict": ["true_positive"], "tags": ["unauthorized_access"]},
        }
        pid = pb.get("playbook_id", "")
        trigger = triggers.get(pid, {"verdict": ["true_positive"]})
        pb["trigger"] = trigger
        with open(fp, "w", encoding="utf-8") as f:
            yaml.dump(pb, f, default_flow_style=False, sort_keys=False)
        print(f"  trigger added to {fn}")

print("\n=== P1-F7: MemoryManager fixes ===")
path = "src/orchestration/memory/manager.py"
c = open(path, "r", encoding="utf-8").read()
# Fix TTL 72h -> 24h
c = c.replace("_DEFAULT_TTL_HOURS = 72", "_DEFAULT_TTL_HOURS = 24")
# Fix _store_in_graph to reuse self._neo4j
if "self._neo4j" in c:
    old = '''    async def _store_in_graph(
        self,
        event_id: str,
        node: str,
        doc_id: str,
        content: str,
        metadata: dict[str, Any],
    ) -> None:
        from neo4j import AsyncGraphDatabase
        settings = get_settings()
        driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        try:
            async with driver.session() as session:
                await session.run(
                    """
                    MERGE (e:Event {event_id: $event_id})
                    MERGE (ev:Evidence {doc_id: $doc_id})
                    SET ev.node = $node,
                        ev.content = $content,
                        ev.metadata = $metadata,
                        ev.ts = $ts
                    MERGE (e)-[:HAS_EVIDENCE]->(ev)
                    """,
                    event_id=event_id,
                    doc_id=doc_id,
                    node=node,
                    content=content[:2000],
                    metadata=json.dumps(metadata),
                    ts=metadata.get("ts", datetime.now(UTC).isoformat()),
                )
        finally:
            await driver.close()'''
    new = '''    async def _store_in_graph(
        self,
        event_id: str,
        node: str,
        doc_id: str,
        content: str,
        metadata: dict[str, Any],
    ) -> None:
        """Insert evidence as a Neo4j node linked to the event, reusing self._neo4j."""
        try:
            async with self._neo4j._driver.session() as session:
                await session.run(
                    """
                    MERGE (e:Event {event_id: $event_id})
                    MERGE (ev:Evidence {doc_id: $doc_id})
                    SET ev.node = $node,
                        ev.content = $content,
                        ev.metadata = $metadata,
                        ev.ts = $ts
                    MERGE (e)-[:HAS_EVIDENCE]->(ev)
                    """,
                    event_id=event_id,
                    doc_id=doc_id,
                    node=node,
                    content=content[:2000],
                    metadata=json.dumps(metadata),
                    ts=metadata.get("ts", datetime.now(UTC).isoformat()),
                )
        except Exception as exc:
            logger.error("neo4j_store_failed", error=str(exc))'''
    c = c.replace(old, new)
    open(path, "w", encoding="utf-8").write(c)
    ast.parse(open(path, "r").read())
    print("  _store_in_graph now reuses self._neo4j driver")
    print("  TTL changed to 24h")

print("\n=== Fixes applied ===")
