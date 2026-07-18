"""S0-4: Middleware connectivity self-check script."""

import sys


def check(label, ok, detail=""):
    status = "OK" if ok else "FAIL"
    msg = f"  [{status}] {label}"
    if detail:
        msg += f": {detail}"
    print(msg)
    return ok


results = []
print("=== Middleware Connectivity Check ===\n")

# 1. Redis
try:
    import redis
    r = redis.Redis.from_url("redis://:redis_password_2026@192.168.80.101:6379/0")
    r.ping()
    results.append(check("Redis", True, "ping OK"))
    r.close()
except Exception as e:
    results.append(check("Redis", False, str(e)[:60]))

# 2. Elasticsearch
try:
    from elasticsearch import Elasticsearch
    es = Elasticsearch("http://192.168.80.101:9200")
    ok = es.ping()
    results.append(check("Elasticsearch", ok))
    es.close()
except Exception as e:
    results.append(check("Elasticsearch", False, str(e)[:60]))

# 3. Kafka (connection test)
try:
    from aiokafka import AIOKafkaConsumer
    import asyncio
    async def test_kafka():
        try:
            consumer = AIOKafkaConsumer(
                "raw-alerts",
                bootstrap_servers="192.168.80.101:9092",
                metadata_max_age_ms=5000,
            )
            await consumer.start()
            await consumer.stop()
            return True, ""
        except Exception as e:
            return False, str(e)[:60]
    ok, detail = asyncio.run(test_kafka())
    results.append(check("Kafka", ok, detail))
except Exception as e:
    results.append(check("Kafka", False, str(e)[:60]))

# 4. Milvus
try:
    from pymilvus import connections
    connections.connect(host="192.168.80.101", port=19530)
    results.append(check("Milvus", True, "connected"))
except Exception as e:
    results.append(check("Milvus", False, str(e)[:60]))

# 5. Neo4j
try:
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver("bolt://192.168.80.101:7687", auth=("neo4j", "neo4j_password_2026"))
    driver.verify_connectivity()
    results.append(check("Neo4j", True, "connected"))
    driver.close()
except Exception as e:
    results.append(check("Neo4j", False, str(e)[:60]))

# 6. vLLM HTTP check
try:
    import httpx
    r = httpx.get("http://192.168.80.101:8000/health", timeout=5)
    results.append(check("vLLM", r.status_code == 200, f"HTTP {r.status_code}"))
except Exception as e:
    results.append(check("vLLM", False, str(e)[:60]))

print(f"\n{'='*20}")
passed = sum(1 for r in results if r)
total = len(results)
print(f"Result: {passed}/{total} services reachable")
if passed < total:
    print("WARNING: Some services are unreachable!")
    sys.exit(1)
else:
    print("All services reachable!")
