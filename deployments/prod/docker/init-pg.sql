-- ============================================================
-- SecAgent PostgreSQL init
-- 启动时由 entrypoint.sh 调用(idempotent:全部 IF NOT EXISTS)。
-- 也可以用 psql 手动执行:
--   PGPASSWORD=... psql -h HOST -U secagent -d SecAgent \
--     -f deployments/prod/docker/init-pg.sql
--
-- 注意:数据库 + 角色必须由运维在数据库初始化时建好(本脚本不创建 ROLE)。
--   CREATE ROLE secagent LOGIN PASSWORD '...';
--   CREATE DATABASE SecAgent OWNER secagent;
-- ============================================================

-- 1) 默认 schema 走 src.common.db.pg._SCHEMA_SQL,这里只确保业务必需的拓展
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2) 一次性塞默认模型:DeepSeek(已默认)+ 空模型槽位
--    llm_models 表由 pg.py 在启动时统一建,这里不再重复 DDL

-- 3) 默认 LLM 模型默认槽位在 init-nacos.sh 里走应用层创建,
--    这里只做与数据库无关的初始化。

SELECT 'pg init OK' AS status;
