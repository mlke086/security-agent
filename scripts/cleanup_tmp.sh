#!/bin/bash
# cleanup_tmp.sh —— 临时文件/垃圾清理工具（RULES.md 规则 5）
# 用法: bash scripts/cleanup_tmp.sh [--apply] [--limit N]
#   --apply   实际删除; 缺省为预览模式(只打印将删除的文件)
#   --limit N 仅当候选文件数 >= N 才提示执行(默认 5, 避免误删刚生成的)
set -euo pipefail
cd "$(dirname "$0")/.."   # 项目根

APPLY=0
LIMIT=5
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --limit) LIMIT="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
done

echo "== 临时文件扫描 (预览: $([ $APPLY -eq 0 ] && echo YES || echo NO)) =="
candidates=()

# 1) 项目内 .tmp* / *.tmp 命名
while IFS= read -r f; do
  candidates+=("$f")
done < <(find . -path ./node_modules -prune -o -path ./.venv -prune -o -path ./.venv312 -prune -o \
  -path ./.git -prune -o -type f \( -name ".tmp*" -o -name "*.tmp" -o -name "*.bak" -o -name "*~" \) -print 2>/dev/null | head -100)

# 2) 一次性验证脚本（根目录 e2e_*/check_*/dbg_*）
while IFS= read -r f; do
  candidates+=("$f")
done < <(find . -maxdepth 1 -type f \( -name "e2e_*.sh" -o -name "check_*.sh" -o -name "dbg_*.sh" -o -name "smoke_*.sh" \) -print 2>/dev/null)

# 3) Python/Go 缓存目录
while IFS= read -r d; do
  candidates+=("$d")
done < <(find . -path ./node_modules -prune -o -path ./.venv -prune -o -path ./.venv312 -prune -o \
  -type d \( -name "__pycache__" -o -name ".pytest_cache" -o -name ".mypy_cache" -o -name ".ruff_cache" \) -print 2>/dev/null | head -50)

count=${#candidates[@]}
echo "  候选: $count 个"
if [[ $count -lt $LIMIT ]]; then
  echo "  少于 $LIMIT 个, 跳过（避免误删）"
  exit 0
fi

for f in "${candidates[@]:0:60}"; do
  echo "  [$([ $APPLY -eq 1 ] && echo DEL || echo KEEP)] $f"
done
if [[ $count -gt 60 ]]; then
  echo "  ... 等 $((count - 60)) 个"
fi

if [[ $APPLY -eq 1 ]]; then
  for f in "${candidates[@]}"; do
    rm -rf "$f" 2>/dev/null || true
  done
  echo "== 已清理 $count 个 =="
else
  echo "== 预览模式, 加 --apply 执行删除 =="
fi
