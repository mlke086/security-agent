#!/bin/bash
# archive_docs.sh —— docs 过期文档归档工具（RULES.md 规则 4）
# 用法: bash scripts/archive_docs.sh [--apply] [--days N]
#   --apply  实际执行移动; 缺省为预览模式(只打印将移动的文件)
#   --days N 超过 N 天未更新的 .md 视为过期(默认 60)
set -euo pipefail
cd "$(dirname "$0")/.."   # 项目根

DAYS=60
APPLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --days) DAYS="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 2 ;;
  esac
done

ARCHIVE="docs/archive"
mkdir -p "$ARCHIVE"

# 保护名单: 永不归档
PROTECT="README.md|PROJECT_TREE.md|新需求方案|开发计划|项目功能详细梳理|分布式架构拆分方案|后续计划V13|部署|deployment-guide"

echo "== docs 过期扫描 (>=${DAYS} 天未更新, 预览: $([ $APPLY -eq 0 ] && echo YES || echo NO)) =="
found=0
while IFS= read -r f; do
  [[ -f "$f" ]] || continue
  base=$(basename "$f")
  echo "$base" | grep -qE "$PROTECT" && continue
  days=$(find "$(dirname "$f")" -name "$base" -mtime +"$DAYS" | wc -l)
  [[ "$days" -lt 1 ]] && continue
  echo "  过期: $f"
  found=$((found + 1))
  if [[ $APPLY -eq 1 ]]; then
    dest="$ARCHIVE/$base"
    # 重名加时间戳
    if [[ -e "$dest" ]]; then
      dest="$ARCHIVE/$(date +%Y%m%d)-$base"
    fi
    mv "$f" "$dest"
    echo "    -> 已归档: $dest"
  fi
done < <(find docs -maxdepth 1 -name "*.md" -o -maxdepth 1 -name "*.js" | sort)

echo "== 完成: 共 $found 个过期文件$([ $APPLY -eq 0 ] && echo " (加 --apply 实际移动)") =="
