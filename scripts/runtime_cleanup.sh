#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

truncate_logs=true
clean_appledouble=true
clean_pycache=false

for arg in "$@"; do
  case "$arg" in
    --no-truncate-logs) truncate_logs=false ;;
    --no-appledouble) clean_appledouble=false ;;
    --clean-pycache) clean_pycache=true ;;
    *)
      echo "Unknown arg: $arg"
      echo "Usage: $0 [--no-truncate-logs] [--no-appledouble] [--clean-pycache]"
      exit 1
      ;;
  esac
done

echo "[cleanup] root: $ROOT_DIR"

if [[ "$clean_appledouble" == true ]]; then
  echo "[cleanup] removing AppleDouble files (._*)..."
  apple_count="$(find "$ROOT_DIR" -type f -name '._*' | wc -l | tr -d ' ')"
  find "$ROOT_DIR" -type f -name '._*' -delete
  echo "[cleanup] removed: $apple_count"
fi

if [[ "$truncate_logs" == true ]]; then
  echo "[cleanup] truncating .log files..."
  while IFS= read -r -d '' log_file; do
    : > "$log_file"
    echo "[cleanup] truncated: $log_file"
  done < <(find "$ROOT_DIR" -type f -name '*.log' -print0)
fi

if [[ "$clean_pycache" == true ]]; then
  echo "[cleanup] removing __pycache__ directories..."
  find "$ROOT_DIR" -type d -name '__pycache__' -prune -exec rm -rf {} +
fi

echo "[cleanup] done."
