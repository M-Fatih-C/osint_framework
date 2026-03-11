#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${OSINT_VENV_DIR:-$ROOT_DIR/.venv}"
if [[ -n "${OSINT_PYTHON_BIN:-}" ]]; then
  PYTHON_BIN="$OSINT_PYTHON_BIN"
elif command -v python3.12 >/dev/null 2>&1; then
  PYTHON_BIN="python3.12"
else
  PYTHON_BIN="python3"
fi

echo "[setup] root: $ROOT_DIR"
echo "[setup] python: $PYTHON_BIN"
echo "[setup] venv: $VENV_DIR"

target_py_ver="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
if [[ ! -d "$VENV_DIR" ]]; then
  echo "[setup] creating virtual environment..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
else
  existing_py_ver="$("$VENV_DIR/bin/python" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  if [[ "$existing_py_ver" != "$target_py_ver" ]]; then
    echo "[setup] existing venv python=$existing_py_ver, target=$target_py_ver"
    echo "[setup] recreating venv for consistent binary compatibility..."
    rm -rf "$VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi
fi

PIP_BIN="$VENV_DIR/bin/pip"
PY_BIN="$VENV_DIR/bin/python"

echo "[setup] upgrading pip/setuptools/wheel..."
"$PIP_BIN" install --upgrade pip setuptools wheel

echo "[setup] installing dependencies..."
"$PIP_BIN" install -r "$ROOT_DIR/requirements.txt"

echo "[setup] done."
echo "[setup] verify: $PY_BIN -m unittest discover -s $ROOT_DIR/tests -p 'test*.py'"
