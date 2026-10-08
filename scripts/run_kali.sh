#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

HOST_NAME="$(hostname 2>/dev/null || printf kali)"
VENV_ROOT="$PROJECT_ROOT/.venvs"
VENV_PATH="$VENV_ROOT/kali-$HOST_NAME"
PYTHON_EXE="$VENV_PATH/bin/python"
STAMP_FILE="$VENV_PATH/.requirements.sha256"

if [ ! -x "$PYTHON_EXE" ]; then
    mkdir -p "$VENV_ROOT"
    python3 -m venv "$VENV_PATH"
fi

if ! "$PYTHON_EXE" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    PYTHON_VERSION="$("$PYTHON_EXE" --version 2>&1 || true)"
    printf 'Python 3.11 or newer is required. This environment uses %s at %s.\n' "$PYTHON_VERSION" "$PYTHON_EXE" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    REQUIREMENTS_HASH="$(sha256sum requirements.txt | awk '{print $1}')"
else
    REQUIREMENTS_HASH="$("$PYTHON_EXE" - <<'PY'
from pathlib import Path
import hashlib
print(hashlib.sha256(Path("requirements.txt").read_bytes()).hexdigest())
PY
)"
fi

INSTALLED_HASH=""
if [ -f "$STAMP_FILE" ]; then
    INSTALLED_HASH="$(cat "$STAMP_FILE")"
fi

if [ "$INSTALLED_HASH" != "$REQUIREMENTS_HASH" ]; then
    "$PYTHON_EXE" -m pip install --upgrade pip
    "$PYTHON_EXE" -m pip install -r requirements.txt
    printf '%s\n' "$REQUIREMENTS_HASH" > "$STAMP_FILE"
fi

"$PYTHON_EXE" scripts/init_db.py

if [ -z "${REVLEARN_SECRET_KEY:-}" ]; then
    REVLEARN_SECRET_KEY="$("$PYTHON_EXE" -c 'import secrets; print(secrets.token_hex(32))')"
    export REVLEARN_SECRET_KEY
fi

export REVLEARN_HOST="${REVLEARN_HOST:-127.0.0.1}"
export REVLEARN_PORT="${REVLEARN_PORT:-5000}"

printf '\nReverse Engineering Learning System\n'
printf 'Project: %s\n' "$PROJECT_ROOT"
printf 'Python:  %s\n' "$PYTHON_EXE"
printf 'Open:    http://%s:%s\n' "$REVLEARN_HOST" "$REVLEARN_PORT"
printf 'Stop:    Ctrl+C\n\n'

"$PYTHON_EXE" app.py
