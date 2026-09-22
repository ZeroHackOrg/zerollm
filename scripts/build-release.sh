#!/usr/bin/env bash
# Build wheel/sdist, verify the import graph, and generate an SBOM (SPDX).
# Requires: python3 build, syft (https://github.com/anchore/syft)
set -euo pipefail
cd "$(dirname "$0")/.."

python -m build

echo "== import/type/test sanity =="
.venv/bin/ruff check src tests
.venv/bin/mypy src/zerollm
.venv/bin/python -m pytest -q

echo "== SBOM (SPDX-JSON) =="
if command -v syft >/dev/null 2>&1; then
  syft dir:. --output spdx-json=dist/zerollm.sbom.spdx.json
  echo "wrote dist/zerollm.sbom.spdx.json"
else
  echo "syft not installed - skipping SBOM (install: brew install syft)"
fi

echo "== artifacts =="
ls -la dist/