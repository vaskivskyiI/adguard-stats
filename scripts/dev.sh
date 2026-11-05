#!/usr/bin/env bash
# Local run without podman, against a fake AdGuard Home with synthetic data.
#   scripts/dev.sh            -> dashboard on http://127.0.0.1:8080
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data web/vendor
[[ -f web/vendor/echarts.min.js ]] || curl -fsSL -o web/vendor/echarts.min.js https://cdn.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js
python tests/fake_adguard.py --days "${DAYS:-21}" --port 3999 &
trap 'kill $!' EXIT
ADGUARD_URL=http://127.0.0.1:3999 DB_PATH=data/dev.db DASHBOARD_PASSWORD= TZ=${TZ:-Europe/Ljubljana} \
  python -m uvicorn app.api:app --host 127.0.0.1 --port "${PORT:-8080}"
