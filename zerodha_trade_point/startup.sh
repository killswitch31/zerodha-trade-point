#!/usr/bin/env bash
set -euo pipefail

cd /home/site/wwwroot

# Ensure dependencies are available even when Oryx build artifacts are missing.
if [[ -f requirements.txt ]]; then
  python -m pip install --no-cache-dir -r requirements.txt
fi

# Best-effort migrations for app startup.
python manage.py migrate --noinput
python manage.py collectstatic --noinput

exec gunicorn zerodha_trade_point.wsgi:application \
  --bind "0.0.0.0:${PORT:-8000}" \
  --workers 2 \
  --timeout 120
