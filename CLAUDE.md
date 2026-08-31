# Security Advisory Proxy — Backend

Flask/Python backend for Concentrix GSE Security Advisory Platform.
Deployed on Render free tier. Supabase for storage.

## Key rules
- Main file: server.py (~5000 lines)
- Validate syntax before every change: python -m py_compile server.py
- Deploy: commit to GitHub → Render auto-deploys
- All Supabase URL timestamps must use strftime("%Y-%m-%dT%H:%M:%SZ") not isoformat()
- In-memory advisory cache TTL: 10 min (MEM_CACHE_TTL = 600)
- Request coalescing via _advisories_lock — never remove this
- flask-compress gzip is active — reduces bandwidth 87%
- fetched_at must NEVER be overwritten on upsert

## Environment vars (on Render)
ACCESS_CODE, ADMIN_PIN, SUPABASE_URL, SUPABASE_KEY,
SENDGRID_API_KEY, TEAMS_WEBHOOK, NVD_API_KEY

## Stack
Flask, Supabase REST API, APScheduler, feedparser, requests, gunicorn+gevent
