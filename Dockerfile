FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY server.py .

# Run as an unprivileged user, not root
RUN useradd --create-home --uid 10001 app
USER app

# Render injects $PORT (default 10000); Azure Container Apps / local fall back to 3001
ENV PORT=3001
EXPOSE 3001

# Shell form so $PORT is expanded at runtime. exec replaces the shell so gunicorn gets SIGTERM directly.
# gthread (real threads), not gevent: the feed refresh is CPU-heavy and starved the gevent loop,
# so /health stopped answering and Render restarted the instance mid-refresh.
# 1 worker only — in-memory caches and APScheduler jobs must not be duplicated.
CMD exec gunicorn server:app --bind 0.0.0.0:${PORT} --workers 1 --worker-class gthread --threads 8 --timeout 300 --graceful-timeout 300
