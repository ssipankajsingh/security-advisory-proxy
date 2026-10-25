FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

ENV PORT=3001
EXPOSE 3001

CMD ["gunicorn", "server:app", "--bind", "0.0.0.0:3001", "--workers", "1", "--worker-class", "gevent", "--timeout", "300", "--graceful-timeout", "300"]
