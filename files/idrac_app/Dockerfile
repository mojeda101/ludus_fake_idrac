FROM python:3.12-slim

LABEL maintainer="mojeda101"
LABEL description="Fake SHELL iDRAC9 - CTF / Security Awareness Training Target"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8443

# -w 1 required: WebSocket connections must stay in a single eventlet worker
CMD gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:${IDRAC_PORT:-8443} --timeout 120 app:app
