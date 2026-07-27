# Image co Chromium + deps cho Playwright tren Linux (cloud).
FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Cai Python deps + Chromium (kem system deps).
COPY requirements.txt .
RUN pip install -r requirements.txt \
 && playwright install --with-deps chromium

# Tao user non-root (giam privilege).
RUN useradd -m app
COPY --chown=app:app . .
USER app

# Render/Render cap PORT qua env; mac dinh 8000.
ENV PORT=8000
EXPOSE 8000

# Healthcheck bang endpoint /healthz (khong can auth).
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/healthz'%os.environ.get('PORT','8000')).read()" || exit 1

# 1 worker gunicorn (worker thread rieng giu 1 browser -> tiet kiem RAM).
# KHONG dung -w > 1 (se mo nhieu browser -> OOM). KHONG --preload (thread worker).
CMD ["sh", "-c", "gunicorn -w 1 -b 0.0.0.0:${PORT:-8000} --timeout 120 web:app"]
