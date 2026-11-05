FROM docker.io/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DB_PATH=/data/stats.db TLDEXTRACT_CACHE=/tmp/tldextract
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app app
COPY web web
ADD https://cdn.jsdelivr.net/npm/echarts@5.5.1/dist/echarts.min.js web/vendor/echarts.min.js
RUN chmod 644 web/vendor/echarts.min.js \
 && useradd --uid 1000 --create-home app \
 && mkdir /data && chown app /data

USER app
VOLUME /data
EXPOSE 8080
# One worker only: the collector thread lives in the web process.
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-access-log"]
