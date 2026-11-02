FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 APP_ENV=production DATABASE_PATH=/data/app.db
WORKDIR /srv/app
COPY requirements.txt requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements-prod.txt
COPY . .
RUN useradd --system --no-create-home app && mkdir /data && chown app /data
USER app
EXPOSE 8000
# One worker: SQLite is single-writer and the rate limiter is in-process. Scale with threads.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "app:create_app()"]
