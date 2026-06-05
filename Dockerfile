FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY samples ./samples
COPY scripts ./scripts

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[web]" \
    && python -m pip check

RUN chmod +x scripts/docker-entrypoint.sh \
    && adduser --disabled-password --gecos "" appuser \
    && mkdir -p data \
    && chown -R appuser:appuser /app

EXPOSE 18080

USER appuser

ENTRYPOINT ["scripts/docker-entrypoint.sh"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:18080/health', timeout=3)"

CMD ["web-log-sql", "serve", "--db", "data/dashboard.db", "--host", "0.0.0.0", "--port", "18080"]
