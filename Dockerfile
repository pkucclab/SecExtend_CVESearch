FROM python:3.11-slim-bullseye

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv uvicorn

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv pip install --system -e .

COPY src ./src
COPY fscan /usr/local/bin/

RUN chmod +x /usr/local/bin/fscan \
    && mkdir -p /data

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["python", "-m", "src.SecExtend_Fscan", "--mode", "sse"]
