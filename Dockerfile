FROM python:3.11-slim-bullseye

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    pip install --no-cache-dir uv uvicorn && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY src ./src

COPY pyproject.toml uv.lock ./
RUN uv pip install --system -e .

RUN  mkdir -p /data

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["python", "-m", "src.SecExtend_CVESearch", "--mode", "sse"]
