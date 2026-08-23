# Dictionary-only Hashcat MCP Server
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    hashcat \
    tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt server.py download_wordlist.sh ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --create-home --uid 1000 mcpuser \
    && mkdir -p /app/wordlists /app/results \
    && chown -R mcpuser:mcpuser /app \
    && chmod 0555 /app/download_wordlist.sh

ENV PYTHONUNBUFFERED=1
USER mcpuser
ENTRYPOINT ["/usr/bin/tini", "--", "/app/download_wordlist.sh"]
CMD ["python", "/app/server.py"]
