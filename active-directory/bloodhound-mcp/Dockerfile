# BloodHound MCP Server
# Wrapper for MorDavid/BloodHound-MCP-AI
# Based on: https://github.com/MorDavid/BloodHound-MCP-AI

FROM python:3.12-alpine

RUN apk add --no-cache \
    tini \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Vendored from MorDavid/BloodHound-MCP-AI commit 1eb21b01da14fd2eda941234e3a545e876bef296.
# The unrestricted query_bloodhound tool has been removed.
COPY vendor/requirements.txt vendor/BloodHound-MCP.py ./

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "BloodHound-MCP.py"]
