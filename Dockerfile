# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Proxy support — passed through from the build environment
ARG http_proxy
ARG https_proxy
ARG no_proxy
ENV http_proxy=$http_proxy \
    https_proxy=$https_proxy \
    no_proxy=$no_proxy

COPY requirements.txt .
# If ca-bundle.pem exists in the repo root, install with it; otherwise install normally.
# To use a custom CA: cp /etc/ssl/ca-bundle.pem . (gitignored)
RUN --mount=type=bind,source=.,target=/ctx \
    if [ -f /ctx/ca-bundle.pem ]; then \
      cp /ctx/ca-bundle.pem /etc/ssl/ca-bundle.pem && \
      pip install --no-cache-dir --cert /etc/ssl/ca-bundle.pem -r requirements.txt; \
    else \
      pip install --no-cache-dir -r requirements.txt; \
    fi

COPY modulator.py server.py cli.py mapping.yaml ./

# Server mode by default; use cli.py for one-shot runs
ENTRYPOINT ["python", "server.py"]
