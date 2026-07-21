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
RUN pip install --no-cache-dir -r requirements.txt

COPY modulator.py server.py cli.py mapping.yaml ./

# Server mode by default; use cli.py for one-shot runs
ENTRYPOINT ["python", "server.py"]
