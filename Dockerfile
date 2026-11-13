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

# Swagger UI for /docs, baked in: FastAPI would load it from a CDN, which an
# air-gapped deployment can't reach. Pinned and checksummed (same as discobox).
ARG SWAGGER_UI_VERSION=5.17.14
ARG SWAGGER_UI_SHA256=c57badf459aa6e65cc036b3862d0502a63f9a22546407ffcb0e64f85f816bb28
RUN python - <<'PY'
import hashlib, io, os, tarfile, urllib.request
version, sha = os.environ["SWAGGER_UI_VERSION"], os.environ["SWAGGER_UI_SHA256"]
url = f"https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-{version}.tgz"
data = urllib.request.urlopen(url, timeout=120).read()
if hashlib.sha256(data).hexdigest() != sha:
    raise SystemExit(f"swagger-ui-dist {version}: sha256 mismatch")
os.makedirs("/app/static/swagger", exist_ok=True)
with tarfile.open(fileobj=io.BytesIO(data)) as tar:
    for name in ("swagger-ui-bundle.js", "swagger-ui.css", "favicon-32x32.png"):
        with open(f"/app/static/swagger/{name}", "wb") as f:
            f.write(tar.extractfile(f"package/{name}").read())
print(f"swagger-ui-dist {version}: /app/static/swagger")
PY

COPY modulator.py server.py cli.py mapping.yaml ./
COPY templates/ templates/

# Server mode by default; use cli.py for one-shot runs
ENTRYPOINT ["python", "server.py"]
