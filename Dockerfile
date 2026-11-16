# syntax=docker/dockerfile:1.7

# Refresh the digest with:
# docker buildx imagetools inspect python:3.12-slim --format '{{json .Manifest.Digest}}'

# -------- build stage --------
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY pyproject.toml ./
COPY README.md ./
COPY constraints ./constraints

# Build the wheel against the pinned toolchain instead of floating build deps.
RUN PIP_CONSTRAINT=/build/constraints/ci.txt \
    pip install --upgrade pip build setuptools wheel

COPY xferry ./xferry

RUN PIP_CONSTRAINT=/build/constraints/ci.txt \
    python -m build --wheel --no-isolation --outdir /build/dist

# -------- runtime stage --------
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime

ARG APP_USER=xferry
ARG APP_UID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    XFERRY_STATE_HOME=/data

# Add a dedicated non-root user.
RUN groupadd --system --gid ${APP_UID} ${APP_USER} && \
    useradd --system --uid ${APP_UID} --gid ${APP_UID} \
            --home-dir /home/${APP_USER} --create-home \
            --shell /usr/sbin/nologin ${APP_USER}

# Install the wheel with its runtime ACME/crypto dependencies.
COPY constraints /tmp/constraints
COPY --from=build /build/dist/*.whl /tmp/
RUN PIP_CONSTRAINT=/tmp/constraints/ci.txt pip install --upgrade pip && \
    PIP_CONSTRAINT=/tmp/constraints/ci.txt pip install "$(ls /tmp/*.whl)" && \
    rm -rf /tmp/*.whl /tmp/constraints

# Prepare one private runtime root; named volumes inherit non-root ownership.
RUN mkdir -p /data/files /data/notes /data/acme /data/.xferry && \
    chown -R ${APP_USER}:${APP_USER} /data

USER ${APP_USER}
WORKDIR /data

EXPOSE 8080 8443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request as u, sys; \
r = u.Request('http://127.0.0.1:8080/', method='PING'); \
sys.exit(0 if u.urlopen(r, timeout=2).status == 200 else 1)"

ENTRYPOINT ["xferry"]
CMD ["run", "--access", "lab", "--host", "0.0.0.0", "--port", "8080", "--files-dir", "/data/files"]
