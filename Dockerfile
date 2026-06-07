# syntax=docker/dockerfile:1.7
# HunterPy — production image with bundled scanning tools.
#
# Build:
#   docker build -t hunterpy:2.0 .
#
# Run (mount your output directory + pass target):
#   docker run --rm -v "$PWD/output:/work/output" hunterpy:2.0 \
#       -t example.com --mode passive --confirm-authorized --i-am-authorized
#
# Drop into a shell with all tools available:
#   docker run --rm -it --entrypoint bash hunterpy:2.0
#
# Use your own NVD API key (recommended — raises rate limit 10×):
#   docker run --rm -e NVD_API_KEY="$NVD_API_KEY" \
#       -v "$PWD/output:/work/output" hunterpy:2.0 \
#       -t example.com --mode full --confirm-authorized --i-am-authorized

# ============================================================================
# Stage 1: tool builder — fetches nuclei via go, then we discard the toolchain
# ============================================================================
FROM golang:1.22-bookworm AS gobuild

# Pinned for reproducibility. Bump in CHANGELOG.md when updating.
ARG NUCLEI_VERSION=v3.2.9

ENV GOPATH=/root/go \
    GOFLAGS="-trimpath -mod=readonly" \
    CGO_ENABLED=0

# Nuclei is the only tool we install from source — apt doesn't ship a
# version recent enough for the template library to be useful.
RUN go install -ldflags="-s -w" \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} && \
    /root/go/bin/nuclei -version 2>&1 | head -3

# ============================================================================
# Stage 2: runtime — python + apt-installed scanners, non-root user
# ============================================================================
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="HunterPy" \
      org.opencontainers.image.description="Web security recon orchestrator with bundled tools" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.source="https://github.com/hunterpy/hunterpy"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HUNTERPY_IN_DOCKER=1

# --- system packages -------------------------------------------------------
# All scanners come from Debian where reasonable. We pin nothing here
# because Debian's stable channel does that for us; switching to apt-pin
# would require us to vendor a snapshot repo and that's not worth it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        # network basics
        ca-certificates curl wget dnsutils whois \
        # python ext deps that need C compilers if pip-built
        libxml2 libxslt1.1 \
        # scanners — these are the workhorses
        nmap \
        nikto \
        sqlmap \
        hydra \
        gobuster \
        ffuf \
        # tini for clean PID 1 (so Ctrl+C reaches the python process)
        tini \
        && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* && \
    # Sanity-check that the tools landed
    nmap --version > /dev/null && \
    nikto -Version > /dev/null 2>&1 || true && \
    sqlmap --version > /dev/null && \
    hydra -h > /dev/null 2>&1 || true && \
    gobuster version > /dev/null && \
    ffuf -V > /dev/null

# --- nuclei from the build stage -------------------------------------------
COPY --from=gobuild /root/go/bin/nuclei /usr/local/bin/nuclei
RUN nuclei -version 2>&1 | head -2

# --- python dependencies ---------------------------------------------------
# Copy only what's needed for `pip install` first so changes to source code
# don't bust the dependency layer cache.
WORKDIR /opt/hunterpy
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- application code ------------------------------------------------------
# Copy everything except what .dockerignore excludes. Order matters: we
# `chown` once at the end so we don't double the image size with chown
# layers.
COPY . .

# --- non-root user ---------------------------------------------------------
# Pentesters often run scans as their own user to avoid file-permission
# headaches when reading reports from /work/output on the host. We pick
# a fixed uid:gid (1000:1000) which matches the typical first-user on a
# host. Override at run-time with `docker run --user $(id -u):$(id -g)`
# if you need to.
RUN groupadd --system --gid 1000 hunterpy && \
    useradd  --system --uid 1000 --gid 1000 \
        --home-dir /work --shell /bin/bash --create-home hunterpy && \
    mkdir -p /work/output && \
    chown -R hunterpy:hunterpy /work /opt/hunterpy

USER hunterpy
WORKDIR /work

# --- pre-warm nuclei templates --------------------------------------------
# Done at runtime (first scan), not build time — otherwise the image
# carries a huge template snapshot that ages out quickly. nuclei does
# this automatically on first run.

# --- runtime --------------------------------------------------------------
# tini ensures Ctrl+C is forwarded to the python process and reaps
# zombies left by subprocess-based tool wrappers.
ENTRYPOINT ["/usr/bin/tini", "--", "python", "/opt/hunterpy/main.py"]

# Default args: print help. Override with your scan command.
CMD ["--help"]

# Quick image-health check: importable + tool detection works
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=2 \
    CMD python /opt/hunterpy/main.py --check-tools >/dev/null 2>&1 || exit 1
