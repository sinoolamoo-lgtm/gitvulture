# =============================================================================
#  GitVulture - .git exposure exploitation framework
#  Run anywhere with:
#     docker build -t gitvulture .
#     docker run --rm -it gitvulture --help
#     docker run --rm -it -e EMERGENT_LLM_KEY=$EMERGENT_LLM_KEY \
#                        -v $PWD/output:/root/.gitvulture/output \
#                        gitvulture https://target.example.com --ai -vv
# =============================================================================
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git is needed by some recon stages (worktree replay) and by the user as well.
# ca-certificates keeps httpx TLS happy.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/gitvulture

# Install dependencies first (better layer cache) by copying only the
# project metadata. The Emergent index hosts emergentintegrations.
COPY pyproject.toml ./
RUN pip install --upgrade pip wheel setuptools \
 && pip install --extra-index-url https://d33sy5i8bnduwe.cloudfront.net/simple/ \
      "httpx[http2]>=0.27" "rich>=13" "aiofiles>=23" "python-dotenv>=1.0" \
      "emergentintegrations==0.2.0"

# Now copy the source and install the package itself
COPY gitvulture ./gitvulture
COPY scripts ./scripts
COPY README.md USAGE.md ./
RUN pip install --no-deps -e .

# Output volume - sqlmap-style: /root/.gitvulture/output/<host>/<timestamp>/
RUN mkdir -p /root/.gitvulture/output
VOLUME ["/root/.gitvulture"]

ENTRYPOINT ["gitvulture"]
CMD ["--help"]
