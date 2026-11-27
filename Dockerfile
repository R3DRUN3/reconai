
FROM kalilinux/kali-rolling

ARG TARGETARCH=amd64

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1

# Install ReconAI's system tools and the utilities needed to install Katana.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates \
      curl unzip \
      nuclei gobuster wpscan nmap dirb whatweb httpx-toolkit wafw00f testssl.sh \
 && rm -rf /var/lib/apt/lists/* \
 && test -f /usr/share/dirb/wordlists/common.txt \
 && command -v whatweb httpx-toolkit wafw00f curl \
 && (command -v testssl.sh || command -v testssl)

# Install a pinned ProjectDiscovery Katana release.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) KATANA_ARCH="amd64" ;; \
      arm64) KATANA_ARCH="arm64" ;; \
      *) echo "Unsupported TARGETARCH for Katana: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    KATANA_VERSION="1.8.0"; \
    KATANA_ARCHIVE="katana_${KATANA_VERSION}_linux_${KATANA_ARCH}.zip"; \
    KATANA_URL="https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/${KATANA_ARCHIVE}"; \
    mkdir -p /tmp/katana; \
    curl --fail --location --silent --show-error \
      "${KATANA_URL}" \
      --output "/tmp/${KATANA_ARCHIVE}"; \
    unzip -q "/tmp/${KATANA_ARCHIVE}" -d /tmp/katana; \
    test -x /tmp/katana/katana; \
    install -m 0755 /tmp/katana/katana /usr/local/bin/katana; \
    katana -version; \
    rm -rf /tmp/katana "/tmp/${KATANA_ARCHIVE}"

# Unprivileged runtime user (built-in tools do not need root / raw sockets).
RUN useradd --create-home --uid 10001 reconai \
 && mkdir /data \
 && chown reconai /data

COPY pyproject.toml README.md requirements.txt /app/
COPY src /app/src

# Install ReconAI and Arjun in the same virtual environment.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir /app \
    && /opt/venv/bin/pip install --no-cache-dir arjun \
    && test -x /opt/venv/bin/arjun

ENV PATH="/opt/venv/bin:$PATH"

USER reconai
WORKDIR /home/reconai

# Pre-fetch templates and WPScan DB at build time; runtime never updates them.
# These steps are non-fatal so offline builds can still complete.
RUN nuclei -update-templates -silent || echo "WARNING: could not fetch nuclei templates"; \
    wpscan --update --no-banner || echo "WARNING: could not update wpscan DB"

ENV RECONAI_DATA_DIR=/data RECONAI_HOST=0.0.0.0 RECONAI_PORT=9889

VOLUME /data
EXPOSE 9889

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:9889/health')"

CMD ["reconai"]
