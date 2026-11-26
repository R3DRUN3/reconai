FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1

# dirb provides the fixed wordlist used by gobuster.
# httpx-toolkit is ProjectDiscovery's httpx binary on Kali.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates \
      nuclei gobuster wpscan nmap dirb whatweb httpx-toolkit wafw00f testssl.sh curl \
 && rm -rf /var/lib/apt/lists/* \
 && test -f /usr/share/dirb/wordlists/common.txt \
 && command -v whatweb httpx-toolkit wafw00f curl \
 && (command -v testssl.sh || command -v testssl)

# Unprivileged runtime user (built-in tools do not need root / raw sockets).
RUN useradd --create-home --uid 10001 reconai \
 && mkdir /data \
 && chown reconai /data

COPY pyproject.toml README.md requirements.txt /app/
COPY src /app/src

RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir /app

ENV PATH="/opt/venv/bin:$PATH"

USER reconai
WORKDIR /home/reconai

# Pre-fetch templates and WPScan DB at build time; the runtime never updates them.
# These steps are non-fatal so offline builds can still complete.
RUN nuclei -update-templates -silent || echo "WARNING: could not fetch nuclei templates"; \
    wpscan --update --no-banner || echo "WARNING: could not update wpscan DB"

ENV RECONAI_DATA_DIR=/data RECONAI_HOST=0.0.0.0 RECONAI_PORT=9889

VOLUME /data
EXPOSE 9889

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:9889/health')"

CMD ["reconai"]