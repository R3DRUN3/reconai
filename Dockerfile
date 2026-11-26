FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1

# Recon tools. Add more here when you add a tool plugin.
# dirb provides /usr/share/dirb/wordlists/common.txt (used by gobuster).
# httpx-toolkit = ProjectDiscovery httpx (binary name: httpx-toolkit).
# testssl.sh pulls in its own dependencies (openssl, dnsutils, hexdump...).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-pip ca-certificates \
      nuclei gobuster wpscan nmap dirb whatweb httpx-toolkit wafw00f testssl.sh \
 && rm -rf /var/lib/apt/lists/* \
 && test -f /usr/share/dirb/wordlists/common.txt \
 && command -v whatweb httpx-toolkit wafw00f \
 && (command -v testssl.sh || command -v testssl)

# Unprivileged runtime user (all built-in tools work without root / raw sockets).
RUN useradd --create-home --uid 10001 reconai && mkdir /data && chown reconai /data

COPY pyproject.toml README.md requirements.txt /app/
COPY src /app/src
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir /app
ENV PATH="/opt/venv/bin:$PATH"

USER reconai
WORKDIR /home/reconai
# Pre-fetch nuclei templates and the WPScan DB at build time; the runtime never updates them.
# (Non-fatal so an offline build still works - then update templates yourself, see README.)
RUN nuclei -update-templates -silent || echo "WARNING: could not fetch nuclei templates"; \
    wpscan --update --no-banner || echo "WARNING: could not update wpscan DB"

ENV RECONAI_DATA_DIR=/data RECONAI_HOST=0.0.0.0 RECONAI_PORT=9889
VOLUME /data
EXPOSE 9889
HEALTHCHECK --interval=30s --timeout=5s CMD python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:9889/health')"
CMD ["reconai"]