FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Force Kali to use the global Cloudflare CDN
RUN echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list

# Install Python, Go, and OSINT tools (theHarvester, WhatWeb)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    golang-go \
    git \
    ca-certificates \
    theharvester \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

# Create Python Virtual Environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install all 8 Go-based Security Tools
RUN GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    GOBIN=/usr/local/bin go install -v github.com/ffuf/ffuf/v2@latest && \
    GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    GOBIN=/usr/local/bin go install -v -ldflags="-s -w" github.com/lc/gau/v2/cmd/gau@latest && \
    GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    GOBIN=/usr/local/bin go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    apt-get remove -y golang-go git && \
    apt-get autoremove -y && \
    rm -rf /root/go /var/cache/apt/archives

WORKDIR /app
RUN mkdir -p /workspace

CMD ["sleep", "infinity"]
