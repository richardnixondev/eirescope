FROM python:3.11-slim

# System dependencies for OSINT modules (whois lookups, DNS queries)
RUN apt-get update && \
    apt-get install -y --no-install-recommends whois dnsutils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["/docker-entrypoint.sh"]
