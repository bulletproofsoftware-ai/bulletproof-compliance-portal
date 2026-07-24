# Production Installation Guide

This guide covers deploying the Compliance Portal to production infrastructure.

## Server Prerequisites

### Minimum Sizing

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 50 GB | 100+ GB (encrypted) |
| Network | 1 Gbps | 10 Gbps |

### Required Services

- **Docker** 20.10+ with `docker compose` plugin
- **PostgreSQL** 14+ (or managed service)
- **Redis** 6.0+ (session store + rate limit counters)
- **Qdrant** 1.0+ (process knowledge index)
- **Compliance Service** (PRD-18 enforcement engine)

### Operating Systems

- **Ubuntu 20.04 LTS** (recommended)
- **Ubuntu 22.04 LTS** (latest stable)
- **Debian 11+**
- **Amazon Linux 2** (AWS EC2)

## Step 1: Clone Repository and Verify

```bash
# Clone the repo
git clone https://github.com/<org>/compliance-portal.git
cd compliance-portal

# Verify git history integrity
git log --oneline | head -20

# Verify SBOM presence
ls -la docker/SBOM.* || ls -la sbom/

# Check SECURITY.md
cat SECURITY.md | head -20
```

## Step 2: Pre-Deployment Checklist

Before deploying, verify:

```bash
# ✓ All tests pass on target OS
docker run -it ubuntu:22.04 bash -c "
  apt-get update && \
  apt-get install -y python3.12 pip && \
  cd /opt/compliance-portal && \
  pip install -r requirements.txt && \
  pytest tests -q
"

# ✓ SBOM generated and scanned
grype sbom:sbom/sbom.cyclonedx.json --output json > vuln-report.json
cat vuln-report.json | grep -i critical || echo "No critical CVEs"

# ✓ SECURITY.md disclosure policy is reviewed
cat SECURITY.md

# ✓ Environment template is prepared
cp .env.example .env.production
# Edit with production values
```

## Step 3: Configure Encryption at Rest (AMD-09)

### Linux (LUKS)

```bash
# Create encrypted partition (100 GB)
sudo fallocate -l 100G /luks-partition.img
sudo cryptsetup luksFormat /luks-partition.img
sudo cryptsetup luksOpen /luks-partition.img compliance-data
sudo mkfs.ext4 /dev/mapper/compliance-data
sudo mkdir -p /opt/compliance-data
sudo mount /dev/mapper/compliance-data /opt/compliance-data
```

Add to `/etc/crypttab`:
```
compliance-data /luks-partition.img none luks,discard
```

### macOS (FileVault)

```bash
# Enable FileVault on the volume containing `/opt/compliance-data`
sudo fdesetup enable -user $USER
# Follow prompts to enable encryption
```

### AWS (EBS)

```bash
# Launch EC2 instance with encrypted EBS volume
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=100,VolumeType=gp3,Encrypted=true}' \
  --instance-type t3.xlarge
```

## Step 4: Netbird Configuration (Internal Portal Isolation)

### Install Netbird Client

```bash
# Ubuntu/Debian
curl -L https://pkgs.netbird.io/install.sh | bash

# Verify installation
sudo netbird status
```

### Register Portal Server

```bash
# On compliance portal server
sudo netbird up

# Authorize on Netbird dashboard
# Return to server and verify peer list
sudo netbird peers list
```

### Configure Firewall Rules

In Netbird dashboard, create access policy:

```yaml
Name: "Compliance Portal Internal"
Rules:
  - Source Group: compliance-officers
    Destination Group: compliance-portal-internal
    Ports: 8443/tcp
    
  - Source Group: auditors
    Destination Group: compliance-portal-internal
    Ports: 8443/tcp
```

## Step 5: WAF Configuration (Public Portal)

### Cloudflare WAF

```bash
# Set up Cloudflare protection for public portal
# Dashboard: Security → WAF → Create Rule

# Rule 1: Rate Limiting
When: Requests to path matches /dsr/*
Then: Block if > 100 req/min per IP

# Rule 2: Body Size
When: POST request body > 4MB
Then: Block (AMD-11)

# Rule 3: Geographic Blocking
When: Request originates from [BLOCKED_COUNTRIES]
Then: Block
```

### AWS WAF

```bash
# Create WAF rules
aws wafv2 create-web-acl \
  --name "compliance-portal-public" \
  --scope REGIONAL \
  --default-action Block={} \
  --rules file://waf-rules.json

# Rules in waf-rules.json:
# - RateBasedStatement (100 req/5min)
# - SizeConstraintStatement (Body < 4MB)
# - GeoMatchStatement (Block countries)
```

## Step 6: mTLS Bootstrap with Compliance Service (AMD-10)

### Generate Client Certificate

```bash
# Create private key
openssl genrsa -out client-key.pem 2048

# Create certificate signing request
openssl req -new \
  -key client-key.pem \
  -out client.csr \
  -subj "/C=US/O=MyOrg/CN=compliance-portal"

# Sign with compliance service CA (get from compliance team)
openssl x509 -req \
  -days 365 \
  -in client.csr \
  -CA compliance-ca.pem \
  -CAkey compliance-ca-key.pem \
  -CAcreateserial \
  -out client-cert.pem
```

### Mount Certificates in Docker

```yaml
# docker-compose.yml
services:
  portal:
    volumes:
      - ./certs/client-cert.pem:/run/secrets/client_cert
      - ./certs/client-key.pem:/run/secrets/client_key
      - ./certs/compliance-ca.pem:/run/secrets/compliance_ca
    environment:
      COMPLIANCE_API_CLIENT_CERT: /run/secrets/client_cert
      COMPLIANCE_API_CLIENT_KEY: /run/secrets/client_key
      COMPLIANCE_API_CA_BUNDLE: /run/secrets/compliance_ca
```

### Test Connection

```bash
# From portal container
curl --cert /run/secrets/client_cert \
     --key /run/secrets/client_key \
     --cacert /run/secrets/compliance_ca \
     https://compliance-svc.internal/api/v1/compliance/healthz
```

## Step 7: Log Forwarding Setup (AMD-24)

### Wazuh Agent

```bash
# Install Wazuh agent
curl -s https://packages.wazuh.com/4.x/apt/0.gpg | apt-key add -
apt-get install wazuh-agent

# Configure /var/ossec/etc/ossec.conf
<agent_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/compliance-portal/app.log</location>
  </localfile>
</agent_config>

# Start Wazuh agent
systemctl start wazuh-agent
systemctl status wazuh-agent
```

### ELK Stack (Elasticsearch + Logstash + Kibana)

```yaml
# docker-compose.yml (optional local ELK)
elasticsearch:
  image: docker.elastic.co/elasticsearch/elasticsearch:8.0.0
  environment:
    - discovery.type=single-node
    - xpack.security.enabled=false

logstash:
  image: docker.elastic.co/logstash/logstash:8.0.0
  volumes:
    - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
  depends_on:
    - elasticsearch

kibana:
  image: docker.elastic.co/kibana/kibana:8.0.0
  ports:
    - "5601:5601"
  depends_on:
    - elasticsearch
```

### Loki (Grafana)

```yaml
# docker-compose.yml
loki:
  image: grafana/loki:2.0
  ports:
    - "3100:3100"
  volumes:
    - ./loki-config.yml:/etc/loki/local-config.yml

promtail:
  image: grafana/promtail:2.0
  volumes:
    - /var/log/compliance-portal:/var/log/compliance-portal
    - ./promtail-config.yml:/etc/promtail/config.yml

grafana:
  image: grafana/grafana:8.0
  ports:
    - "3000:3000"
  depends_on:
    - loki
```

## Step 8: Production Docker Compose Deployment

```yaml
# docker-compose.yml (production)
version: '3.9'

services:
  # Internal Portal (Compliance Officers, Auditors)
  portal:
    image: ghcr.io/org/compliance-portal:latest
    environment:
      APP_MODE: internal
      APP_ENV: production
      LOG_LEVEL: INFO
      INTERNAL_PORT: 8001
      COMPLIANCE_API_CLIENT_CERT: /run/secrets/client_cert
      COMPLIANCE_API_CLIENT_KEY: /run/secrets/client_key
      COMPLIANCE_API_CA_BUNDLE: /run/secrets/compliance_ca
      REDIS_URL: redis://redis:6379/0
      PG_DSN: postgresql+asyncpg://portal:${PG_PASSWORD}@postgres:5432/compliance_portal
      QDRANT_URL: http://qdrant:6333
    secrets:
      - client_cert
      - client_key
      - compliance_ca
    volumes:
      - evidence-store:/data/evidence
      - pdf-cache:/data/pdf
    depends_on:
      - redis
      - postgres
      - qdrant
    networks:
      - portal-net
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8001/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Public DSR Portal (Data Subjects)
  dsr_portal:
    image: ghcr.io/org/compliance-portal:latest
    environment:
      APP_MODE: public
      APP_ENV: production
      LOG_LEVEL: INFO
      PUBLIC_PORT: 8002
      COMPLIANCE_API_BASE_URL: https://compliance-svc.internal/api/v1/compliance
      COMPLIANCE_API_TOKEN: ${COMPLIANCE_API_SERVICE_TOKEN}
      REDIS_URL: redis://redis:6379/1
      CAPTCHA_PROVIDER: hcaptcha
      CAPTCHA_SITE_KEY: ${CAPTCHA_SITE_KEY}
      CAPTCHA_SECRET: ${CAPTCHA_SECRET}
      PUBLIC_RATE_LIMIT_PER_MIN: 100
    depends_on:
      - redis
    networks:
      - public-net
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8002/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  # Shared Services
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis-data:/data
    networks:
      - portal-net
    restart: always

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: portal
      POSTGRES_PASSWORD: ${PG_PASSWORD}
      POSTGRES_DB: compliance_portal
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - portal-net
    restart: always

  qdrant:
    image: qdrant/qdrant:latest
    volumes:
      - qdrant-data:/qdrant/storage
    networks:
      - portal-net
    restart: always

  # nginx internal (TLS termination)
  portal_nginx:
    image: nginx:latest
    ports:
      - "8443:443"
    volumes:
      - ./nginx/internal.conf:/etc/nginx/nginx.conf:ro
      - /run/secrets/tls_cert:/etc/nginx/certs/cert.pem:ro
      - /run/secrets/tls_key:/etc/nginx/certs/key.pem:ro
    secrets:
      - tls_cert
      - tls_key
    depends_on:
      - portal
    networks:
      - portal-net
    restart: always

  # nginx public (TLS + WAF rules)
  public_nginx:
    image: nginx:latest
    ports:
      - "8444:443"
    volumes:
      - ./nginx/public.conf:/etc/nginx/nginx.conf:ro
      - /run/secrets/public_tls_cert:/etc/nginx/certs/cert.pem:ro
      - /run/secrets/public_tls_key:/etc/nginx/certs/key.pem:ro
    secrets:
      - public_tls_cert
      - public_tls_key
    depends_on:
      - dsr_portal
    networks:
      - public-net
    restart: always

networks:
  portal-net:
    driver: bridge
  public-net:
    driver: bridge

volumes:
  evidence-store:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /mnt/compliance-data/evidence
  pdf-cache:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /mnt/compliance-data/pdf
  redis-data:
  postgres-data:
  qdrant-data:

secrets:
  client_cert:
    file: ./certs/client-cert.pem
  client_key:
    file: ./certs/client-key.pem
  compliance_ca:
    file: ./certs/compliance-ca.pem
  tls_cert:
    file: ./certs/portal-cert.pem
  tls_key:
    file: ./certs/portal-key.pem
  public_tls_cert:
    file: ./certs/public-cert.pem
  public_tls_key:
    file: ./certs/public-key.pem
```

## Step 9: Deploy and Verify

```bash
# Create environment file with production values
cat > .env.production << 'EOF'
PG_PASSWORD=$(openssl rand -base64 32)
COMPLIANCE_API_SERVICE_TOKEN=$(openssl rand -hex 32)
CAPTCHA_SITE_KEY=<from-hcaptcha-dashboard>
CAPTCHA_SECRET=<from-hcaptcha-dashboard>
EOF

# Start all services
docker compose -f docker-compose.yml up -d

# Verify all containers are healthy
docker compose ps

# Check logs
docker compose logs -f portal
docker compose logs -f dsr_portal

# Test health endpoints
curl --insecure https://127.0.0.1:8443/healthz
curl --insecure https://127.0.0.1:8444/healthz

# Run smoke tests
docker compose exec portal pytest tests/test_health.py -v
```

## Step 10: Create Initial Admin Account

```bash
# Inside the portal container
docker compose exec portal bash

# Create admin user via CLI (if script exists)
python -m portal.cli create-admin \
  --email admin@org.com \
  --name "Admin User" \
  --password "$(openssl rand -base64 32)"

# Or via database (if using PostgreSQL)
psql -U portal -d compliance_portal << 'EOF'
INSERT INTO users (email, name, role, created_at)
VALUES ('admin@org.com', 'Admin User', 'admin', NOW());
EOF
```

## Step 11: Backup and Recovery

### Automated Backups

```bash
# Daily backup script (runs via cron)
#!/bin/bash
BACKUP_DIR="/backups/compliance-portal"
DATE=$(date +%Y%m%d-%H%M%S)

# Backup PostgreSQL
docker compose exec -T postgres pg_dump -U portal compliance_portal | \
  gzip > "$BACKUP_DIR/postgres-$DATE.sql.gz"

# Backup Redis
docker compose exec -T redis redis-cli BGSAVE
docker cp compliance_portal-redis-1:/data/dump.rdb "$BACKUP_DIR/redis-$DATE.rdb"

# Backup Qdrant snapshots
docker compose exec -T qdrant /qdrant/qdrant-snapshot.sh
docker cp compliance_portal-qdrant-1:/qdrant/snapshots "$BACKUP_DIR/qdrant-$DATE"

# Backup encrypted volumes
tar czf "$BACKUP_DIR/evidence-$DATE.tar.gz" /mnt/compliance-data/evidence
tar czf "$BACKUP_DIR/pdf-$DATE.tar.gz" /mnt/compliance-data/pdf

# Clean up old backups (keep 30 days)
find "$BACKUP_DIR" -mtime +30 -delete
```

### Recovery Procedure

```bash
# Restore from backup
docker compose down
docker volume rm compliance_portal_postgres-data
docker volume rm compliance_portal_redis-data

# Restore PostgreSQL
zcat /backups/compliance-portal/postgres-YYYYMMDD.sql.gz | \
  docker compose exec -T postgres psql -U portal compliance_portal

# Restore Redis
docker cp /backups/compliance-portal/redis-YYYYMMDD.rdb \
  compliance_portal-redis-1:/data/dump.rdb

docker compose up -d
```

## Monitoring and Alerts

### Prometheus Metrics

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'compliance-portal'
    static_configs:
      - targets: ['localhost:8001']
    metrics_path: '/metrics'
```

### Alert Rules

```yaml
# alerts.yml
groups:
  - name: compliance-portal
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate on compliance portal"

      - alert: ServiceDown
        expr: up{job="compliance-portal"} == 0
        for: 1m
        annotations:
          summary: "Compliance portal is down"
```

## Maintenance Windows

### Zero-Downtime Deployment

```bash
# 1. Build new image
docker build -t ghcr.io/org/compliance-portal:v1.1.0 .
docker push ghcr.io/org/compliance-portal:v1.1.0

# 2. Update docker-compose.yml with new image tag
sed -i 's/:latest/:v1.1.0/g' docker-compose.yml

# 3. Roll out with health check
docker compose up -d --no-deps --scale portal=2 portal

# 4. Wait for new instance to be healthy
docker compose exec -T portal curl http://localhost:8001/healthz

# 5. Remove old instance
docker compose down portal_1

# 6. Scale back to 1
docker compose up -d --no-deps --scale portal=1 portal
```

## Troubleshooting

### Container Fails to Start

```bash
docker compose logs portal
# Check for:
# - Missing environment variables
# - Database connection errors
# - Certificate/secret mount errors
```

### High Memory Usage

```bash
docker compose stats
# Check which container is consuming memory
docker compose exec portal python -m memory_profiler

# Consider adjusting:
# - PYTHONUNBUFFERED=1 for logging
# - Connection pool sizes
# - Cache sizes
```

### Database Deadlocks

```bash
# Monitor locks
docker compose exec -T postgres psql -U portal << 'EOF'
SELECT * FROM pg_stat_activity WHERE state = 'active';
SELECT * FROM pg_locks WHERE NOT granted;
EOF
```

See **[INCIDENT-RESPONSE.md](./INCIDENT-RESPONSE.md)** for security incident procedures.
