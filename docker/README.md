# Compliance Portal — Docker Deployment

This directory contains the production-grade containerization for the
Compliance Portal: TWO isolated FastAPI apps fronted by TWO nginx reverse
proxies on TWO non-bridged Docker networks.

## Topology

```
                                   Host
       ┌────────────────────────────────────────────────────────────┐
       │                                                            │
       │   127.0.0.1:8443 ────►  portal_nginx  (TLS, Netbird-side)  │
       │                              │                             │
       │                              │ internal-mgmt (internal)    │
       │                              ▼                             │
       │                          portal:8001  (FastAPI)            │
       │                              │                             │
       │                              │ portal-net                  │
       │                              ▼                             │
       │                          redis:6379                        │
       │                          postgres:5432  (dev profile only) │
       │                                                            │
       │   ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── ── │
       │                                                            │
       │   127.0.0.1:8444 ────►  public_nginx  (TLS, internet-side) │
       │                              │                             │
       │                              │ public-net                  │
       │                              ▼                             │
       │                          dsr_portal:8002 (FastAPI)         │
       │                                                            │
       │   ※ portal-net  ⊥  public-net  (NO bridge — REQ-CPL-036)   │
       └────────────────────────────────────────────────────────────┘
```

## Quick Start (Localhost)

```bash
# 1. From repo root
cd /path/to/compliance-portal

# 2. (Dev only) start everything including Postgres
docker compose -f docker/compose.yaml --profile dev up -d --build

# 3. Verify health
curl --insecure https://127.0.0.1:8443/healthz   # internal portal
curl --insecure https://127.0.0.1:8444/healthz   # public DSR portal

# Or hit the FastAPI containers directly (bypassing nginx, for diagnostics)
docker compose -f docker/compose.yaml exec portal     curl -fsS http://127.0.0.1:8001/healthz
docker compose -f docker/compose.yaml exec dsr_portal curl -fsS http://127.0.0.1:8002/healthz

# 4. Access
# Internal portal (operator UI):   https://localhost:8443/
# Public DSR portal (subject UI):  https://localhost:8444/

# 5. Tear down (preserves volumes)
docker compose -f docker/compose.yaml down

# 6. Tear down + delete volumes (DATA LOSS)
docker compose -f docker/compose.yaml down -v
```

## Validating the Compose File

Without bringing the stack up:

```bash
docker compose -f docker/compose.yaml config        # render full config
docker compose -f docker/compose.yaml config --quiet # validate only
```

## Network Isolation Verification (REQ-CPL-036)

The two portals MUST live on isolated Docker networks. Verify after `up`:

```bash
# 1. Inspect each network — confirm only the expected services are members.
docker network inspect compliance-portal_portal-net  | jq '.[].Containers'
docker network inspect compliance-portal_public-net  | jq '.[].Containers'

# Expected:
#   portal-net  → portal, redis, postgres (only)
#   public-net  → dsr_portal, public_nginx (only)

# 2. Confirm public-net cannot reach portal-net services.
docker compose -f docker/compose.yaml exec dsr_portal \
    curl --max-time 3 --silent --output /dev/null -w "%{http_code}\n" \
         http://portal:8001/healthz
# Expected: 000  (DNS resolution fails — no route to portal-net)

# 3. Confirm dsr_portal cannot reach redis or postgres.
docker compose -f docker/compose.yaml exec dsr_portal \
    nc -zv redis 6379 2>&1 | grep -E 'fail|refused|timed out'
docker compose -f docker/compose.yaml exec dsr_portal \
    nc -zv postgres 5432 2>&1 | grep -E 'fail|refused|timed out'
```

The `tests/test_docker_config.py` automated test parses `compose.yaml` and
asserts no overlap between `portal-net` and `public-net` service membership.

## Encryption At Rest (AMD-09 — MANDATORY)

The `evidence-store` and `pdf-cache` Docker volumes contain personal data,
evidence packages, and rendered PDFs that may include classified information.
The host filesystem holding `/var/lib/docker/volumes/` MUST be encrypted at
rest. Choose one:

### Linux: LUKS (recommended for self-hosted)

```bash
# 1. Allocate a block device or LUKS-on-file
cryptsetup luksFormat /dev/<device>
cryptsetup luksOpen   /dev/<device> docker-vol
mkfs.ext4 /dev/mapper/docker-vol
mount /dev/mapper/docker-vol /var/lib/docker/volumes

# 2. Verify
cryptsetup status docker-vol
# expected: type: LUKS2, cipher: aes-xts-plain64, keysize: 512 bits
```

### macOS: FileVault

System-wide FileVault encryption is sufficient because Docker Desktop stores
volumes in the user's encrypted home directory. Verify with:

```bash
fdesetup status
# expected: FileVault is On.
```

### Windows: BitLocker

Enable BitLocker on the drive backing `C:\ProgramData\Docker`. Verify:

```powershell
Get-BitLockerVolume -MountPoint C:
# ProtectionStatus should be On
```

### Cloud-managed

- AWS: encrypted EBS volumes — `aws ec2 describe-volumes --filters Name=encrypted,Values=true`
- Azure: Azure Disk Encryption / SSE
- GCP: CMEK on persistent disks

A non-encrypted host filesystem is a deployment-blocking violation of
AMD-09. The runbook for any production deployment must include the
verification command output.

## Centralized Log Forwarding (AMD-24)

Container stdout JSON logs and the `audit-logs` volume contents MUST be
forwarded to a centralized log store with the retention policy below.

### Retention Policy

| Log class                          | Retention      |
|------------------------------------|----------------|
| Application logs (portal stdout)   | 90d hot, 1y cold |
| Audit chain (compliance service)   | 7 years (regulatory minimum) |
| nginx access logs                  | 90d            |
| nginx error logs                   | 1y             |
| Behavioral hook detections         | 1y             |

### Filebeat (Elastic / OpenSearch)

`/etc/filebeat/filebeat.yml` snippet on the host:

```yaml
filebeat.inputs:
  - type: container
    paths:
      - /var/lib/docker/containers/*/*-json.log

  - type: log
    paths:
      - /var/lib/docker/volumes/compliance-portal_audit-logs/_data/*.log

processors:
  - decode_json_fields:
      fields: ["message"]
      target: ""
      overwrite_keys: true
  - drop_fields:
      fields:
        - "password"
        - "secret"
        - "token"
        - "authorization"
        - "cookie"
        - "subject_email"
        - "subject_name"
        - "subject_phone"
        - "subject_address"
        - "dob"

output.elasticsearch:
  hosts: ["https://elastic.internal:9200"]
  api_key: "${ELASTIC_API_KEY}"
```

### Wazuh

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/docker/containers/*/*-json.log</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/docker/volumes/compliance-portal_audit-logs/_data/*.log</location>
</localfile>
```

### Loki + Promtail (recommended for Grafana stacks)

```yaml
clients:
  - url: https://loki.internal/loki/api/v1/push

scrape_configs:
  - job_name: docker
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        regex:  '/(compliance-portal-.+)'
        target_label: container
```

## mTLS Bootstrap (Compliance Service)

The internal portal connects upstream to the compliance service over mTLS.
Bootstrap inside the container:

```bash
# 1. On the host, place the certs in docker/certs/ (gitignored)
docker/certs/portal.crt
docker/certs/portal.key
docker/certs/compliance-ca.crt

# 2. Add a bind mount in docker/compose.yaml `portal:` (already declared
#    via the COMPLIANCE_API_CLIENT_CERT env var — see .env.example).
```

## Operational

### Logs

```bash
docker compose -f docker/compose.yaml logs -f portal
docker compose -f docker/compose.yaml logs -f dsr_portal
docker compose -f docker/compose.yaml logs -f portal_nginx
docker compose -f docker/compose.yaml logs -f public_nginx
```

### Backups (evidence-store volume)

```bash
# Snapshot
docker run --rm \
    -v compliance-portal_evidence-store:/data:ro \
    -v $(pwd):/backup \
    alpine \
    tar czf /backup/evidence-store-$(date +%Y%m%d).tgz -C /data .

# Restore
docker run --rm \
    -v compliance-portal_evidence-store:/data \
    -v $(pwd):/backup \
    alpine \
    sh -c "rm -rf /data/* && tar xzf /backup/evidence-store-YYYYMMDD.tgz -C /data"
```

### Secret Rotation

Rotate file content on host, then signal the affected container:

```bash
echo -n "<new-token>" > docker/secrets/compliance_service_token
docker compose -f docker/compose.yaml restart portal
```

### Image Vulnerability Scan

```bash
# Trivy
trivy image --severity HIGH,CRITICAL compliance-portal-internal:latest
trivy image --severity HIGH,CRITICAL compliance-portal-public:latest

# SBOM (see SBOM.md)
syft compliance-portal-internal:latest -o cyclonedx-json > sbom-internal.cdx.json
```

## Troubleshooting

| Symptom                                  | Investigation                                |
|------------------------------------------|----------------------------------------------|
| `portal_nginx` won't start               | `nginx -t` inside container; check certs paths |
| `portal` failing health checks            | `docker compose logs portal`; check `entrypoint.sh` secret loading |
| 502 from nginx                            | Backend healthcheck failing; check uvicorn workers |
| `dsr_portal` reaching `redis`             | NETWORK ISOLATION VIOLATION — file a P0; check compose networks |
| WeasyPrint render fails                   | Confirm `libcairo2` and `libpango-1.0-0` installed in image |

## Production Hardening Checklist

- [ ] Encryption at rest verified (LUKS / FileVault / cloud)
- [ ] Real secrets in `docker/secrets/` (NOT `secrets.example/`)
- [ ] TLS certs valid and not self-signed
- [ ] Internal portal placed behind Netbird / Tailscale (no direct internet exposure on 8443)
- [ ] Public portal fronted by an additional WAF (Cloudflare / AWS WAF) in production
- [ ] Centralized log forwarding active (Wazuh / Filebeat / Loki)
- [ ] SBOM generated and attached to image (see `SBOM.md`)
- [ ] Trivy scan clean for HIGH/CRITICAL
- [ ] Resource limits validated against expected load
- [ ] Backup / restore procedure exercised at least once
