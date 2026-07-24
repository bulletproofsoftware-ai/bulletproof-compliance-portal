# SBOM Generation (AMD-22)

CISO M-13 / OWASP A06 / NIST SI-2 require an attestable Software Bill of
Materials (SBOM) for every shipped image. SBOMs let downstream consumers
verify dependency provenance and run fast vulnerability lookups without
re-scanning the image.

## Format

CycloneDX 1.5 JSON. Both portal images produce a SBOM at build time and the
artefacts are attached to the image in the registry as Trivy attestations.

## Local Generation

### Using `syft` (recommended)

```bash
# One-time install
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b /usr/local/bin

# Build images
docker compose -f docker/compose.yaml build

# Generate SBOMs in CycloneDX JSON
syft compliance-portal-internal:latest -o cyclonedx-json > sbom-internal.cdx.json
syft compliance-portal-public:latest   -o cyclonedx-json > sbom-public.cdx.json

# Validate JSON (basic shape)
python -m json.tool sbom-internal.cdx.json >/dev/null
python -m json.tool sbom-public.cdx.json   >/dev/null

# Attach SBOM to image (cosign / OCI)
cosign attest --predicate sbom-internal.cdx.json \
              --type cyclonedx \
              compliance-portal-internal:latest
```

### Using `docker scout`

```bash
docker scout sbom --format cyclonedx --output sbom-internal.cdx.json \
  compliance-portal-internal:latest

docker scout sbom --format cyclonedx --output sbom-public.cdx.json \
  compliance-portal-public:latest
```

### Using `cyclonedx-bom` (Python tool, source-tree SBOM)

```bash
pip install cyclonedx-bom
cyclonedx-py requirements -r requirements.txt -o sbom-source.cdx.json
```

## CI Integration

Add to your CI pipeline after `docker build`:

```yaml
# .github/workflows/build.yml (excerpt)
- name: Install Syft
  run: |
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sh -s -- -b /usr/local/bin

- name: Generate SBOMs
  run: |
    syft compliance-portal-internal:${{ github.sha }} -o cyclonedx-json \
      > sbom-internal.cdx.json
    syft compliance-portal-public:${{ github.sha }}   -o cyclonedx-json \
      > sbom-public.cdx.json

- name: Validate SBOM JSON
  run: |
    python -m json.tool sbom-internal.cdx.json >/dev/null
    python -m json.tool sbom-public.cdx.json   >/dev/null

- name: Upload SBOMs as artifacts
  uses: actions/upload-artifact@v4
  with:
    name: sboms
    path: sbom-*.cdx.json

- name: Run Trivy scan against SBOM
  run: |
    trivy sbom --severity HIGH,CRITICAL --exit-code 1 sbom-internal.cdx.json
    trivy sbom --severity HIGH,CRITICAL --exit-code 1 sbom-public.cdx.json
```

## Retention

SBOMs are retained for the lifetime of the released image plus 24 months. A
release is identified by an immutable SHA tag; mutable tags (`latest`,
`stable`) are SBOM-attestation-resolved at consumption time.

## Vulnerability Re-scanning

Run nightly:

```bash
# Re-scan SBOM against current vuln database
trivy sbom --severity HIGH,CRITICAL sbom-internal.cdx.json
trivy sbom --severity HIGH,CRITICAL sbom-public.cdx.json
```

Any new HIGH/CRITICAL finding triggers an investigation ticket and a patch
release if the finding is exploitable in the deployed configuration.
