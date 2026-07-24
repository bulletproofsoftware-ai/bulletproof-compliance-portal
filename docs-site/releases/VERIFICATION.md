# Release Asset Verification Guide

This guide explains how to verify the integrity and authenticity of Compliance Portal release assets before installation.

## Overview

All official Compliance Portal releases are distributed with cryptographic signatures and checksums to ensure:

- **Integrity**: The release file has not been corrupted or tampered with
- **Authenticity**: The release came from the official Compliance Portal project

## Verification Methods

### Method 1: SHA256 Checksum (Fastest)

The fastest verification method uses SHA256 checksums to verify that the file you downloaded matches the official release.

#### Step 1: Download the Checksum File

```bash
curl -O https://github.com/[org]/compliance-portal/releases/download/v0.1.0/checksums.txt
```

#### Step 2: Verify Your Downloaded File

**Linux/macOS**:
```bash
# Verify single file
sha256sum compliance-portal-0.1.0-linux-amd64.tar.gz

# Compare with checksum file
sha256sum -c checksums.txt 2>&1 | grep compliance-portal-0.1.0-linux-amd64
```

**macOS (alternative)**:
```bash
shasum -a 256 compliance-portal-0.1.0-darwin-amd64.tar.gz
```

**Windows (PowerShell)**:
```powershell
# Single file
(Get-FileHash compliance-portal-0.1.0-windows-amd64.zip -Algorithm SHA256).Hash

# Verify against checksum
$expected = Get-Content checksums.txt | Select-String "windows-amd64" | ForEach-Object { $_.Line.Split()[0] }
$actual = (Get-FileHash compliance-portal-0.1.0-windows-amd64.zip -Algorithm SHA256).Hash
if ($actual -eq $expected) { "OK" } else { "MISMATCH" }
```

**Expected Output**: If the checksum matches, you should see `OK` or no error message.

### Method 2: GPG Signature (Recommended)

GPG signature verification provides strong authentication that the release came from the official maintainers.

#### Step 1: Import the Release Signing Key

If you don't already have the release key, import it from the keyserver:

```bash
# Import from OpenPGP keyserver
gpg --keyserver keys.openpgp.org --recv-keys 0xABCD1234EFGH5678

# Or import from the project repository
curl -sSL https://raw.githubusercontent.com/[org]/compliance-portal/main/keys/release.asc | gpg --import
```

#### Step 2: Download the Signature File

```bash
curl -O https://github.com/[org]/compliance-portal/releases/download/v0.1.0/checksums.txt.sig
```

#### Step 3: Verify the Signature

```bash
gpg --verify checksums.txt.sig checksums.txt
```

**Expected Output**:
```
gpg: Signature made Sun 27 Apr 2024 12:00:00 PM UTC
gpg:                using RSA key ABCD1234EFGH5678IJKLMNOPQRSTUVWXYZ012345
gpg: Good signature from "Compliance Portal Release Bot <releases@example.com>"
```

**If You See "Good Signature"**: The file is authentic and signed by the official release key.

#### Step 4 (Optional): Trust the Key

For future releases, you can mark the key as trusted:

```bash
gpg --edit-key 0xABCD1234EFGH5678

# At the gpg prompt, type: trust
# Then select trust level (4 = full trust)
# Then type: quit
```

### Method 3: Container Image Verification (For Docker Deployments)

If you're using the container image, verify the image signature:

```bash
# Install Cosign
brew install cosign  # macOS
# or download from https://github.com/sigstore/cosign

# Verify the image signature
cosign verify ghcr.io/[org]/compliance-portal:v0.1.0 \
  --certificate-identity=https://github.com/[org]/compliance-portal/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com
```

## Release Signing Key Information

### Key Details

| Property | Value |
|----------|-------|
| **Key ID** | `0xABCD1234EFGH5678` |
| **Fingerprint** | `ABCD 1234 EFGH 5678 IJKL  MNOP QRST UVWX YZ01 2345` |
| **Algorithm** | RSA 4096-bit |
| **Created** | 2024-04-27 |
| **Expires** | 2027-04-27 |
| **Email** | `releases@example.com` |

### Key Distribution

The release signing key is available from multiple sources:

1. **OpenPGP Keyserver**:
   ```bash
   gpg --keyserver keys.openpgp.org --recv-keys 0xABCD1234EFGH5678
   ```

2. **GitHub Repository**:
   ```bash
   curl -sSL https://raw.githubusercontent.com/[org]/compliance-portal/main/keys/release.asc
   ```

3. **Project Website**:
   - https://example.com/security/release-signing-key

## Release Artifacts

Each release includes multiple artifacts:

| File | Type | Purpose |
|------|------|---------|
| `compliance-portal-VERSION-linux-amd64.tar.gz` | Binary | Linux 64-bit |
| `compliance-portal-VERSION-darwin-amd64.tar.gz` | Binary | macOS Intel |
| `compliance-portal-VERSION-windows-amd64.zip` | Binary | Windows 64-bit |
| `compliance-portal-VERSION.docker.tar` | Image | Docker/Podman |
| `checksums.txt` | Checksums | SHA256 hashes for all artifacts |
| `checksums.txt.sig` | GPG signature | Signed checksums file |
| `sbom.cyclonedx.json` | SBOM | CycloneDX (security scanning) |
| `sbom.spdx.json` | SBOM | SPDX (license compliance) |

## Verification Checklist

Before using a release, verify:

- [ ] Downloaded from official GitHub Releases page
- [ ] SHA256 checksum matches (or GPG signature verified)
- [ ] Signing key fingerprint matches documented fingerprint
- [ ] SBOM included and scanned for vulnerabilities
- [ ] Release notes mention no issues or retracted versions

## Common Issues & Troubleshooting

### "No Public Key" Error

```
gpg: keyid ABCD1234EFGH5678 is unknown
gpg: verify signatures failed: Unknown key
```

**Solution**: Import the key first:
```bash
gpg --keyserver keys.openpgp.org --recv-keys 0xABCD1234EFGH5678
```

### "Bad Signature" Error

```
gpg: BAD signature from "Compliance Portal Release Bot <releases@example.com>"
```

**Possible Causes**:
1. File was corrupted during download
2. You're verifying the wrong file (not checksums.txt)
3. Key is incorrect or expired
4. File was modified after signing

**Solution**:
1. Re-download the files
2. Delete local GPG keys and re-import: `gpg --delete-keys 0xABCD1234EFGH5678`
3. Try verifying again

### Checksum Mismatch

```
compliance-portal-0.1.0-linux-amd64.tar.gz: FAILED
```

**Solution**:
1. Delete the corrupted file
2. Re-download from official GitHub Releases
3. Verify checksum again

## Release Distribution Channels

Official release channels:

| Channel | URL | Verification |
|---------|-----|--------------|
| **GitHub Releases** | https://github.com/[org]/compliance-portal/releases | GPG-signed |
| **Docker Hub** | https://hub.docker.com/r/[org]/compliance-portal | Cosign-signed |
| **GitHub Container Registry** | https://ghcr.io/[org]/compliance-portal | Cosign-signed |

**Do NOT download from**:
- Unofficial mirrors or third-party sites
- Unauthenticated HTTP URLs (always use HTTPS)
- Sites without proper TLS certificates

## Report Suspected Compromise

If verification fails and you suspect the release is compromised:

1. **DO NOT USE THE RELEASE**
2. Email `security@example.com` immediately
3. Include:
   - Which file failed verification
   - What verification method you used
   - The exact error message
   - Where you downloaded the file

## Additional Security Resources

- **Security Policy**: See [SECURITY.md](../../SECURITY.md)
- **Known Issues**: See release notes for any identified issues
- **Security Advisories**: See [Security Advisories](../security/advisories.md)

---

**For Questions**: security@example.com

**Last Updated**: 2024-04-27
