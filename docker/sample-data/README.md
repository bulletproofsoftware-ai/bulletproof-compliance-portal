# sample-data

Default bind-mount targets for the `compliance_service` container so that
`docker compose up` works from a clean clone without any host paths configured.

These directories are intentionally empty. The compliance service renders its
empty-state UIs when they contain no data, which is the expected first-run
experience.

To use real data, set the corresponding host paths in `docker/.env`:

| Variable | Mounted at | Holds |
|---|---|---|
| `CODE_ROOT_HOST` | `/workspace/code` | Project source trees to analyse |
| `GOVERNANCE_AUDIT_DB_HOST` | `/workspace/governance` | Directory containing `audit.db` |
| `KNOWLEDGE_ROOT_HOST` | `/workspace/knowledge` | Knowledge corpus |

All three are mounted read-only.
