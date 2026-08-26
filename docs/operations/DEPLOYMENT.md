# Deployment

## Environments

| Name | Data | Secrets | Purpose |
|---|---|---|---|
| development | PGlite on disk | `.env` dummy values | Engineers |
| staging | Managed PG + Redis + MinIO | staging secret manager | QA, pentest |
| production | Multi-AZ PG + Redis Cluster + S3 | production secret manager | Users |

Promotion: tag → CI → staging smoke → manual approval → production.

## Containers

```bash
docker build -f infrastructure/docker/Dockerfile.server -t ollo-server:$GIT_SHA .
```

Images are distroless/node, non-root, read-only root FS, signed with cosign
in CI. No secrets in layers.

## Kubernetes

Helm chart: `infrastructure/helm/ollo`.

```bash
helm upgrade --install ollo infrastructure/helm/ollo \
  --namespace ollo --create-namespace \
  -f infrastructure/helm/ollo/values-staging.yaml
```

Required values: `image.tag`, secret store refs, ingress host, S3, Redis, PG.

Probes: `/healthz` (liveness), `/readyz` (readiness — PG reachable).

HPA: CPU 60% / in-flight WS connections custom metric.

PDB: `minAvailable: 1` (staging), `minAvailable: 2` (prod).

## Terraform

`infrastructure/terraform` creates: VPC, AZs, RDS Postgres, ElastiCache
Redis, S3 bucket + lifecycle, IAM, EKS/GKE/AKS skeleton, coturn nodes.

Copy `terraform.tfvars.example` → `terraform.tfvars` (not committed).

## Secrets

Never in git. Injected as env from the platform:

- `DATABASE_URL`
- `REDIS_URL`
- `PHONE_HMAC_PEPPER`
- `SESSION_SIGNING_KEY`
- `OTP_PEPPER`
- `S3_*`
- FCM / APNs material
- `TURN_SECRET`

`OTP_DEV_REVEAL` is forced `false` when `NODE_ENV=production` in code, not
only in config.

## Migrations

Run as a Helm pre-install/pre-upgrade Job with a single replica:

```
node dist/migrate.js
```

Backward-compatible only. Expand/contract for breaking column changes.

## Zero / low downtime

- Rolling update, `maxUnavailable: 0`
- WS clients reconnect with resume tokens
- In-flight envelopes live in Postgres, not in pod memory
- Drain period 30s (`preStop` sleep + stop accepting new WS)

## Feature flags

`services/server/src/config.ts` + `config` table. Flags that weaken
security (`OTP_DEV_REVEAL`, plaintext push) cannot be enabled when
`OLLO_ENV=production`.
