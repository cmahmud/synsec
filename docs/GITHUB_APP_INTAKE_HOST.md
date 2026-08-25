# GitHub App intake host

SynSec now ships an executable **webhook-intake host** for production-style PostgreSQL deployments:

```text
npm run github-app:intake-host -- \
  --profile /etc/synsec/github-app-host.json \
  --conformance /etc/synsec/postgres-conformance.json
```

For `tlsMode: "local"`, also provide `--tls-key <absolute-path>` and `--tls-cert <absolute-path>`. When TLS terminates at a trusted reverse proxy or load balancer, the profile must use `terminated-upstream` and the executable rejects local key/certificate arguments.

## Activation order

The host deliberately fails closed in this order:

1. Read bounded regular non-symlink profile and conformance JSON files.
2. Validate the exact-keyed secret-free host profile.
3. Validate that the canonical shared-state conformance report is complete and bound to the exact built-in PostgreSQL backend id and implementation version.
4. Resolve the PostgreSQL URL only from the environment-variable name declared by the profile. The connection value is never accepted in the profile or printed by the host.
5. Load the fixed-filename mounted GitHub App credential generation into the existing memory-only atomic credential source.
6. Run the serialized PostgreSQL migrations.
7. Compose PostgreSQL replay, installation-authorization, and scan-queue stores.
8. Wrap webhook intake in the enforced local admission-drain controller.
9. Start the bounded HTTP(S) listener.

Invalid conformance evidence and invalid TLS ownership fail **before** credential loading or database access.

## Credential mount

The `credentialDirectory` from the host profile uses the existing mounted credential contract:

- `generation`
- `private-key.pem`
- `webhook-secret`
- optional `webhook-secret-previous`

The directory and files must satisfy the existing regular-file, non-symlink, and byte-bound checks. SynSec does not write credentials back to this directory.

## PostgreSQL secret boundary

`postgresUrlEnvironment` is an environment-variable **name**, for example `SYNSEC_POSTGRES_URL`. Hosting or a service manager supplies the actual secret value:

```text
SYNSEC_POSTGRES_URL=postgresql://...
```

Do not place the connection value in the JSON profile, command line, repository, or logs. The executable validates only that a bounded PostgreSQL URL is present; PostgreSQL authentication and TLS policy remain operator-owned connection configuration.

## Shutdown

`SIGTERM` and `SIGINT` stop new webhook admission, wait for locally admitted webhook requests to finish, close the listener, and then close the PostgreSQL pool. Rejected requests receive the existing retryable drain response so GitHub can retry them.

This is **local intake drainage only**. It does not prove worker drainage, durable zero-lease state, fleet-wide maintenance eligibility, GitHub credential acceptance, repository authorization, or scanner completion.

## Role separation

This executable intentionally performs webhook intake and durable queue insertion only. It does not run scanner workers or hosted ownership re-verification sweeps. Keeping those roles separate prevents a webhook listener from silently expanding into scanner execution and allows intake and worker replica counts to be managed independently.

Workers must continue to use the fenced durable queue, authorization rechecks, enforced OCI scanner boundary, and their worker-drain/service-lifecycle controls. Service-wide upgrades still require the existing durable lease and upgrade gates.

## systemd example

A minimal deployment shape behind an HTTPS reverse proxy is:

```ini
[Unit]
Description=SynSec GitHub App intake
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/synsec
EnvironmentFile=/run/synsec/postgres.env
ExecStart=/usr/bin/npm run github-app:intake-host -- --profile /etc/synsec/github-app-host.json --conformance /etc/synsec/postgres-conformance.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=45
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/synsec

[Install]
WantedBy=multi-user.target
```

The service-manager sandbox above is an operator example, not a SynSec security attestation. Paths and permissions must be adapted to the actual deployment, and the reverse proxy must enforce HTTPS when the host profile declares `terminated-upstream`.

## Current packaging limitation

The executable is usable from a built repository/workspace, but a reproducible container image is still intentionally blocked by the repository's missing verified dependency lockfile. SynSec's strict release-readiness gate continues to report that blocker. Do not build a production image around unconstrained `npm install` and call it reproducible.
