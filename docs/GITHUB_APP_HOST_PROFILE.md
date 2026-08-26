# Secret-free GitHub App host profile

`@synsec/github/app-host-profile` defines the declarative configuration that may safely live in an operator-managed deployment file. It is intentionally **not** a credential bundle and is not runtime-readiness evidence.

The profile contains release/replica identity, App ID, the mounted credential directory, the **name** of the environment variable from which trusted hosting code obtains the PostgreSQL URL, listener settings, a repository workspace directory, an OCI runtime command, an immutable digest-pinned scanner image, and the protected operator-status path.

## Why the profile is exact-keyed

Unknown and missing fields are rejected. This prevents a convenient deployment JSON file from gradually accumulating `privateKey`, `webhookSecret`, `databaseUrl`, tokens, tenant metadata, or arbitrary backend payloads. Credential values remain in the existing mounted-credential boundary. The PostgreSQL URL remains in hosting/secret-manager state and the profile stores only its environment-variable name.

The credential directory and repository workspace must be absolute and non-overlapping so untrusted repository content cannot be placed underneath the credential tree. Scanner images must be pinned by `sha256` digest. The scanner runtime is one bounded command token, preventing a declarative profile from becoming a shell-command surface.

## Example

```json
{
  "releaseId": "synsec-v0.2.0+abcdef0",
  "replicaId": "github-app-01",
  "replicaCount": 3,
  "appId": 12345,
  "credentialDirectory": "/run/credentials/synsec-github",
  "postgresUrlEnvironment": "SYNSEC_POSTGRES_URL",
  "listenHost": "127.0.0.1",
  "port": 8787,
  "tlsMode": "terminated-upstream",
  "workspaceDirectory": "/var/lib/synsec/workspaces",
  "scannerRuntimeCommand": "/usr/bin/docker",
  "scannerImage": "ghcr.io/example/synsec-scanners@sha256:<64-hex-digest>",
  "operatorStatusPath": "/_synsec/operator/status"
}
```

The placeholder digest above is documentation only and will not pass validation until replaced by an actual immutable image digest.

## Hosting integration boundary

A systemd/Kubernetes/container host should:

1. read and validate this non-secret profile;
2. resolve `postgresUrlEnvironment` through its trusted secret/configuration mechanism without logging the resulting value;
3. load the fixed mounted credential files with `loadMountedGitHubAppRuntimeCredentialSnapshot()`;
4. migrate and compose the built-in PostgreSQL shared backend;
5. use the enforced OCI scanner process runner with the profile's pinned image/runtime;
6. mount the webhook endpoint behind TLS and protect the operator-status endpoint with an independent authenticated operator plane;
7. bind SIGTERM/SIGINT through the existing service-lifecycle/maintenance drain before process exit.

The environment-variable mechanism is a hosting integration boundary, not a recommendation to expose database credentials broadly in process environments. Operators should use the narrowest secret-manager/service-manager mechanism available and ensure untrusted scanners never inherit the host environment.

A successfully parsed profile carries `secret-free-host-wiring-contract-not-runtime-readiness`. Parsing does not prove files exist, PostgreSQL is reachable, migrations succeeded, GitHub accepted credentials, the service manager applied the intended sandbox, or the fleet is healthy.
