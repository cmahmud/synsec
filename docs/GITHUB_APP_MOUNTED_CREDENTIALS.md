# GitHub App mounted runtime credentials

SynSec can load one operator-managed GitHub App credential generation from a fixed mounted directory and hand that snapshot directly to the existing memory-only runtime credential source.

The mount contract uses fixed filenames:

- `generation` — a non-secret generation identifier.
- `private-key.pem` — the GitHub App private key.
- `webhook-secret` — the currently active webhook verification secret.
- `webhook-secret-previous` — optional previous webhook secret during a bounded rotation overlap.

`loadMountedGitHubAppRuntimeCredentialSnapshot()` only reads an absolute operator-supplied directory. The directory and every credential file must be non-symlink filesystem objects of the expected type. File sizes are bounded before reads, filenames cannot be selected by repository or webhook data, and loader errors are categorical rather than reflecting paths or credential contents.

This is a vendor-neutral integration boundary for a supervisor, container-orchestrator secret mount, CSI driver, tmpfs handoff, or another operator-controlled mechanism. SynSec does not write credentials back to the mount and does not persist the returned snapshot.

## Runtime reload

A mounted snapshot is intended to be passed immediately to `createGitHubAppRuntimeCredentialSource()` or used as its `reload()` loader:

```ts
const credentials = createGitHubAppRuntimeCredentialSource(
  await loadMountedGitHubAppRuntimeCredentialSnapshot(secretDirectory),
);

await credentials.reload(
  () => loadMountedGitHubAppRuntimeCredentialSnapshot(secretDirectory),
);
```

The existing runtime source validates the generation, PEM framing, webhook-secret strength, and bounded two-secret rotation overlap before atomically replacing the active generation. Reloads serialize. A read or validation failure preserves the previous active generation.

Operators should publish a complete new mounted generation atomically at the secret-manager/service-manager boundary rather than modifying individual live files in place. SynSec's loader does not claim to make a sequence of external filesystem replacements transactional.

## Rotation sequence

For webhook-secret rotation, mount the new active secret and optionally retain the previous secret in `webhook-secret-previous`, reload the runtime generation, observe the existing fleet reload/freshness checks, confirm authenticated GitHub deliveries with the new credential, and only then retire the old secret according to the credential-rotation runbook.

For private-key rotation, mount the new private key under a new generation, reload the runtime generation, verify a fresh installation-token exchange, and only then retire the old GitHub App key. A successful mounted-file read or in-process reload is not proof that GitHub accepted or activated a credential.

## Isolation boundary

Do not mount the credential directory inside a repository checkout, scanner workspace, OCI scanner mount, report directory, or durable SynSec shared state. Scanner execution must remain credential-free. The mounted source is for the trusted GitHub App runtime/supervisor boundary only.

The loader deliberately rejects symlink-shaped secret files even though some secret-management products implement rotation through symlink trees. Supporting such a provider requires a separate adapter with an explicit trust model rather than silently weakening this portable filesystem boundary.
