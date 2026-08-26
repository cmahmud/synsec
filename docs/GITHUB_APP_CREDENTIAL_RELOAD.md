# GitHub App runtime credential reload

SynSec can now keep GitHub App credentials in a validated, memory-only generation that is atomically replaced without reconstructing the webhook handler or installation-token provider.

## Integration boundary

`createGitHubAppRuntimeCredentialSource()` accepts an initial credential snapshot and exposes a `reload()` callback boundary. The callback is where hosting code may read from an operator-approved secret manager, mounted credential file, supervisor IPC channel, or equivalent deployment mechanism. SynSec does not implement vendor-specific secret retrieval, write credentials to durable state, or send credentials to scanners.

A snapshot contains the App private key, one webhook secret or a two-secret rotation overlap, and a bounded non-secret generation identifier. Status surfaces only the generation, webhook-secret count, and successful reload count.

## Safe rollout sequence

For a webhook-secret rotation, publish a generation containing `[new, previous]`, reload each application replica, and use the existing credential-reload assessment to verify that every expected replica reports the target generation and is ready. Only after that observation should the operator update GitHub to the new secret and later publish a second generation containing only the new secret. Reload all replicas again before retiring the previous value from the external secret manager.

For a private-key rotation, provision the replacement key in the external secret source, publish a new generation, reload replicas, and verify the complete replica set before revoking the previous key in GitHub. A generation match is deployment evidence only; it is not proof that GitHub accepted the credential.

## Failure behavior

Reload operations are serialized within a process. The candidate generation is fully validated before the active snapshot changes. Loader or validation failure leaves the previous credential generation active. Reusing the currently active generation is rejected so a supervisor cannot accidentally report progress without changing deployment metadata.

The webhook HTTP path resolves its current secret immediately before signature verification. The installation-token provider resolves its current private key immediately before each App JWT signature. If either supplier fails, the operation fails closed rather than silently using an empty credential or persisting a fallback.

## Service-manager orchestration

A service manager should treat secret material and reload signaling as separate concerns:

1. Stage the new secret material with restrictive filesystem/secret-manager permissions outside repository workspaces and scanner sandboxes.
2. Atomically update the external secret source or mounted secret projection.
3. Trigger application-owned reload logic that calls the credential source's `reload()` method.
4. Read only secret-free generation/readiness status from each replica.
5. Use SynSec's deployment-wide reload assessment before moving to the credential-revocation step.

Do not pass private keys, webhook secrets, GitHub tokens, database credentials, host control sockets, or durable SynSec state into scanner containers. Do not place credential files beneath the repository workspace tree.

## Security interpretation

Successful reload means the process validated and activated the supplied in-memory generation. It does not attest the external secret manager, prove GitHub-side activation, prove replica health beyond the operator's readiness signal, or authorize any repository operation. Existing installation authorization and least-privilege token checks remain separate trust boundaries.
