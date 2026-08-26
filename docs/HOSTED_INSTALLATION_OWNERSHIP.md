# Hosted GitHub installation ownership

SynSec hosted collaboration must not infer tenant ownership from an installation id supplied by a browser, webhook, repository, or URL parameter. The hosted setup boundary requires two independent facts before an installation can be associated with a tenant:

1. the caller-owned authentication layer has already bound the current application principal to a specific GitHub user id; and
2. a user-scoped GitHub transport, using that same GitHub identity, confirms that the requested installation is currently accessible to the authenticated user.

`verifyAndClaimSynSecHostedGitHubInstallation()` enforces those checks and then asks an ownership store to atomically claim the installation for one hosted tenant. It accepts no GitHub access token directly. Credential acquisition, storage, refresh, revocation, and transport headers stay outside SynSec's ownership record and must remain in the trusted identity/secret-management layer.

## PostgreSQL tenant fence

`PostgresSynSecHostedInstallationOwnershipStore` provides the built-in transactional implementation. `installation_id` is the durable global fence. The first tenant claim wins; a competing tenant receives `conflict` and cannot overwrite the row. Re-verification by the same tenant is accepted only when the durable GitHub account id and account type still match. Account login and authenticating-user churn cannot transfer ownership.

`release(tenantId, installationId)` is compare-and-delete. A tenant cannot release another tenant's installation by knowing its numeric installation id. Normal access revocation does **not** call `release()`: the durable tenant fence remains present so loss of GitHub access cannot make the installation claimable by a different hosted tenant.

Apply `migrateSynSecGitHubPostgresHostedInstallationOwnership()` before enabling hosted setup. Migrations are serialized with a transaction-scoped PostgreSQL advisory lock and contain no credentials. The additive re-verification migration backfills existing `verified_at` state from the original claim timestamp; a configured freshness gate therefore naturally denies sufficiently old pre-upgrade claims until they are re-verified.

## Required hosted setup sequence

The hosting application should perform this sequence:

1. authenticate the local application session and resolve its stable `subject`, `tenantId`, and GitHub user id;
2. obtain or refresh a GitHub **user-scoped** credential in the trusted identity layer;
3. construct a transport whose `getAuthenticatedUser()` and `getAccessibleInstallation()` calls use that same user identity;
4. call `verifyAndClaimSynSecHostedGitHubInstallation()` with the requested installation id;
5. only after `status: "verified"` may hosted application state refer to the tenant/installation association;
6. continue enforcing repository-level installation authorization from SynSec's installation state for every repository operation. Tenant ownership does not replace repository authorization.

Do not accept a GitHub login string, organization name, webhook payload, setup URL parameter, repository metadata, or installation id as ownership proof by itself.

## Periodic and revocation-aware re-verification

A one-time setup proof is not durable authorization evidence. Hosted deployments should periodically call `reverifySynSecHostedGitHubInstallation()` with the same authenticated hosted principal and a freshly usable user-scoped GitHub transport.

The PostgreSQL store implements this as a fenced multi-replica protocol:

1. `beginReverification()` atomically increments a durable `verification_epoch` for the exact tenant, installation, and currently recorded proof user;
2. GitHub identity and installation access are checked outside the database transaction;
3. `finishVerified()` or `finishRevoked()` applies the observation only when that epoch is still current;
4. if another replica started a newer check first, the older completion returns `stale` and cannot overwrite newer authorization state.

This fencing is important because a slow negative GitHub response must not be able to revoke a newer successful verification, and a slow positive response must not reactivate a newer revocation.

Definitive observations that the exact installation is inaccessible, suspended, or now represents a different durable GitHub account identity set `access_status = 'revoked'`. Revocation retains the tenant fence and records only a categorical reason. A later successful verification by the same durable tenant/proof identity can reactivate access.

Transport exceptions are **not** converted into revocation evidence. Network failures, rate limits, GitHub outages, and secret-manager failures can be transient and do not prove access loss. Instead, hosted authorization should call `isSynSecHostedInstallationFreshlyAuthorized()` (or the store's equivalent gate) with an operator-selected bounded maximum age. PostgreSQL evaluates freshness using database time and returns false when the claim is revoked or its last successful verification is too old. This gives transient failures a bounded grace period while still failing closed after evidence becomes stale.

A new authenticated GitHub user for the same hosted tenant cannot use the periodic path to revoke the previous proof. The tenant must first pass the full setup verification/claim path successfully; that operation can update the recorded proof user without moving the installation to another tenant and supersedes older in-flight re-verifications.

## What successful evidence means

Initial setup evidence is labeled `authenticated-user-access-and-atomic-tenant-claim-only`. It means that, at verification time:

- the GitHub user returned by the user-scoped transport matched the GitHub user id bound to the authenticated hosted session;
- GitHub exposed the exact requested installation to that user;
- the installation was not reported suspended;
- the ownership store atomically accepted the tenant claim or found the same durable tenant/account identity already present.

Periodic evidence is separately labeled `fresh-user-access-and-fenced-durable-reverification-only`. It additionally means that the observation won the current durable verification epoch. It does **not** prove that the user is an organization owner, that GitHub access will remain valid, that every repository in the installation is authorized, that a route is runtime-protected, or that the hosted tenant should gain access to any other installation or repository. Those boundaries remain separate and must fail closed independently.

## Failure and disclosure behavior

GitHub transport and ownership-backend exceptions are reduced to categorical messages. Backend URLs, authorization headers, tokens, tenant data, SQL diagnostics, and GitHub response bodies must not be reflected to an untrusted client. The caller may log separately sanitized operational telemetry, but should not serialize raw upstream exceptions into hosted responses.

Periodic scheduling remains a hosting concern. SynSec supplies the fenced operation and freshness gate; it does not claim that a scheduler ran, that GitHub accepted any credential beyond the observed request, or that a successful ownership check replaces repository-level authorization.
