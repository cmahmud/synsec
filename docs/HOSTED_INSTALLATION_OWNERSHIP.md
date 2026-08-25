# Hosted GitHub installation ownership

SynSec hosted collaboration must not infer tenant ownership from an installation id supplied by a browser, webhook, repository, or URL parameter. The hosted setup boundary requires two independent facts before an installation can be associated with a tenant:

1. the caller-owned authentication layer has already bound the current application principal to a specific GitHub user id; and
2. a user-scoped GitHub transport, using that same GitHub identity, confirms that the requested installation is currently accessible to the authenticated user.

`verifyAndClaimSynSecHostedGitHubInstallation()` enforces those checks and then asks an ownership store to atomically claim the installation for one hosted tenant. It accepts no GitHub access token directly. Credential acquisition, storage, refresh, revocation, and transport headers stay outside SynSec's ownership record and must remain in the trusted identity/secret-management layer.

## PostgreSQL tenant fence

`PostgresSynSecHostedInstallationOwnershipStore` provides the built-in transactional implementation. `installation_id` is the durable global fence. The first tenant claim wins; a competing tenant receives `conflict` and cannot overwrite the row. Re-verification by the same tenant is accepted only when the durable GitHub account id and account type still match. Account login and authenticating user churn are not allowed to transfer ownership.

`release(tenantId, installationId)` is compare-and-delete. A tenant cannot release another tenant's installation by knowing its numeric installation id.

Apply `migrateSynSecGitHubPostgresHostedInstallationOwnership()` before enabling hosted setup. Migrations are serialized with a transaction-scoped PostgreSQL advisory lock and contain no credentials.

## Required hosted setup sequence

The hosting application should perform this sequence:

1. authenticate the local application session and resolve its stable `subject`, `tenantId`, and GitHub user id;
2. obtain or refresh a GitHub **user-scoped** credential in the trusted identity layer;
3. construct a transport whose `getAuthenticatedUser()` and `getAccessibleInstallation()` calls use that same user identity;
4. call `verifyAndClaimSynSecHostedGitHubInstallation()` with the requested installation id;
5. only after `status: "verified"` may hosted application state refer to the tenant/installation association;
6. continue enforcing repository-level installation authorization from SynSec's installation state for every repository operation. Tenant ownership does not replace repository authorization.

Do not accept a GitHub login string, organization name, webhook payload, setup URL parameter, repository metadata, or installation id as ownership proof by itself.

## What successful evidence means

A successful result is labeled `authenticated-user-access-and-atomic-tenant-claim-only`. It means that, at verification time:

- the GitHub user returned by the user-scoped transport matched the GitHub user id bound to the authenticated hosted session;
- GitHub exposed the exact requested installation to that user;
- the installation was not reported suspended;
- the ownership store atomically accepted the tenant claim or found the same durable tenant/account identity already present.

It does **not** prove that the user is an organization owner, that GitHub access will remain valid, that every repository in the installation is authorized, that a route is runtime-protected, or that the hosted tenant should gain access to any other installation or repository. Those boundaries remain separate and must fail closed independently.

## Failure and disclosure behavior

GitHub transport and ownership-backend exceptions are reduced to categorical messages. Backend URLs, authorization headers, tokens, tenant data, SQL diagnostics, and GitHub response bodies must not be reflected to an untrusted client. The caller may log separately sanitized operational telemetry, but should not serialize raw upstream exceptions into hosted responses.
