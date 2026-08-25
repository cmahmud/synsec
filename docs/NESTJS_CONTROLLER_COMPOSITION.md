# NestJS controller composition

SynSec can derive bounded structural route evidence from a deliberately narrow subset of NestJS controller syntax. This improves repository-first correlation without treating decorators as proof of runtime behavior.

## Accepted structure

The analyzer requires one-line, unaliased named imports from `@nestjs/common`. It recognizes literal or empty `@Controller(...)` prefixes on class declarations and literal or empty `@Get`, `@Post`, `@Put`, `@Patch`, `@Delete`, `@Options`, and `@Head` decorators on immediate class methods.

For example, `@Controller("admin")` plus `@Post("run")` produces the structural route `/admin/run`. The resolved class method is added to the bounded lexical call graph so an exact sink located inside that method can participate in the same route-to-sink correlation used by other supported frameworks.

`@UseGuards(SessionGuard, AdminGuard)` is retained only when every argument is a plain identifier and `UseGuards` itself is an unshadowed direct import from `@nestjs/common`. Guard evidence is labeled `structural-nestjs-guard-attachment-not-runtime-protection`.

## Fail-closed cases

SynSec deliberately emits no NestJS composition evidence when the required syntax is ambiguous. Unsupported cases include dynamic controller or route paths, aliased or shadowed NestJS decorators, malformed/unbounded class or method bodies, multiple HTTP decorators for one method, decorator factories, and guard expressions such as `AuthGuard("jwt")`.

Files are subject to the same repository-root, regular-file, non-symlink, source-size, file-count, and output bounds as the aggregate route-flow analysis.

## Security interpretation

This layer is static repository evidence only. It does **not** prove that NestJS discovers or instantiates a controller, that a module imports it, that a route is externally reachable, that a guard executes, that a guard permits or denies a request, or that a finding is exploitable.

In particular, an auth-looking guard name is never treated as proof of authentication or authorization. Guard attachment is surfaced for review context only. Runtime claims require independent runtime or deployment evidence.
