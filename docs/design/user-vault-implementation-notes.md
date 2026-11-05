---
summary: "User vault implementation map, authority boundaries, decisions, and verification evidence"
read_when:
  - Implementing the opt-in personal user vault
title: "User vault implementation notes"
---

# User vault implementation notes

## Scope and baseline

This work targets `fetzig/openclaw`, branch `feat/personal-vault-worker-exec`,
on dispatched base `a4297e5af3c40d2222c911ba03b09e001e1c8ac3`. No rebase,
PR, issue, or production Gateway changes are authorized. The implementation
is an explicit user-opted exception to the team secret-store isolation described
in the Codex harness documentation: personal values may reach command processes,
but must never reach model-facing context or a Codex app-server process.

GitHub prerequisite: the managed `github_identity_status` tool reports an available
GitHub-API-verified `fetzig` identity with `repo` scope. The initial bare GitHub CLI lacked
authentication; subsequent checks on 2026-11-04 and in the restored checkout on
2026-11-05 returned `fetzig` and repository push permission `true` (both exit 0).
`git push --dry-run origin HEAD:feat/personal-vault-worker-exec` succeeded. The
identity tool reports repository grants as unknown; the dry-run is transport
evidence, not a repository permissions API result. Actual pushes will be verified
against the remote ref after each commit.

## Components 1–6: implementation map

| Component                    | Existing owner and implementation seams                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Required proof                                                                                                                                                                                                                                                                                                                 |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1. Personal storage and CRUD | `src/state/user-model-accounts.ts` owns the identity-scope owner-resolution pattern; `src/state/user-model-account-operations.ts` demonstrates off-thread operations and current-authority admission. Add a dedicated vault store/operations module, not another team-store scope. `src/gateway/server-methods/personal-profile-authorization.ts:preparePersonalProfileAction` supplies self-only verified human authority. Register methods in `src/gateway/methods/core-descriptors.ts` and the core/lazy handler owners. `ui/src/pages/profile/profile-page.tsx` hosts the User vault section; reuse form/reveal affordances from `ui/src/pages/secrets/` and `ui/src/components/secret-reveal-dialog.tsx`.                                                                                                                                                                                                                                                                                                                                                                                                                            | Alice/Bob isolation; metadata-only replies; prefix exclusion; hard deletion; reserved-name and byte-limit rejection; non-admin self access.                                                                                                                                                                                    |
| 2. Configuration             | `src/config/zod-schema.core.ts:SecretsConfigSchema`, `src/config/types.secrets.ts`, and the owning `src/config/schema.help.*` map. Add enabled, exposureTtl, maxEntries, maxBytes without materializing unrelated defaults.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Accepted defaults and zero TTL; invalid sizes/durations rejected; disabled feature blocks reads and mutations and hides UI.                                                                                                                                                                                                    |
| 3. Exposure UI and state     | Add one Gateway-memory exposure owner keyed by scoped session identity and canonical profile ID. `ui/src/pages/chat/components/chat-details-session.tsx`/Details hosts and chat composer consume one participant-safe session-state projection. An RPC uses the same personal-profile authority as CRUD and existing session access checks.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Only the human changes their own state; restart/reset/archive/delete clear state; other participants see holder/mode, never secret names or values; composer warning.                                                                                                                                                          |
| 4. Lifecycle                 | `src/sessions/session-controller.mailbox.ts:reserveOrJoinSessionControllerSource` is the common admission seam. Consume admitted source principal and operator authority, including steers and queued inputs. Bind once at actual turn start, revoke at admission for another human, consume turn mode at turn settlement. Use `src/cron/execution-context.ts:resolveScheduledPrincipal` for automation ownership. Profile changes invalidate grants, following `src/gateway/worker-environments/worker-github-binding.ts`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Prompt/steer/queue breaker; unverified sender; internal completion versus automation semantics; expiry, cancellation, loss of authority; no delegated-session inheritance.                                                                                                                                                     |
| 5. Names-only awareness      | `src/agents/tools/secrets-tool.ts` gains optional team/user scope without changing default team calls. Follow `src/plugins/requester-models.ts` for a bound read-only names reader with current-authority checks. Extend normal runtime-context preparation and `WorkerRuntimeContextFragmentsSchema` with a names-free count/mode hint.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | User list returns empty values and own names only; mutations rejected; automated/child sessions lack names/hint; no extra admin RPC.                                                                                                                                                                                           |
| 6. Command execution         | `src/agents/bash-tools.exec-request-preparation.ts:resolvePreparedExecEnvironment` and `src/agents/bash-tools.exec-run.ts` own execution-only injection. Carry a separate prepared grant through `ExecToolDefaults`/core tools. Sandbox backend `buildExecSpec`, Docker env-file staging, remote-shell staging, and `src/agents/sandbox/sanitize-env-vars.ts` preserve private delivery. `src/gateway/worker-environments/worker-turn-execution.ts` binds worker snapshots; `src/worker/launch-descriptor.ts`, `src/worker/worker-placement-tools.ts:createWorkerPlacementTools`, heartbeat and protocol owners carry revocable worker grants. `src/agents/bash-tools.exec-host-node-phases.ts`, host-env policy and node command handling carry a private capability-gated system.run field. `src/node-host/node-worker-workspace-admission.ts` and `src/plugins/types.node-host.ts` carry remote-exec grants; `extensions/codex/src/node-exec-server.runtime.ts` applies them only at command spawn. `extensions/acpx/src/service.ts` and its process owner carry explicit child grants and invalidate children before next-turn reuse. | Every launch checks authority; approval/requestedEnv and argv exclude values; per-call > vault > team, launcher/binding wins; durable launch; sandbox TOKEN names; worker heartbeat/monotonic deadline; node capability warnings; native Codex routes via gateway_exec; no app-server injection; ACP context survives respawn. |

## Reconciled requirements and design decisions

- The introductory plan says to rebase from an older reference. The ground rules
  and implementation section override that: retain the exact dispatched base.
- The plan mentions an issue/design note. Only this design note is authorized;
  never create the issue or a PR.
- Reuse the existing host-env denylist without vault-specific additions. The dispatched base
  already blocks `GH_TOKEN`/`GITHUB_TOKEN` as override-only keys in
  `src/infra/host-env-security-policy.json`, contradicting the plan’s example.
  Preserve that existing policy: those names are rejected, without adding any
  vault-only denylist entries. Binding/launcher precedence still applies to
  otherwise accepted keys.
- Existing prepared exec logic includes team-store values in `requestedEnv`. Do
  not reuse that carrier for vault values: introduce an execution-only layer and
  preserve the team-store behavior unchanged.
- Both Codex node exec-server and node app-server currently consume lease
  `processEnvironment`. Adding vault values to that shared callback would violate
  the plan. Use an explicitly command-spawn-only grant; leave existing GitHub
  process-environment behavior unchanged.
- Reject incompatible worker builds when a vault would be bound. Missing node
  capability instead means no vault and a visible warning, never another route.
- Profile merges must use the existing canonical owner resolution, without
  treating stranded merged profile tombstones as secret owners.
- Secret limits are UTF-8 value bytes, including replacement accounting inside
  the write transaction. Entry names are validated environment identifiers.
- The exposure owner is memory-only; persistent vault CRUD reuses existing SQL
  schema and worker admission. Do not introduce a schema migration or sidecar.
- Scope exposure by the session store/target as well as session identity to avoid
  accidental cross-agent/store key collisions. UI events contain holder display
  identity and mode/expiry, not entry names or values.
- Values containing NUL bytes are rejected because process environments cannot
  represent them. This is value validation, not a vault-specific name denylist.
- Snapshots are per binding. An edit does not modify an already bound turn.
  Revocation blocks future launches but does not kill or scrub running processes.

## Ordered implementation and evidence ledger

After this mapping commit, implementation follows the eight requested commits:

1. Storage, RPCs, config, Settings UI.
2. Exposure owner, Details/indicator/warning, admission breaker.
3. Shared injection and Gateway grant, including sandbox/durable.
4. Worker launch/heartbeat/expiry/protocol.
5. Node system.run private field/capability.
6. Codex native routing and remote-exec command-spawn lease.
7. ACP child grants/respawn.
8. Names-only secrets scope and runtime hint.

Each commit requires focused tests and targeted checks before push. Keep test
outputs in excluded caches or outside the checkout. No implementation or live
acceptance result is implied by this mapping.

Known infrastructure to check before proof: a disposable two-user authenticated
Gateway, Docker, durable systemd support, paired nodes, a cloud worker, Codex
remote-exec, and ACP. The required sibling Codex source checkout is not currently
present beside this checkout; inspect the matching source before Codex behavior
changes. Missing infrastructure must be reported as an untested gap, not a pass.

## Security documentation to ship with behavior

Personal values are unencrypted at rest and readable by host administrators.
Values reach selected command hosts/devices and less-trusted sandboxes. Printed
values are not transcript-masked. CLI-written credential files persist beyond
revocation for later turns/users. Durable exec stores launch environment in
systemd unit properties readable by the Gateway Unix user. Existing processes
retain their environment after expiry/revocation. Devices sharing a verified
profile are one user. These limits must be visible in the user-facing vault page.

## Review and recovery status (2026-11-05)

Independent review: **not performed**. Klemens explicitly authorized proceeding
without independent review for these fork commits. Nix will review the pushed
commits with Opus; that future review is not claimed as completed evidence.
No reviewer agents, PRs, issues, or production changes have been created.

The restored checkout contained all 24 uncommitted commit-1 files. Its local
HEAD had reverted to the dispatched base, while the remote retained design
commit `726b79354db87eabe114e47d2c8a1a56226dc78d`. Restored that existing
ancestry without rebasing or rewriting remote history; SHA-256 checks verified
all 24 working-file contents were unchanged. Previous interrupted build and
typecheck commands have no live sessions in this restored worker. Their final
results are unknown and are not counted as passes. Re-run focused checks here.

Commit 1 implements storage, self-only metadata/write/delete RPCs, config and
help, and the Profile vault section. Exposure and execution injection are not
yet implemented, and no live end-to-end acceptance claim is made.

### Commit-1 verification in restored checkout

- Focused backend tests: 101 passed across seven files (vault/model-account
  storage, RPC authorization, config, method discovery, and profile policies).
- Profile and vault UI regressions: 28 passed across two files.
- `pnpm tsgo:core` and `pnpm tsgo:ui`: passed.
- Focused core and UI oxlint: passed, zero warnings/errors. The pinned Bun
  download was unavailable; the repository-supported Node/oxlint fallback ran.
- Formatting and `git diff --check`: passed.
- `pnpm build:runtime`: completed with exit 0, including runtime source checks,
  bundling, CLI import guard, plugin assets, and UI build. The UI asset report
  reported advisory violations for startup JS, total CSS, chat boot JS, and new
  boot JS. These are not claimed clean or attributed to this change without a
  base comparison. The full declaration/package build was not re-run.
- These are unit/synthetic/static/build results, not live two-user acceptance.
  Before/after UI screenshots and the end-to-end execution matrix remain open.

The pre-commit freshness gate initially refused the commit because the restored
checkout has no `origin/main` and the intentional config surface grew by five
paths. Used the supported `PROTOCOL_SINCE_BASE_SHA` override with the exact
dispatched base, not a newer upstream reference. `pnpm protocol:check` passed
for all three new methods. Ran `pnpm config:docs:gen` and its check; the generated
core count increases from 2586 to 2591 for the requested `secrets.userVault`
container plus enabled, exposureTtl, maxEntries, and maxBytes. Channel/plugin
budgets are unchanged. This intentional growth supports the explicitly
requested opt-in feature and per-user limits; no unrelated config was removed
to hide the increase. Only the small tracked count/hash artifacts are committed.
