# 2026-08-14 ACP authentication, config hardening, and workflow kill-switch

## Context

A security review of the DeepSeek Harness identified four vulnerability surfaces:

1. **ACP server no-auth** — the Agent Client Protocol server (`packages/acp/acp/src/index.ts`) accepted unauthenticated connections by default, allowing any client on the local transport to start sessions and drive agent prompts.
2. **Windows ACL hard-link alias** — NTFS ACLs bind to file objects, not pathnames; an inheritable workspace write-SID ACE propagated to an existing hard link grants write access through the external alias.
3. **`!!js` config execution** — `cordis.yml` and patch files allow `!!js` tagged scalars that evaluate against the runtime context; when sourced from untrusted config paths this is arbitrary code execution.
4. **Workflow VM trust** — model-written orchestration scripts run in a `vm` context on a worker thread; the trust boundary relied on VM isolation alone with no process-level kill switch.

## Decision

For each surface, the resolution is:

- **ACP**: add an optional `authToken` config field. When set, `initialize()` advertises `authMethods: ['bearer']` and `authenticate()` validates `Authorization: Bearer <token>` with constant-time comparison. All RPC methods (`newSession`, `prompt`, `cancelSession`/`cancel`) call `assertAuthenticated()` before proceeding. When `authToken` is absent, behavior is unchanged (no auth) to preserve the existing headless/automation use case where transport isolation is already in practice. The kill switch is defense-in-depth, not a substitute for transport isolation.

- **Windows ACL hard link**: this is an inherent NTFS limitation already documented in `sandbox-windows-acl/README.md` Known Limitations (line 76) and pinned by the native runner test `runner.spec.ts:414`. No code change is warranted — rejecting every multiply-linked file would break common pnpm workspace layouts. The provider reports `enforcement: 'partial'` and the model-facing docs name the consequence.

- **Config `!!js`**: add a `DSH_DISABLE_JS_CONFIG=1` environment variable that swaps the YAML schema to `JSON_SCHEMA` (no custom tags) in both `parsePatchList` and `renderConfigDump`. This is an opt-in hardening for deployments that process config from untrusted paths; the default retains `!!js` support for the patch-layer use case documented in the existing config loader.

- **Workflow VM**: add a `DSH_DISABLE_WORKFLOWS=1` environment variable checked at `start()` in `WorkerThreadWorkflowEngine` (`packages/workflow/workflow-worker-thread/src/index.ts`). When set, `start()` throws `WorkflowError('workflow execution is disabled by DSH_DISABLE_WORKFLOWS=1', 'AGENT_START')` before any worker is spawned. This is a deployment-level kill switch for environments where model-authored untrusted scripts must not be evaluated. The existing VM isolation (`vm.createContext({})`, a fresh worker thread per run, `syncTimeoutMs`, and a cancellation grace timer with forced worker termination) remains the primary control.

## Consequences

- ACP clients that previously connected without auth will continue to work when `authToken` is unset; deployments that set `authToken` must call `authenticate()` with the matching bearer token.
- `DSH_DISABLE_JS_CONFIG=1` makes any `!!js` tag in a patch file a parse error; deployments using JS config expressions must not set this.
- `DSH_DISABLE_WORKFLOWS=1` makes `workflow_engine.start()` reject every invocation; the tool surface that depends on it should detect the `AGENT_START` error and degrade gracefully.
- The Windows hard-link boundary requires no change and remains a documented partial-enforcement edge.

## Test Coverage

- `packages/acp/acp/tests/bridge.spec.ts`: three new cases — `initialize()` advertises `authMethods: ['bearer']` when configured; unauthenticated `newSession()` rejects with "authentication required"; successful `authenticate()` then `newSession()` succeeds.
- Manual verification of `DSH_DISABLE_JS_CONFIG` and `DSH_DISABLE_WORKFLOWS` kill switches in the relevant packages.

## Tag

Proposed for implementation in the first tagged release cycle.
