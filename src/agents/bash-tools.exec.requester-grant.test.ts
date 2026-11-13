import { randomUUID } from "node:crypto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createQueueTestRun } from "../auto-reply/reply/queue.test-helpers.js";
import { reserveSteerCandidate } from "../auto-reply/reply/queue/enqueue.js";
import { clearFollowupQueue } from "../auto-reply/reply/queue/state.js";
import type { FollowupRun } from "../auto-reply/reply/queue/types.js";
import {
  bindReplySourceToFollowup,
  prepareReplySourceInput,
} from "../auto-reply/reply/reply-source-binding.js";
import { registerChatAbortController } from "../gateway/chat-abort.js";
import { isSecretValueRegisteredForRedaction } from "../logging/secret-redaction-registry.js";
import type { SpawnInput } from "../process/supervisor/types.js";
import { withSessionTurn } from "../sessions/session-controller.admission.js";
import {
  beginSessionControllerSourceInjection,
  bindSessionControllerSource,
  claimSessionControllerInput,
  holdSessionControllerSourceWithdrawal,
  releaseSessionControllerClaim,
  retargetSessionControllerSource,
  retireSessionControllerInput,
  type SessionControllerInput,
  type SessionControllerMailboxClaim,
} from "../sessions/session-controller.mailbox.js";
import { captureSessionTarget, type SessionTarget } from "../sessions/session-controller.target.js";
import {
  createAdmittedRunOperatorAuthority,
  prepareSystemAgentRunAdmission,
  resolvePreparedRunAdmission,
} from "./admitted-run-context.js";
import { resetProcessRegistryForTests } from "./bash-process-registry.test-support.js";
import type { CapturedEnvironment } from "./bash-tools.exec-env.test-support.js";
import { runExecFixture } from "./bash-tools.exec-fixture.test-support.js";
import { runtimeManagedRun } from "./bash-tools.exec-runtime.test-support.js";
import { createOperationalRunInstanceRef } from "./operational-run-instance.js";
import {
  disableRequesterGrant,
  enableRequesterGrantForTest,
  readRequesterGrantHoldersForTest,
  resetRequesterGrantsForTest,
  setRequesterGrantValueProviderForTest,
  type RequesterGrantMode,
} from "./requester-grants.js";
import type { ExtensionContext } from "./sessions/index.js";
import { withGatewayToolCallerIdentity } from "./tools/gateway-caller-context.js";

const mocks = vi.hoisted(() => ({
  hookRunner: undefined as
    | {
        hasHooks: (name: string) => boolean;
        runResolveExecEnv: ReturnType<typeof vi.fn>;
        runBeforeToolCall: ReturnType<typeof vi.fn>;
      }
    | undefined,
  gatewayParams: [] as CapturedEnvironment[],
  nodeHostParams: [] as CapturedEnvironment[],
  spawnInputs: [] as Array<{ env?: Record<string, string> }>,
  /** Runs inside the final synchronous spawn boundary, before the native launch. */
  beforeNativeSpawn: undefined as (() => void) | undefined,
  durableInputs: [] as Array<{ env?: Record<string, string> }>,
}));

vi.mock("../plugins/hook-runner-global.js", () => ({
  getGlobalHookRunner: () => mocks.hookRunner,
  getGlobalHookRunnerRegistry: () => null,
}));
// mock-isolation: Keep the host login shell out of synthetic environments.
vi.mock("../infra/shell-env.js", async () =>
  (await import("./bash-tools.exec-env.test-support.js")).shellEnvironmentMock(),
);
// mock-isolation: Capture the prepared requestedEnv; the direct path then launches through runExecProcess.
vi.mock("./bash-tools.exec-host-gateway.js", async () =>
  (await import("./bash-tools.exec-env.test-support.js")).gatewayEnvironmentMock(mocks),
);
// mock-isolation: Durable launches are captured instead of reaching systemd.
vi.mock("./bash-process-durable.js", () => ({
  startDurableExecProcess: async (_session: unknown, _id: unknown, input: SpawnInput) => {
    mocks.durableInputs.push({
      env: input.env ? { ...(input.env as Record<string, string>) } : {},
    });
    return runtimeManagedRun(input);
  },
}));
// mock-isolation: Record spawn environments and run the final synchronous checks without launching.
vi.mock("../process/supervisor/index.js", () => ({
  getProcessSupervisor: () => ({
    spawn: async (input: SpawnInput) => {
      await Promise.resolve();
      mocks.beforeNativeSpawn?.();
      input.assertCurrent?.();
      mocks.spawnInputs.push({
        env: input.env ? { ...(input.env as Record<string, string>) } : {},
      });
      return runtimeManagedRun(input, "ok\n");
    },
    cancel: vi.fn(),
    cancelScope: vi.fn(),
  }),
}));

let createExecTool: typeof import("./bash-tools.exec-run.js").createExecTool;
let toToolDefinitions: typeof import("./agent-tool-definition-adapter.js").toToolDefinitions;

const AGENT = "main";
const SESSION = "agent:main:dashboard:vault";
const STORE = "/synthetic/requester-grant/sessions";
const OTHER_STORE = "/synthetic/requester-grant/other-sessions";
const KEY = "VAULT_TEST_TOKEN";
let value: string;
let logs: string[];

const authority = (profileId: string) =>
  createAdmittedRunOperatorAuthority({ profileId, scopes: [], assertCurrent: () => {} });
const target = (overrides: { agentId?: string; storeScope?: string } = {}) =>
  captureSessionTarget({
    storeScope: overrides.storeScope ?? STORE,
    sessionKey: SESSION,
    agentId: overrides.agentId ?? AGENT,
  });
const grant = (holder: string, mode: RequesterGrantMode = "full-session", extra = {}) =>
  enableRequesterGrantForTest({
    holderProfileId: holder,
    target: { storeScope: STORE, agentId: AGENT, sessionKey: SESSION },
    mode,
    ...extra,
  });

/** One admitted turn: a fresh run ref, created now (its sequence orders it after earlier grants). */
const turn = (profileId: string | undefined, agentId = AGENT) => ({
  agentId,
  sessionKey: SESSION,
  operationalRunInstance: createOperationalRunInstanceRef(`run-${randomUUID()}`),
  ...(profileId ? { operatorAuthority: authority(profileId) } : {}),
});

/** Launches one command through runExecProcess as the given turn; returns every observable surface. */
async function launch(
  caller: ReturnType<typeof turn>,
  overrides: Parameters<typeof runExecFixture>[0] = {},
) {
  const warnings: string[] = [];
  const transportEnvs: unknown[] = [];
  const before = mocks.spawnInputs.length + mocks.durableInputs.length;
  const run = await withGatewayToolCallerIdentity(caller, () =>
    runExecFixture({
      env: { BASE: "1" },
      warnings,
      sessionKey: SESSION,
      agentId: caller.agentId,
      requesterGrant: { storeScope: STORE },
      approvalTransport: {
        assertExecution: (request: unknown) => transportEnvs.push(request),
      } as never,
      ...overrides,
    }),
  );
  const outcome = await run.promise;
  const spawned = [...mocks.spawnInputs, ...mocks.durableInputs].slice(before);
  return {
    env: spawned.at(-1)?.env ?? {},
    warnings,
    surfaces: {
      warnings,
      outcome,
      session: { command: run.session.command, aggregated: run.session.aggregated },
      approvalTransport: transportEnvs,
      logs,
    },
  };
}

/** The value may appear only in the spawned process env, never in any other channel. */
function expectNoLeak(surfaces: Record<string, unknown>) {
  for (const [name, surface] of Object.entries(surfaces)) {
    expect(JSON.stringify(surface) ?? "", `${name} leaked the grant value`).not.toContain(value);
  }
}

const inputs: SessionControllerInput[] = [];
const claims: SessionControllerMailboxClaim[] = [];
const injections: ReturnType<typeof beginSessionControllerSourceInjection>[] = [];
const registrations: Array<{ cleanup(): void }> = [];
const holders = (storeScope = STORE) =>
  readRequesterGrantHoldersForTest({ storeScope, agentId: AGENT, sessionKey: SESSION });

/** Runs the exec tool inside a session turn of the given store, as an agent turn does. */
async function execToolInTurn(
  caller: ReturnType<typeof turn>,
  params: Record<string, unknown>,
  storeScope = STORE,
) {
  const tool = createExecTool({ host: "gateway", security: "full", ask: "off" });
  const [definition] = toToolDefinitions([tool], { agentId: AGENT, sessionKey: SESSION });
  return await withSessionTurn(
    { sessionKey: SESSION, sessionId: "vault-session", agentId: AGENT, storePath: storeScope },
    () =>
      withGatewayToolCallerIdentity(caller, () =>
        definition!.execute(
          `call-${randomUUID()}`,
          { yieldMs: 120_000, ...params },
          undefined,
          undefined,
          {} as ExtensionContext,
        ),
      ),
  );
}

/** A channel prompt or follow-up from one sender: reserved by real reply ingress, then bound (not claimed). */
async function queue(profileId: string | undefined, sessionTarget?: SessionTarget) {
  const operatorAuthority = profileId ? authority(profileId) : undefined;
  const { options, input } = await prepareReplySourceInput(
    { SessionKey: SESSION },
    { session: { store: STORE } },
    operatorAuthority ? { operatorAuthority } : undefined,
  );
  if (!input) {
    throw new Error("reply ingress reserved no input");
  }
  inputs.push(input);
  if (sessionTarget) {
    // As a native command does when it resolves another agent's session as its target.
    retargetSessionControllerSource(input, sessionTarget, "command-target");
  }
  const run = createQueueTestRun(
    { prompt: "hi", ...(operatorAuthority ? { operatorAuthority } : {}) },
    {
      agentId: sessionTarget?.agentId ?? AGENT,
      sessionKey: SESSION,
      config: { session: { store: sessionTarget?.storeScope ?? STORE } },
    },
  );
  bindReplySourceToFollowup(options, run);
  return { run, input };
}

/** The input's own turn starts: the session controller claims it. */
async function startTurn(queued: { run: FollowupRun }) {
  const claim = await claimSessionControllerInput(queued.run);
  claims.push(claim);
  return claim;
}

async function endTurn(claim: SessionControllerMailboxClaim) {
  releaseSessionControllerClaim(claim);
  await claim.settlement.promise;
}

/** A dashboard chat.send steer: the real RPC source reservation, admitted for injection. */
async function dashboardSteer(profileId: string | undefined) {
  const registration = registerChatAbortController({
    target: target(),
    sessionKey: SESSION,
    sessionId: "vault-session",
    runId: `steer-${randomUUID()}`,
    timeoutMs: 60_000,
    policy: { mode: "steer" },
  });
  if (!registration.registered) {
    throw new Error("dashboard steer was not registered");
  }
  registrations.push(registration);
  // retainGatewayOperatorRun records the verified sender (operator-run-cancellation.test.ts).
  if (profileId) {
    registration.entry.adapter.requesterProfileId = profileId;
  }
  const { input } = registration.entry;
  const injection = beginSessionControllerSourceInjection(input);
  injections.push(injection);
  expect(await injection.admit()).toBe(true);
  return { input, injection };
}

beforeAll(async () => {
  ({ createExecTool } = await import("./bash-tools.exec-run.js"));
  ({ toToolDefinitions } = await import("./agent-tool-definition-adapter.js"));
});

beforeEach(() => {
  value = `vt-${randomUUID()}`;
  logs = [];
  for (const method of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, method).mockImplementation((...args) => void logs.push(args.join(" ")));
  }
  for (const stream of [process.stdout, process.stderr]) {
    const write = stream.write.bind(stream);
    vi.spyOn(stream, "write").mockImplementation((chunk, ...rest) => {
      logs.push(String(chunk));
      return write(chunk, ...(rest as []));
    });
  }
  resetRequesterGrantsForTest();
  setRequesterGrantValueProviderForTest({
    readEntries: (holder) => (holder === "alice" ? { [KEY]: value } : { [KEY]: `other-${value}` }),
  });
  mocks.spawnInputs.length = 0;
  mocks.durableInputs.length = 0;
  mocks.gatewayParams.length = 0;
  mocks.beforeNativeSpawn = undefined;
  mocks.hookRunner = undefined;
});

afterEach(async () => {
  for (const claim of claims.splice(0)) {
    releaseSessionControllerClaim(claim);
  }
  // A failed case must not leave a pending injection blocking the next test's mailbox.
  for (const injection of injections.splice(0)) {
    injection.finish(false);
  }
  for (const input of inputs.splice(0)) {
    retireSessionControllerInput(input);
  }
  for (const registration of registrations.splice(0)) {
    registration.cleanup();
  }
  clearFollowupQueue(SESSION);
  vi.useRealTimers();
  vi.restoreAllMocks();
  resetProcessRegistryForTests();
  setRequesterGrantValueProviderForTest(undefined);
});

describe("requester-bound exec grants", () => {
  it("1: delivers the holder's value to its own turn through the exec tool, and nowhere else", async () => {
    grant("alice");
    const hooks = {
      hasHooks: (name: string) => name === "resolve_exec_env" || name === "before_tool_call",
      runResolveExecEnv: vi.fn(async () => ({ PLUGIN_SAFE: "yes" })),
      runBeforeToolCall: vi.fn(async () => undefined),
    };
    mocks.hookRunner = hooks;
    const result = await execToolInTurn(turn("alice"), { command: "echo ok" });

    expect(mocks.spawnInputs.at(-1)?.env?.[KEY]).toBe(value);
    expect(isSecretValueRegisteredForRedaction(value)).toBe(true);
    expect(hooks.runResolveExecEnv).toHaveBeenCalled();
    expect(hooks.runBeforeToolCall).toHaveBeenCalled();
    expectNoLeak({
      requestedEnv: mocks.gatewayParams.map((params) => params.requestedEnv),
      preparedEnv: mocks.gatewayParams.map((params) => params.env),
      resolveExecEnvHook: hooks.runResolveExecEnv.mock.calls,
      beforeToolCallHook: hooks.runBeforeToolCall.mock.calls,
      toolResult: result,
      logs,
    });
  });

  it("16: per-call env and plugin env win over grant keys; grant keys win over inherited env", async () => {
    setRequesterGrantValueProviderForTest({
      readEntries: () => ({ [KEY]: value, PLUGIN_KEY: value, GRANT_ONLY: value }),
    });
    grant("alice");
    vi.stubEnv("GRANT_ONLY", "inherited");
    mocks.hookRunner = {
      hasHooks: (name: string) => name === "resolve_exec_env",
      runResolveExecEnv: vi.fn(async () => ({ PLUGIN_KEY: "from-plugin" })),
      runBeforeToolCall: vi.fn(),
    };
    const result = await execToolInTurn(turn("alice"), {
      command: "echo ok",
      env: { [KEY]: "per-call" },
    });

    expect(mocks.spawnInputs.at(-1)?.env).toMatchObject({
      [KEY]: "per-call",
      PLUGIN_KEY: "from-plugin",
      GRANT_ONLY: value,
    });
    expectNoLeak({
      requestedEnv: mocks.gatewayParams.map((params) => params.requestedEnv),
      toolResult: result,
      logs,
    });
  });

  it("2: sandbox exec gets no value and a warning", async () => {
    grant("alice");
    const { env, warnings, surfaces } = await launch(turn("alice"), {
      sandbox: {
        containerName: "sandbox",
        workspaceDir: "/workspace",
        containerWorkdir: "/workspace",
        buildExecSpec: async ({ env: sandboxEnv }) => ({
          argv: ["sh", "-c", "echo ok"],
          env: sandboxEnv,
          stdinMode: "pipe-closed" as const,
        }),
      },
    });
    expect(env[KEY]).toBeUndefined();
    expect(warnings).toEqual([expect.stringContaining("sandbox exec is not supported")]);
    expectNoLeak(surfaces);
  });

  it("3: durable exec gets no value and a warning, and the durable launch proceeds", async () => {
    grant("alice");
    const { env, warnings, surfaces } = await launch(turn("alice"), {
      durable: { notifyOnExit: false, notifyOnExitEmptySuccess: false },
    });
    expect(mocks.durableInputs).toHaveLength(1);
    expect(env.BASE).toBe("1");
    expect(env[KEY]).toBeUndefined();
    expect(warnings).toEqual([expect.stringContaining("durable exec is not supported")]);
    expectNoLeak(surfaces);
  });

  it("4: another sender's prompt whose turn starts before the holder's launch revokes the grant", async () => {
    grant("alice");
    const bob = await queue("bob");
    expect(holders()).toEqual(["alice"]);
    await endTurn(await startTurn(bob));
    const { env, surfaces } = await launch(turn("alice"));
    expect(env[KEY]).toBeUndefined();
    expectNoLeak(surfaces);
  });

  it("5: a queued follow-up keeps the holder's current turn and revokes when its own turn starts", async () => {
    grant("alice");
    const aliceClaim = await startTurn(await queue("alice"));
    const aliceTurn = turn("alice");
    const first = await launch(aliceTurn);

    const bob = await queue("bob");
    const bobTurnStarted = claimSessionControllerInput(bob.run);
    const later = await launch(aliceTurn);
    expect(holders()).toEqual(["alice"]);

    await endTurn(aliceClaim);
    claims.push(await bobTurnStarted);
    expect(holders()).toEqual([]);
    const bobTurn = await launch(turn("bob"));

    expect(first.env[KEY]).toBe(value);
    expect(later.env[KEY]).toBe(value);
    expect(bobTurn.env[KEY]).toBeUndefined();
    for (const result of [first, later, bobTurn]) {
      expectNoLeak(result.surfaces);
    }
  });

  it.each(["channel", "dashboard"] as const)(
    "6: a %s steer from another sender revokes immediately and keeps the sender's own grant",
    async (via) => {
      grant("alice");
      const aliceClaim = await startTurn(await queue("alice"));
      grant("bob"); // After Alice's turn starts, which ends every other holder's grant.
      const aliceTurn = turn("alice");
      const before = await launch(aliceTurn);
      if (via === "channel") {
        // The running turn's adoption parks the channel message as a steer candidate.
        const bob = await queue("bob");
        const steer = reserveSteerCandidate(SESSION, bob.run, { mode: "steer" }, async () => {});
        expect(steer).toBeDefined();
        expect(await steer!.admit()).toBe("steer");
        steer!.consume();
      } else {
        (await dashboardSteer("bob")).injection.finish(true);
      }
      expect(holders()).toEqual(["bob"]);
      const after = await launch(aliceTurn);
      await endTurn(aliceClaim);
      expect(before.env[KEY]).toBe(value);
      expect(after.env[KEY]).toBeUndefined();
      expectNoLeak({ ...before.surfaces, after: after.surfaces });
    },
  );

  it("7a: an unverified sender's input removes every grant in the session when its turn starts", async () => {
    grant("alice");
    grant("carol");
    await endTurn(await startTurn(await queue(undefined)));
    expect(holders()).toEqual([]);
    const alice = await launch(turn("alice"));
    const carol = await launch(turn("carol"));
    expect(alice.env[KEY]).toBeUndefined();
    expect(carol.env[KEY]).toBeUndefined();
    expectNoLeak({ ...alice.surfaces, carol: carol.surfaces });
  });

  it("7b: a host task (withSessionTurn, no ingress source) removes no grant", async () => {
    grant("alice");
    grant("carol");
    // Agent-command, plugin runtime, scheduled plugin commands, maintenance, completion wakes.
    await withSessionTurn({ sessionKey: SESSION, agentId: AGENT, storePath: STORE }, async () =>
      expect(holders()).toEqual(["alice", "carol"]),
    );
    expect(holders()).toEqual(["alice", "carol"]);
    const { env, surfaces } = await launch(turn("alice"));
    expect(env[KEY]).toBe(value);
    expectNoLeak(surfaces);
  });

  it("9: a revocation between lookup and spawn fails the launch closed", async () => {
    grant("alice");
    mocks.beforeNativeSpawn = () =>
      disableRequesterGrant({ storeScope: STORE, agentId: AGENT, sessionKey: SESSION }, "alice");
    const warnings: string[] = [];
    await expect(
      withGatewayToolCallerIdentity(turn("alice"), () =>
        runExecFixture({
          warnings,
          sessionKey: SESSION,
          agentId: AGENT,
          requesterGrant: { storeScope: STORE },
        }),
      ),
    ).rejects.toThrow("Session secrets were revoked before the command started");
    expect(mocks.spawnInputs).toHaveLength(0);
    expectNoLeak({ warnings, logs });
  });

  it("10: an expired grant delivers nothing", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    grant("alice", "full-session", { ttlMs: 60_000 });
    const before = await launch(turn("alice"));
    vi.setSystemTime(Date.now() + 60_001);
    const after = await launch(turn("alice"));
    expect(before.env[KEY]).toBe(value);
    expect(after.env[KEY]).toBeUndefined();
    expectNoLeak({ ...before.surfaces, after: after.surfaces });
  });

  it("11: a single-turn grant pins the first turn that uses it", async () => {
    grant("alice", "single-turn");
    const firstTurn = turn("alice");
    const first = await launch(firstTurn);
    const again = await launch(firstTurn);
    const second = await launch(turn("alice"));
    expect(first.env[KEY]).toBe(value);
    expect(again.env[KEY]).toBe(value);
    expect(second.env[KEY]).toBeUndefined();
    expectNoLeak({ ...first.surfaces, second: second.surfaces });
  });

  it("12: a grant enabled during a turn reaches only the next turn", async () => {
    const running = turn("alice");
    grant("alice");
    const current = await launch(running);
    const next = await launch(turn("alice"));
    expect(current.env[KEY]).toBeUndefined();
    expect(next.env[KEY]).toBe(value);
    expectNoLeak({ ...current.surfaces, next: next.surfaces });
  });

  it("13: a Gateway restart (fresh registry) has no grants", async () => {
    grant("alice");
    resetRequesterGrantsForTest();
    const { env, surfaces } = await launch(turn("alice"));
    expect(env[KEY]).toBeUndefined();
    expectNoLeak(surfaces);
  });

  it("14: the breaker trips once per input across steer admit, rebind and claim", async () => {
    grant("alice");
    const { input, injection } = await dashboardSteer("bob");
    expect(holders()).toEqual([]);
    injection.finish(false); // Declined steer falls back to a queued turn.

    grant("alice");
    const bobRun = createQueueTestRun(
      { prompt: "hi", operatorAuthority: authority("bob") },
      { agentId: AGENT, sessionKey: SESSION },
    );
    bindSessionControllerSource(input, bobRun);
    bindSessionControllerSource(input, bobRun);
    await endTurn(await startTurn({ run: bobRun }));
    expect(holders()).toEqual(["alice"]);
    const { env, surfaces } = await launch(turn("alice"));
    expect(env[KEY]).toBe(value);
    expectNoLeak(surfaces);
  });

  it("15: a grant for one agent's session does not apply to another agent's same key", async () => {
    grant("alice");
    const other = target({ agentId: "other", storeScope: "/synthetic/other/sessions" });
    await endTurn(await startTurn(await queue("bob", other)));
    const sameAgent = await launch(turn("alice"));
    const otherAgent = await launch(turn("alice", "other"));
    expect(sameAgent.env[KEY]).toBe(value);
    expect(otherAgent.env[KEY]).toBeUndefined();
    expectNoLeak({ ...sameAgent.surfaces, other: otherAgent.surfaces });
  });

  it("22: the same agent and key in another session store share no grant", async () => {
    grant("alice");
    grant("alice", "full-session", {
      target: { storeScope: OTHER_STORE, agentId: AGENT, sessionKey: SESSION },
    });
    // Bob's prompt in the other store's session ends only that store's grant.
    await endTurn(await startTurn(await queue("bob", target({ storeScope: OTHER_STORE }))));
    expect(holders()).toEqual(["alice"]);
    expect(holders(OTHER_STORE)).toEqual([]);

    // The exec tool keys the lookup by the store of the turn it runs in.
    const otherStore = await execToolInTurn(turn("alice"), { command: "echo ok" }, OTHER_STORE);
    const ownStore = await execToolInTurn(turn("alice"), { command: "echo ok" });
    expect(mocks.spawnInputs).toHaveLength(2);
    expect(mocks.spawnInputs[0]?.env?.[KEY]).toBeUndefined();
    expect(mocks.spawnInputs[1]?.env?.[KEY]).toBe(value);
    expectNoLeak({ otherStore, ownStore, logs });
  });

  it("17: entryNames delivers only the selected entries", async () => {
    setRequesterGrantValueProviderForTest({ readEntries: () => ({ A: value, B: `b-${value}` }) });
    grant("alice", "full-session", { entryNames: ["A"] });
    const { env, surfaces } = await launch(turn("alice"));
    expect(env.A).toBe(value);
    expect(env.B).toBeUndefined();
    expectNoLeak(surfaces);
  });

  it("18: invalid, reserved, NUL and oversize entries are rejected by name only", async () => {
    const rejected = {
      "bad-name": `x-${value}`,
      GH_TOKEN: `gh-${value}`,
      LD_PRELOAD: `ld-${value}`,
      OPENCLAW_SHELL: `oc-${value}`,
      NUL_VALUE: `a\0${value}`,
      BIG: `${value}${"x".repeat(17 * 1024)}`,
    };
    setRequesterGrantValueProviderForTest({ readEntries: () => rejected });
    grant("alice");
    const { env, warnings, surfaces } = await launch(turn("alice"));
    for (const name of Object.keys(rejected)) {
      expect(env[name] ?? "").not.toContain(value);
    }
    expect(warnings).toHaveLength(1);
    for (const part of [
      "BIG (too large)",
      "GH_TOKEN (reserved name)",
      "LD_PRELOAD (reserved name)",
      "NUL_VALUE (NUL byte)",
      "OPENCLAW_SHELL (reserved name)",
      "one entry with an invalid name",
    ]) {
      expect(warnings[0]).toContain(part);
    }
    expectNoLeak(surfaces);
  });

  it("19: a queued follow-up withdrawn before its turn never revokes", async () => {
    grant("alice");
    const aliceClaim = await startTurn(await queue("alice"));
    const bob = await queue("bob");
    expect(holdSessionControllerSourceWithdrawal(bob.input).commit()).toBe(true);
    await endTurn(aliceClaim);
    await endTurn(await startTurn(await queue("alice")));
    expect(holders()).toEqual(["alice"]);
    const { env, surfaces } = await launch(turn("alice"));
    expect(env[KEY]).toBe(value);
    expectNoLeak(surfaces);
  });

  it("20: a run without a verified operator gets nothing, even with a full-session grant", async () => {
    grant("alice");
    const { env, warnings, surfaces } = await launch(turn(undefined));
    expect(env[KEY]).toBeUndefined();
    expect(warnings).toEqual([]);
    expect(holders()).toEqual(["alice"]);
    expectNoLeak(surfaces);
  });

  it("21: a single-turn grant is removed when its pinned run ends, not when another run ends", async () => {
    grant("alice", "single-turn");
    const admit = async (runId: string) => {
      const prepared = prepareSystemAgentRunAdmission({}, runId, AGENT, "requester-grant-test");
      const admitted = await resolvePreparedRunAdmission({
        runId,
        runtimeKind: "embedded",
        preparedRunAdmission: prepared,
      });
      return { prepared, run: admitted.operationalRunInstance };
    };
    const pinned = await admit(`pinned-${randomUUID()}`);
    const sibling = await admit(`sibling-${randomUUID()}`);
    const { env, surfaces } = await launch({
      ...turn("alice"),
      operationalRunInstance: pinned.run,
    });
    expect(env[KEY]).toBe(value);
    sibling.prepared.close();
    expect(holders()).toEqual(["alice"]);
    pinned.prepared.close();
    expect(holders()).toEqual([]);
    expectNoLeak(surfaces);
  });
});
