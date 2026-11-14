import { randomUUID } from "node:crypto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { isSecretValueRegisteredForRedaction } from "../logging/secret-redaction-registry.js";
import type { SpawnInput } from "../process/supervisor/types.js";
import { withSessionTurn } from "../sessions/session-controller.admission.js";
import { createAdmittedRunOperatorAuthority } from "./admitted-run-context.js";
import { resetProcessRegistryForTests } from "./bash-process-registry.test-support.js";
import type { CapturedEnvironment } from "./bash-tools.exec-env.test-support.js";
import { runExecFixture } from "./bash-tools.exec-fixture.test-support.js";
import { runtimeManagedRun } from "./bash-tools.exec-runtime.test-support.js";
import { createOperationalRunInstanceRef } from "./operational-run-instance.js";
import {
  disableRequesterGrant,
  enableRequesterGrantForTest,
  resetRequesterGrantsForTest,
  setRequesterGrantValueProviderForTest,
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
const grant = (holder: string, extra = {}) =>
  enableRequesterGrantForTest({
    holderProfileId: holder,
    target: { storeScope: STORE, agentId: AGENT, sessionKey: SESSION },
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

  it("4: every turn in the session uses the holder's entries, whoever prompted it", async () => {
    grant("alice");
    const bob = await launch(turn("bob"));
    const unverified = await launch(turn(undefined));
    expect(bob.env[KEY]).toBe(value);
    expect(unverified.env[KEY]).toBe(value);
    expectNoLeak({ ...bob.surfaces, unverified: unverified.surfaces });
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

  it("9: a revocation between lookup and spawn fails the launch closed", async () => {
    grant("alice");
    mocks.beforeNativeSpawn = () =>
      disableRequesterGrant({ storeScope: STORE, agentId: AGENT, sessionKey: SESSION });
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

  it("13: a Gateway restart (fresh registry) has no grants", async () => {
    grant("alice");
    resetRequesterGrantsForTest();
    const { env, surfaces } = await launch(turn("alice"));
    expect(env[KEY]).toBeUndefined();
    expectNoLeak(surfaces);
  });

  it("15: a grant for one agent's session does not apply to another agent's same key", async () => {
    grant("alice");
    const sameAgent = await launch(turn("alice"));
    const otherAgent = await launch(turn("alice", "other"));
    expect(sameAgent.env[KEY]).toBe(value);
    expect(otherAgent.env[KEY]).toBeUndefined();
    expectNoLeak({ ...sameAgent.surfaces, other: otherAgent.surfaces });
  });

  it("22: the same agent and key in another session store share no grant", async () => {
    grant("alice");

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
    grant("alice", { entryNames: ["A"] });
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

});
