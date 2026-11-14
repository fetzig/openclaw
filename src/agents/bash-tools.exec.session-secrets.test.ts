import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { GATEWAY_OWNER_PROFILE_ID } from "../../packages/gateway-protocol/src/schema/user-profile-constants.js";
import { resolveSessionStorePathCore } from "../config/sessions/paths.js";
import {
  assignSessionOwner,
  loadSessionEntry,
  replaceSessionEntry,
} from "../config/sessions/session-accessor.js";
import {
  addSessionMember,
  removeSessionMember,
} from "../config/sessions/session-sharing-store.native.js";
import type { SessionEntry } from "../config/sessions/types.js";
import { isSecretValueRegisteredForRedaction } from "../logging/secret-redaction-registry.js";
import type { SpawnInput } from "../process/supervisor/types.js";
import type { SecretEgressSentinelBinding } from "../secrets/egress-proxy/proxy-server.js";
import {
  clearSecretEgressProxy,
  publishSecretEgressProxy,
} from "../secrets/egress-proxy/registry.js";
import {
  looksLikeSecretSentinel,
  resolveSecretSentinel,
  sealSecretSentinel,
} from "../secrets/sentinel.js";
import { withSessionTurn } from "../sessions/session-controller.admission.js";
import { prepareUserProfileCatalog } from "../state/user-profile-list.js";
import { mergeProfiles } from "../state/user-profile-writes.worker.js";
import { ensureProfileForEmail } from "../state/user-profiles.js";
import {
  createOpenClawTestState,
  type OpenClawTestState,
} from "../test-utils/openclaw-test-state.js";
import { createAdmittedRunOperatorAuthority } from "./admitted-run-context.js";
import { resetProcessRegistryForTests } from "./bash-process-registry.test-support.js";
import type { CapturedEnvironment } from "./bash-tools.exec-env.test-support.js";
import { runExecFixture } from "./bash-tools.exec-fixture.test-support.js";
import { runtimeManagedRun } from "./bash-tools.exec-runtime.test-support.js";
import type { ExecToolDefaults } from "./bash-tools.exec-types.js";
import { createOperationalRunInstanceRef } from "./operational-run-instance.js";
import {
  disableSessionSecrets,
  enableSessionSecretsForTest,
  readSessionSecretsCreatorForTest,
  resetSessionSecretsForTest,
  SESSION_SECRETS_ENDED_ERROR,
  SESSION_SECRETS_NO_PERSON_NOTICE,
  SESSION_SECRETS_OFF_NOTICE,
  setSessionSecretValueProviderForTest,
  type SessionSecretEntry,
} from "./session-secrets.js";
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
const SESSION_ID = "vault-session";
const OTHER_STORE = "/synthetic/session-secrets/other-sessions";
const KEY = "VAULT_TEST_TOKEN";
/** Verified Gateway profiles, created in beforeAll; Alice's old profile was merged into hers. */
const people = { alice: "", aliceOld: "", bob: "", carol: "" };
const human = (id: string) => ({ type: "human", source: "profile", id }) as const;
let ALICE: ReturnType<typeof human>;
let state: OpenClawTestState;
let releaseProfileCatalog: (() => void) | undefined;
let store: string;
let value: string;
let logs: string[];
/** Bindings each launch registered with the egress proxy, when one is active. */
let registered: SecretEgressSentinelBinding[][];
let proxy:
  | { registerProcess: (bindings?: readonly SecretEgressSentinelBinding[]) => unknown }
  | undefined;

const target = (sessionKey = SESSION) => ({ storeScope: store, agentId: AGENT, sessionKey });
const enable = (requesterProfileId = people.alice, extra = {}, sessionKey = SESSION) =>
  enableSessionSecretsForTest({ requesterProfileId, target: target(sessionKey), ...extra });
const entries = (...list: SessionSecretEntry[]) =>
  setSessionSecretValueProviderForTest({
    readEntries: (profileId) => (profileId === people.alice ? list : []),
  });
const authority = (profileId: string) =>
  createAdmittedRunOperatorAuthority({ profileId, scopes: [], assertCurrent: () => {} });

/** One admitted turn; `profileId` is whoever prompted it. */
const turn = (person: keyof typeof people | undefined, agentId = AGENT) => ({
  agentId,
  sessionKey: SESSION,
  operationalRunInstance: createOperationalRunInstanceRef(`run-${randomUUID()}`),
  ...(person ? { operatorAuthority: authority(people[person]) } : {}),
});

/** A Gateway egress proxy stand-in that records each launch's bindings. */
function activateProxy() {
  proxy = {
    registerProcess: (bindings = []) => {
      registered.push([...bindings]);
      return { env: { HTTPS_PROXY: "http://openclaw:token@127.0.0.1:9" }, revoke: () => {} };
    },
  };
  publishSecretEgressProxy(proxy as never);
}

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
      sessionId: SESSION_ID,
      agentId: caller.agentId,
      sessionSecrets: {
        target: { storeScope: store, agentId: caller.agentId, sessionKey: SESSION },
      },
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
    expect(JSON.stringify(surface) ?? "", `${name} leaked the value`).not.toContain(value);
  }
}

/** Runs the exec tool inside a session turn of the given store, as an agent turn does. */
async function execToolInTurn(
  caller: ReturnType<typeof turn>,
  params: Record<string, unknown>,
  options: { storeScope?: string; defaults?: ExecToolDefaults } = {},
) {
  const tool = createExecTool({
    host: "gateway",
    security: "full",
    ask: "off",
    sessionId: SESSION_ID,
    ...options.defaults,
  });
  const [definition] = toToolDefinitions([tool], { agentId: AGENT, sessionKey: SESSION });
  return await withSessionTurn(
    {
      sessionKey: SESSION,
      sessionId: SESSION_ID,
      agentId: AGENT,
      storePath: options.storeScope ?? store,
    },
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

async function writeSession(sessionKey: string, fields: Partial<SessionEntry>) {
  await replaceSessionEntry(
    { agentId: AGENT, sessionKey, storePath: store },
    { sessionId: SESSION_ID, updatedAt: Date.now(), ...fields },
  );
}

beforeAll(async () => {
  state = await createOpenClawTestState({
    prefix: "openclaw-session-secrets-",
    layout: "state-only",
    env: { OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1" },
  });
  store = resolveSessionStorePathCore(undefined, { agentId: AGENT });
  for (const name of Object.keys(people) as Array<keyof typeof people>) {
    people[name] = ensureProfileForEmail(`${name}@example.test`).id;
  }
  // Alice signed in under a second profile that an admin merged with her first one.
  mergeProfiles(people.aliceOld, people.alice);
  ALICE = human(people.alice);
  await writeSession(SESSION, { createdActor: ALICE });
  // The Gateway prepares the profile catalog at admission; sharing checks read it.
  releaseProfileCatalog = (await prepareUserProfileCatalog()).release;
  ({ createExecTool } = await import("./bash-tools.exec-run.js"));
  ({ toToolDefinitions } = await import("./agent-tool-definition-adapter.js"));
});

afterAll(async () => {
  releaseProfileCatalog?.();
  await state?.cleanup();
});

beforeEach(() => {
  value = `vt-${randomUUID()}`;
  logs = [];
  registered = [];
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
  resetSessionSecretsForTest();
  entries({ name: KEY, kind: "env", value });
  mocks.spawnInputs.length = 0;
  mocks.durableInputs.length = 0;
  mocks.gatewayParams.length = 0;
  mocks.beforeNativeSpawn = undefined;
  mocks.hookRunner = undefined;
});

afterEach(async () => {
  if (proxy) {
    clearSecretEgressProxy(proxy as never);
    proxy = undefined;
  }
  vi.useRealTimers();
  vi.restoreAllMocks();
  resetProcessRegistryForTests();
  setSessionSecretValueProviderForTest(undefined);
});

describe("who can turn session secrets on", () => {
  type Name = keyof typeof people;
  it.each<[string, () => Partial<SessionEntry> & { assignTo?: Name }, Name | undefined]>([
    ["the profile creator", () => ({ createdActor: ALICE }), "alice"],
    // The assignable owner never counts; the creator keeps the right.
    [
      "the creator after Bob became owner",
      () => ({ createdActor: ALICE, assignTo: "bob" }),
      "alice",
    ],
    // Upstream's creator rule: a merged profile counts as the creator.
    ["Alice's merged profile", () => ({ createdActor: human(people.aliceOld) }), "alice"],
    [
      "a channel sender",
      () => ({ createdActor: { type: "human", source: "channel", id: people.alice } }),
      undefined,
    ],
    [
      "an unknown human",
      () => ({ createdActor: { type: "human", source: "unknown", id: people.alice } }),
      undefined,
    ],
    ["an agent", () => ({ createdActor: { type: "agent", id: "main" } }), undefined],
    ["an automation", () => ({ createdActor: { type: "system", id: "cron" } }), undefined],
    // A creation an agent made for Alice is hers.
    [
      "an agent on Alice's behalf",
      () => ({ createdActor: { type: "agent", id: "main", delegatedBy: ALICE } }),
      "alice",
    ],
    [
      "Carol through an agent",
      () => ({
        createdActor: { ...human(people.carol), delegatedBy: { type: "agent", id: "main" } },
      }),
      undefined,
    ],
    ["a child session", () => ({ createdActor: ALICE, parentSessionKey: SESSION }), "alice"],
    ["a spawned session", () => ({ createdActor: ALICE, spawnedBy: SESSION }), "alice"],
    ["no recorded creator", () => ({}), undefined],
    // Every token or password connection signs in as this one profile; it is not a person.
    [
      "the shared Gateway owner profile",
      () => ({ createdActor: human(GATEWAY_OWNER_PROFILE_ID) }),
      undefined,
    ],
  ])("%s", async (_label, fields, creator) => {
    const sessionKey = `agent:main:dashboard:creator-${randomUUID()}`;
    const { assignTo, ...entry } = fields();
    await writeSession(sessionKey, entry);
    if (assignTo) {
      // Anyone who can see a session can reassign its owner; Bob takes it over.
      const bob = { type: "human" as const, id: people[assignTo] };
      const scope = { agentId: AGENT, sessionKey, storePath: store };
      assignSessionOwner(scope, { owner: bob, assignedBy: bob });
      expect(loadSessionEntry(scope)?.owner?.actor.id).toBe(people[assignTo]);
    }
    if (entry.parentSessionKey) {
      // Never inherited: the parent's secrets being on leaves the child off.
      await enable();
      expect(readSessionSecretsCreatorForTest(target(sessionKey))).toBeUndefined();
    }
    for (const requester of [people.alice, people.bob, people.carol, GATEWAY_OWNER_PROFILE_ID]) {
      const attempt = enable(requester, {}, sessionKey);
      if (creator && requester === people[creator]) {
        await expect(attempt).resolves.toBeUndefined();
      } else {
        await expect(attempt).rejects.toThrow("Only the session's creator");
      }
    }
    expect(readSessionSecretsCreatorForTest(target(sessionKey))).toBe(
      creator ? people[creator] : undefined,
    );
  });

  it("refuses a session that does not exist and only the creator turns them off", async () => {
    await expect(
      enableSessionSecretsForTest({
        requesterProfileId: people.alice,
        target: target("agent:main:dashboard:missing"),
      }),
    ).rejects.toThrow("Only the session's creator");
    await enable();
    disableSessionSecrets(target(), people.bob);
    expect(readSessionSecretsCreatorForTest(target())).toBe(people.alice);
    disableSessionSecrets(target(), people.alice);
    expect(readSessionSecretsCreatorForTest(target())).toBeUndefined();
  });
});

/** A fresh session of Alice's with the given fields; returns its key. */
async function aliceSession(fields: Partial<SessionEntry> = {}) {
  const sessionKey = `agent:main:dashboard:reach-${randomUUID()}`;
  await writeSession(sessionKey, { createdActor: ALICE, ...fields });
  return sessionKey;
}
const launchIn = (sessionKey: string, person: keyof typeof people | undefined) =>
  launch(turn(person), { sessionKey, sessionSecrets: { target: target(sessionKey) } });
const setVisibility = (sessionKey: string, visibility: SessionEntry["visibility"]) =>
  writeSession(sessionKey, { createdActor: ALICE, visibility });
const addMember = (sessionKey: string, person: keyof typeof people) =>
  addSessionMember(
    { agentId: AGENT, sessionKey, storePath: store },
    { identityId: people[person], addedBy: people.alice },
  );

describe("who may send decides at launch", () => {
  it("a change that lets more people send ends them at the next launch, once", async () => {
    // Bob is an invited member: he can send in Read-only, Suggest and Shared, never in Draft.
    const widening = new Set([
      "draft>read-only",
      "draft>suggest",
      "draft>shared",
      "read-only>shared",
      "suggest>shared",
    ]);
    const visibilities = ["draft", "read-only", "suggest", "shared"] as const;
    for (const previous of visibilities) {
      for (const next of visibilities) {
        const sessionKey = await aliceSession({ visibility: previous });
        addMember(sessionKey, "bob");
        await enable(people.alice, {}, sessionKey);
        await setVisibility(sessionKey, next);
        const first = await launchIn(sessionKey, "alice");
        const ended = widening.has(`${previous}>${next}`);
        expect(first.env[KEY], `${previous} -> ${next}`).toBe(ended ? undefined : value);
        expect(first.warnings).toEqual(ended ? [SESSION_SECRETS_OFF_NOTICE] : []);
        expect(readSessionSecretsCreatorForTest(target(sessionKey))).toBe(
          ended ? undefined : people.alice,
        );
      }
    }
  });

  it("adding a member to a Read-only session ends them at the next launch", async () => {
    const sessionKey = await aliceSession({ visibility: "read-only" });
    await enable(people.alice, {}, sessionKey);
    const before = await launchIn(sessionKey, "alice");
    addMember(sessionKey, "carol");
    const after = await launchIn(sessionKey, "alice");
    const later = await launchIn(sessionKey, "alice");

    expect([before, after, later].map((result) => result.env[KEY])).toEqual([
      value,
      undefined,
      undefined,
    ]);
    expect(after.warnings).toEqual([SESSION_SECRETS_OFF_NOTICE]);
    expect(later.warnings).toEqual([]);
    expectNoLeak({ before: before.surfaces, after: after.surfaces, later: later.surfaces });
  });

  it("swapping one member for another ends them, though no more people can send", async () => {
    const sessionKey = await aliceSession({ visibility: "read-only" });
    addMember(sessionKey, "bob");
    await enable(people.alice, {}, sessionKey);
    removeSessionMember({ agentId: AGENT, sessionKey, storePath: store }, people.bob);
    addMember(sessionKey, "carol");
    const { env, warnings, surfaces } = await launchIn(sessionKey, "alice");

    expect(env[KEY]).toBeUndefined();
    expect(warnings).toEqual([SESSION_SECRETS_OFF_NOTICE]);
    expectNoLeak(surfaces);
  });

  it("only a run acting for a person who may send gets them", async () => {
    const sessionKey = await aliceSession({ visibility: "draft" });
    await enable(people.alice, {}, sessionKey);
    const alice = await launchIn(sessionKey, "alice");
    // Bob cannot send in Alice's Draft; a run for him gets nothing, and they stay on.
    const bob = await launchIn(sessionKey, "bob");
    // No person: unlinked channel senders, hooks, node requests, system dispatch.
    const nobody = await launchIn(sessionKey, undefined);

    expect(alice.env[KEY]).toBe(value);
    for (const result of [bob, nobody]) {
      expect(result.env[KEY]).toBeUndefined();
      expect(result.warnings).toEqual([SESSION_SECRETS_NO_PERSON_NOTICE]);
    }
    expect(readSessionSecretsCreatorForTest(target(sessionKey))).toBe(people.alice);
    expectNoLeak({ alice: alice.surfaces, bob: bob.surfaces, nobody: nobody.surfaces });
  });

  it("enable and launch name one session however its key is spelled", async () => {
    // Enabled under the agent-relative alias; launches use the canonical key.
    const alias = { storeScope: store, agentId: AGENT, sessionKey: "dashboard:vault" };
    await enableSessionSecretsForTest({ requesterProfileId: people.alice, target: alias });
    const on = await execToolInTurn(turn("bob"), { command: "echo ok" });
    expect(readSessionSecretsCreatorForTest(target())).toBe(people.alice);
    disableSessionSecrets(alias, people.alice);
    const off = await execToolInTurn(turn("bob"), { command: "echo ok" });

    expect(mocks.spawnInputs.map((input) => input.env?.[KEY])).toEqual([value, undefined]);
    expect(JSON.stringify(off)).toContain(SESSION_SECRETS_OFF_NOTICE);
    expectNoLeak({ on, off, logs });
  });
});

describe("session secrets at launch", () => {
  it("every turn uses the creator's entries through the exec tool, whoever prompted it", async () => {
    await enable();
    const hooks = {
      hasHooks: (name: string) => name === "resolve_exec_env" || name === "before_tool_call",
      runResolveExecEnv: vi.fn(async () => ({ PLUGIN_SAFE: "yes" })),
      runBeforeToolCall: vi.fn(async () => undefined),
    };
    mocks.hookRunner = hooks;
    const results = [];
    for (const prompter of ["alice", "bob", undefined] as const) {
      results.push(await execToolInTurn(turn(prompter), { command: "echo ok" }));
    }

    // A turn that acts for no person gets nothing.
    expect(mocks.spawnInputs.map((input) => input.env?.[KEY])).toEqual([value, value, undefined]);
    expect(JSON.stringify(results[2])).toContain(SESSION_SECRETS_NO_PERSON_NOTICE);
    expect(isSecretValueRegisteredForRedaction(value)).toBe(true);
    expect(hooks.runResolveExecEnv).toHaveBeenCalled();
    expect(hooks.runBeforeToolCall).toHaveBeenCalled();
    expectNoLeak({
      requestedEnv: mocks.gatewayParams.map((params) => params.requestedEnv),
      preparedEnv: mocks.gatewayParams.map((params) => params.env),
      resolveExecEnvHook: hooks.runResolveExecEnv.mock.calls,
      beforeToolCallHook: hooks.runBeforeToolCall.mock.calls,
      toolResults: results,
      logs,
    });
  });

  it("delivers a protected secret only as a sentinel bound to its allowed hosts", async () => {
    entries({ name: KEY, value, allowedHosts: ["API.Example.test"] });
    await enable();
    activateProxy();
    const { env, warnings, surfaces } = await launch(turn("bob"));

    const sentinel = env[KEY]!;
    expect(looksLikeSecretSentinel(sentinel)).toBe(true);
    expect(resolveSecretSentinel(sentinel)).toBe(value);
    expect(env.HTTPS_PROXY).toBeDefined();
    expect(registered).toEqual([[{ name: KEY, sentinel, allowedHosts: ["api.example.test"] }]]);
    expect(warnings).toEqual([]);
    expectNoLeak({ ...surfaces, env });
  });

  it("withholds protected secrets without the egress proxy or allowed hosts, and says so", async () => {
    entries(
      { name: KEY, value, allowedHosts: ["api.example.test"] },
      { name: "NO_HOSTS", value },
      { name: "PLAIN", kind: "env", value },
    );
    await enable();
    const withoutProxy = await launch(turn("alice"));
    activateProxy();
    const withProxy = await launch(turn("alice"));

    expect(withoutProxy.env[KEY]).toBeUndefined();
    expect(withoutProxy.env.PLAIN).toBe(value);
    expect(withoutProxy.warnings).toEqual([
      expect.stringContaining("NO_HOSTS (no valid allowed hosts)"),
      expect.stringContaining(`egress proxy is disabled: ${KEY}`),
    ]);
    expect(looksLikeSecretSentinel(withProxy.env[KEY]!)).toBe(true);
    expect(withProxy.env.NO_HOSTS).toBeUndefined();
    expectNoLeak({ ...withoutProxy.surfaces, withProxy: withProxy.surfaces });
  });

  it("OpenClaw-set > plugin resolve_exec_env > per-call env > session secrets > team store", async () => {
    const teamSentinel = sealSecretSentinel(`team-${value}`, { label: "exec-store:BOTH_SECRET" });
    entries(
      ...["OWNED_KEY", "CALL_KEY", "PLUGIN_KEY", "CALL_AND_PLUGIN", "BOTH_ENV", "INHERITED"].map(
        (name) => ({
          name,
          kind: "env" as const,
          value: `${name}-${value}`,
        }),
      ),
      { name: "BOTH_SECRET", value, allowedHosts: ["api.example.test"] },
    );
    await enable();
    activateProxy();
    vi.stubEnv("INHERITED", "inherited");
    mocks.hookRunner = {
      hasHooks: (name: string) => name === "resolve_exec_env",
      runResolveExecEnv: vi.fn(async () => ({
        PLUGIN_KEY: "from-plugin",
        CALL_AND_PLUGIN: "from-plugin",
      })),
      runBeforeToolCall: vi.fn(),
    };
    const result = await execToolInTurn(
      turn("bob"),
      { command: "echo ok", env: { CALL_KEY: "per-call", CALL_AND_PLUGIN: "per-call" } },
      {
        defaults: {
          operationalRunInstance: createOperationalRunInstanceRef(`run-${randomUUID()}`),
          preparedRunEnvironment: {
            credentialScrubEnv: {},
            localIdentityEnv: { OWNED_KEY: "openclaw" },
            excludedStoreNames: [],
            managedLocalIdentity: true,
          },
          preparedStoreEnvironment: {
            env: { BOTH_ENV: "team", STORE_ONLY: "team" },
            secretSentinels: { BOTH_SECRET: teamSentinel },
            secretEgressBindings: [
              { name: "BOTH_SECRET", sentinel: teamSentinel, allowedHosts: ["team.example.test"] },
            ],
          },
        },
      },
    );

    const env = mocks.spawnInputs.at(-1)?.env ?? {};
    expect(env).toMatchObject({
      OWNED_KEY: "openclaw",
      CALL_KEY: "per-call",
      PLUGIN_KEY: "from-plugin",
      CALL_AND_PLUGIN: "from-plugin",
      BOTH_ENV: `BOTH_ENV-${value}`,
      INHERITED: `INHERITED-${value}`,
      STORE_ONLY: "team",
    });
    expect(resolveSecretSentinel(env.BOTH_SECRET!)).toBe(value);
    // The team-store binding of the same name is replaced, not registered alongside.
    expect(registered).toEqual([
      [{ name: "BOTH_SECRET", sentinel: env.BOTH_SECRET, allowedHosts: ["api.example.test"] }],
    ]);
    expectNoLeak({
      requestedEnv: mocks.gatewayParams.map((params) => params.requestedEnv),
      toolResult: result,
      logs,
    });
  });

  it("a command launched after the creator turned them off runs without them and says so once", async () => {
    const neverOn = await execToolInTurn(turn("bob"), { command: "echo ok" });
    await enable();
    disableSessionSecrets(target(), people.alice);
    const afterOff = await execToolInTurn(turn("bob"), { command: "echo ok" });
    const later = await execToolInTurn(turn("bob"), { command: "echo ok" });

    expect(mocks.spawnInputs.map((input) => input.env?.[KEY])).toEqual([
      undefined,
      undefined,
      undefined,
    ]);
    expect(JSON.stringify(neverOn)).not.toContain(SESSION_SECRETS_OFF_NOTICE);
    expect(JSON.stringify(afterOff)).toContain(SESSION_SECRETS_OFF_NOTICE);
    // Said once: later launches run without them silently.
    expect(JSON.stringify(later)).not.toContain(SESSION_SECRETS_OFF_NOTICE);
    expectNoLeak({ neverOn, afterOff, later, logs });
  });

  it.each([
    [
      "sandbox",
      {
        sandbox: {
          containerName: "sandbox",
          workspaceDir: "/workspace",
          containerWorkdir: "/workspace",
          buildExecSpec: async ({ env }: { env: Record<string, string> }) => ({
            argv: ["sh", "-c", "echo ok"],
            env,
            stdinMode: "pipe-closed" as const,
          }),
        },
      },
    ],
    ["durable", { durable: { notifyOnExit: false, notifyOnExitEmptySuccess: false } }],
  ] as const)("%s exec gets nothing and a warning", async (kind, overrides) => {
    await enable();
    const { env, warnings, surfaces } = await launch(turn("alice"), overrides as never);
    expect(env.BASE).toBe("1");
    expect(env[KEY]).toBeUndefined();
    expect(warnings).toEqual([
      `Session secrets were not provided to this command: ${kind} exec is not supported.`,
    ]);
    expect(kind === "durable" ? mocks.durableInputs : mocks.spawnInputs).toHaveLength(1);
    expectNoLeak(surfaces);
  });

  it("session secrets ending between lookup and spawn fail the launch closed", async () => {
    await enable();
    mocks.beforeNativeSpawn = () => disableSessionSecrets(target(), people.alice);
    const warnings: string[] = [];
    await expect(
      withGatewayToolCallerIdentity(turn("alice"), () =>
        runExecFixture({
          warnings,
          sessionKey: SESSION,
          sessionId: SESSION_ID,
          agentId: AGENT,
          sessionSecrets: { target: target() },
        }),
      ),
    ).rejects.toThrow(SESSION_SECRETS_ENDED_ERROR);
    expect(mocks.spawnInputs).toHaveLength(0);
    expectNoLeak({ warnings, logs });
  });

  it("another agent or another store get nothing", async () => {
    await enable();
    const delivered = await launch(turn("alice"));
    const otherAgent = await launch(turn("alice", "other"));
    const otherStore = await execToolInTurn(
      turn("alice"),
      { command: "echo ok" },
      { storeScope: OTHER_STORE },
    );

    expect(delivered.env[KEY]).toBe(value);
    expect(otherAgent.env[KEY]).toBeUndefined();
    expect(mocks.spawnInputs.at(-1)?.env?.[KEY]).toBeUndefined();
    expect(readSessionSecretsCreatorForTest(target())).toBe(people.alice);
    expectNoLeak({ ...delivered.surfaces, otherAgent: otherAgent.surfaces, otherStore });
  });

  it("a reset session or a Gateway restart ends them; status then reads off", async () => {
    await enable();
    const resetSession = await launch(turn("alice"), { sessionId: "after-reset" });
    const afterReset = await launch(turn("alice"), { sessionId: "after-reset" });
    expect(readSessionSecretsCreatorForTest(target())).toBeUndefined();
    // `/new` on a dashboard session keeps its sessionId and rotates only lifecycleRevision.
    await enable();
    await writeSession(SESSION, { createdActor: ALICE, lifecycleRevision: randomUUID() });
    const rotated = await launch(turn("alice"));
    expect(readSessionSecretsCreatorForTest(target())).toBeUndefined();
    await enable();
    resetSessionSecretsForTest();
    const restarted = await launch(turn("alice"));

    for (const result of [resetSession, afterReset, rotated, restarted]) {
      expect(result.env[KEY]).toBeUndefined();
    }
    expect(resetSession.warnings).toEqual([SESSION_SECRETS_OFF_NOTICE]);
    expect(afterReset.warnings).toEqual([]);
    expect(rotated.warnings).toEqual([SESSION_SECRETS_OFF_NOTICE]);
    // A restart forgets everything, including that they were ever on.
    expect(restarted.warnings).toEqual([]);
    expectNoLeak({
      resetSession: resetSession.surfaces,
      afterReset: afterReset.surfaces,
      rotated: rotated.surfaces,
      restarted: restarted.surfaces,
    });
  });

  it("entryNames delivers only the selected entries", async () => {
    entries({ name: "A", kind: "env", value }, { name: "B", kind: "env", value: `b-${value}` });
    await enable(people.alice, { entryNames: ["A"] });
    const { env, surfaces } = await launch(turn("alice"));
    expect(env.A).toBe(value);
    expect(env.B).toBeUndefined();
    expectNoLeak(surfaces);
  });

  it("invalid, reserved, NUL and oversize entries are rejected by name only", async () => {
    const rejected = {
      "bad-name": `x-${value}`,
      lower_case: `l-${value}`,
      GH_TOKEN: `gh-${value}`,
      LD_PRELOAD: `ld-${value}`,
      OPENCLAW_SHELL: `oc-${value}`,
      NUL_VALUE: `a\0${value}`,
      // Over the team store's 64 KiB value limit.
      BIG: `${value}${"x".repeat(64 * 1024)}`,
    };
    entries(
      ...Object.entries(rejected).map(([name, entryValue]) => ({
        name,
        kind: "env" as const,
        value: entryValue,
      })),
    );
    await enable();
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
      "one entry with an invalid name, one entry with an invalid name",
    ]) {
      expect(warnings[0]).toContain(part);
    }
    expectNoLeak(surfaces);
  });

  it("protected entries skip the host-env denylist, as team-store secrets do", async () => {
    entries(
      { name: "GH_TOKEN", value, allowedHosts: ["api.github.com"] },
      { name: "NODE_OPTIONS", value: `n-${value}`, allowedHosts: ["api.example.test"] },
    );
    await enable();
    activateProxy();
    const { env, warnings, surfaces } = await launch(turn("alice"));

    expect(resolveSecretSentinel(env.GH_TOKEN!)).toBe(value);
    expect(resolveSecretSentinel(env.NODE_OPTIONS!)).toBe(`n-${value}`);
    expect(warnings).toEqual([]);
    expectNoLeak(surfaces);
  });
});
