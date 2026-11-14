import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { GATEWAY_OWNER_PROFILE_ID } from "../../packages/gateway-protocol/src/schema/user-profile-constants.js";
import { resolveSessionStorePathCore } from "../config/sessions/paths.js";
import {
  assignSessionOwner,
  loadSessionEntry,
  replaceSessionEntry,
} from "../config/sessions/session-accessor.js";
import { addSessionMember } from "../config/sessions/session-sharing-store.native.js";
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
import { ensureGatewayOwnerProfile, ensureProfileForEmail } from "../state/user-profiles.js";
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
  readSessionSecretsStatus,
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
/** The synthetic vault: each profile's current entries, changed between launches by tests. */
const vault = new Map<string, readonly SessionSecretEntry[]>();
/** Alice's entries from now on. */
const entries = (...list: SessionSecretEntry[]) => vault.set(people.alice, list);
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
  ensureGatewayOwnerProfile(null);
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
  vault.clear();
  setSessionSecretValueProviderForTest({
    listNames: (profileId) => (vault.get(profileId) ?? []).map((entry) => entry.name),
    readEntries: (profileId) => vault.get(profileId) ?? [],
  });
  entries({ name: KEY, kind: "env", value });
  mocks.spawnInputs.length = 0;
  mocks.durableInputs.length = 0;
  mocks.gatewayParams.length = 0;
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

describe("whose secrets a session uses", () => {
  type Name = "alice" | "bob";
  it.each<[string, () => Partial<SessionEntry> & { assignTo?: Name }, Name | undefined]>([
    ["the profile creator", () => ({ createdActor: ALICE }), "alice"],
    // The assignable owner never counts; the creator keeps them.
    [
      "the creator after Bob became owner",
      () => ({ createdActor: ALICE, assignTo: "bob" }),
      "alice",
    ],
    // Upstream's creator rule: a merged profile counts and reads the canonical vault.
    ["Alice's merged profile", () => ({ createdActor: human(people.aliceOld) }), "alice"],
    // A creation an agent made for Alice is hers.
    [
      "an agent on Alice's behalf",
      () => ({ createdActor: { type: "agent", id: "main", delegatedBy: ALICE } }),
      "alice",
    ],
    [
      "a child session Alice created",
      () => ({ createdActor: ALICE, parentSessionKey: SESSION }),
      "alice",
    ],
    ["a session spawned for Alice", () => ({ createdActor: ALICE, spawnedBy: SESSION }), "alice"],
    // cronExecutionActor stamps the job owner's profile on isolated and current run sessions.
    [
      "a cron run session of Alice's job",
      () => ({ createdActor: ALICE, createdVia: "cron", parentSessionKey: SESSION }),
      "alice",
    ],
    // The parent's creator never leaks into a session someone else created.
    [
      "a child Bob created under Alice's session",
      () => ({ createdActor: human(people.bob), parentSessionKey: SESSION }),
      "bob",
    ],
    [
      "a child an agent created under Alice's session",
      () => ({ createdActor: { type: "agent", id: "main" }, parentSessionKey: SESSION }),
      undefined,
    ],
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
    ["an unverified profile id", () => ({ createdActor: human("not-a-profile") }), undefined],
    ["an agent", () => ({ createdActor: { type: "agent", id: "main" } }), undefined],
    ["an automation", () => ({ createdActor: { type: "system", id: "cron" } }), undefined],
    [
      "Carol through an agent",
      () => ({
        createdActor: { ...human(people.carol), delegatedBy: { type: "agent", id: "main" } },
      }),
      undefined,
    ],
    ["no recorded creator", () => ({}), undefined],
    // Every token or password connection signs in as this one profile; it is not a person.
    [
      "the shared Gateway owner profile",
      () => ({ createdActor: human(GATEWAY_OWNER_PROFILE_ID) }),
      undefined,
    ],
    [
      "an agent on the Gateway owner's behalf",
      () => ({
        createdActor: { type: "agent", id: "main", delegatedBy: human(GATEWAY_OWNER_PROFILE_ID) },
      }),
      undefined,
    ],
  ])("%s", async (_label, fields, creator) => {
    for (const [person, entryValue] of [
      [people.bob, `bob-${value}`],
      [people.carol, `carol-${value}`],
      [GATEWAY_OWNER_PROFILE_ID, `owner-${value}`],
      ["not-a-profile", `unverified-${value}`],
    ]) {
      vault.set(person!, [{ name: KEY, kind: "env", value: entryValue! }]);
    }
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
    const expected = vault.get(creator ? people[creator] : "")?.[0]?.value;
    // Whoever causes the turn, or no person at all, the session's creator decides.
    for (const person of ["alice", "bob", "carol", undefined] as const) {
      const { env, warnings, surfaces } = await launchIn(sessionKey, person);
      expect(env[KEY], String(person)).toBe(expected);
      expect(warnings).toEqual([]);
      expectNoLeak(surfaces);
    }
  });
});

/** A fresh session of Alice's with the given fields; returns its key. */
async function aliceSession(fields: Partial<SessionEntry> = {}) {
  const sessionKey = `agent:main:dashboard:alice-${randomUUID()}`;
  await writeSession(sessionKey, { createdActor: ALICE, ...fields });
  return sessionKey;
}
const launchIn = (sessionKey: string, person: keyof typeof people | undefined) =>
  launch(turn(person), { sessionKey, sessionSecrets: { target: target(sessionKey) } });
const addMember = (sessionKey: string, person: keyof typeof people) =>
  addSessionMember(
    { agentId: AGENT, sessionKey, storePath: store },
    { identityId: people[person], addedBy: people.alice },
  );

describe("the creator's vault is the switch", () => {
  it("each launch reads the creator's current entries", async () => {
    const stored = await launchIn(SESSION, "bob");
    // Alice deletes her entry and stores another one.
    entries({ name: "ADDED", kind: "env", value: `added-${value}` });
    const changed = await launchIn(SESSION, "bob");
    vault.delete(people.alice);
    const emptied = await launchIn(SESSION, "bob");

    expect([stored, changed, emptied].map(({ env }) => [env[KEY], env.ADDED])).toEqual([
      [value, undefined],
      [undefined, `added-${value}`],
      [undefined, undefined],
    ]);
    // Storing and deleting entries are the opt-in and opt-out: no notices.
    expect([stored, changed, emptied].flatMap(({ warnings }) => warnings)).toEqual([]);
    expectNoLeak({ stored: stored.surfaces, changed: changed.surfaces, emptied: emptied.surfaces });
  });

  it("sharing, visibility, members, owner and resets change nothing", async () => {
    const sessionKey = await aliceSession({ visibility: "draft" });
    const results = [await launchIn(sessionKey, "alice")];
    for (const visibility of ["read-only", "suggest", "shared", "draft"] as const) {
      await writeSession(sessionKey, { createdActor: ALICE, visibility });
      results.push(await launchIn(sessionKey, "bob"));
    }
    addMember(sessionKey, "carol");
    const scope = { agentId: AGENT, sessionKey, storePath: store };
    const bob = { type: "human" as const, id: people.bob };
    assignSessionOwner(scope, { owner: bob, assignedBy: bob });
    results.push(await launchIn(sessionKey, "carol"));
    // `/new` rotates lifecycleRevision; a reset session gets a new sessionId.
    await writeSession(sessionKey, { createdActor: ALICE, lifecycleRevision: randomUUID() });
    results.push(
      await launch(turn("bob"), {
        sessionKey,
        sessionId: "after-reset",
        sessionSecrets: { target: target(sessionKey) },
      }),
    );

    expect(results.map(({ env }) => env[KEY])).toEqual(results.map(() => value));
    expect(results.flatMap(({ warnings }) => warnings)).toEqual([]);
    expectNoLeak(Object.fromEntries(results.map(({ surfaces }, index) => [index, surfaces])));
  });

  it("status shows session participants the creator and entry names, never values", async () => {
    entries(
      { name: KEY, kind: "env", value },
      { name: "API_SECRET", value, allowedHosts: ["api.example.test"] },
    );
    const sessionKey = await aliceSession({ visibility: "draft" });
    const read = (person: keyof typeof people) =>
      readSessionSecretsStatus(target(sessionKey), people[person]);
    const statuses = { alice: await read("alice"), bobInDraft: await read("bob") };
    await writeSession(sessionKey, { createdActor: ALICE, visibility: "read-only" });
    const bobInReadOnly = await read("bob");
    vault.delete(people.alice);
    const afterDelete = await read("alice");

    const expected = { creatorProfileId: people.alice, entryNames: ["API_SECRET", KEY] };
    expect(statuses.alice).toEqual(expected);
    // Bob cannot see Alice's Draft; her Read-only session he can see.
    expect(statuses.bobInDraft).toBeUndefined();
    expect(bobInReadOnly).toEqual(expected);
    expect(afterDelete).toBeUndefined();
    expectNoLeak({ statuses, bobInReadOnly });
  });

  it("a launch names one session however its key is spelled", async () => {
    // The agent-relative alias reads the canonical session entry.
    const alias = { storeScope: store, agentId: AGENT, sessionKey: "dashboard:vault" };
    const { env, surfaces } = await launch(turn("bob"), { sessionSecrets: { target: alias } });
    expect(env[KEY]).toBe(value);
    expectNoLeak(surfaces);
  });
});

describe("session secrets at launch", () => {
  it("every turn uses the creator's entries through the exec tool, whoever caused it", async () => {
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

    // A turn that acts for no person (a channel sender, a hook, a system dispatch) gets them too.
    expect(mocks.spawnInputs.map((input) => input.env?.[KEY])).toEqual([value, value, value]);
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
    const { env, warnings, surfaces } = await launch(turn("alice"), overrides as never);
    // A creator without entries has nothing withheld, so there is nothing to say.
    vault.delete(people.alice);
    const empty = await launch(turn("alice"), overrides as never);
    expect(env.BASE).toBe("1");
    expect(env[KEY]).toBeUndefined();
    expect(warnings).toEqual([
      `Session secrets were not provided to this command: ${kind} exec is not supported.`,
    ]);
    expect(empty.warnings).toEqual([]);
    expect(kind === "durable" ? mocks.durableInputs : mocks.spawnInputs).toHaveLength(2);
    expectNoLeak({ ...surfaces, empty: empty.surfaces });
  });

  it("another agent or another store get nothing", async () => {
    const delivered = await launch(turn("alice"));
    // The other agent's session of the same name lives in its own store; Alice did not create it.
    const otherTarget = {
      storeScope: resolveSessionStorePathCore(undefined, { agentId: "other" }),
      agentId: "other",
      sessionKey: "agent:other:dashboard:vault",
    };
    const otherAgent = await launch(turn("alice", "other"), {
      sessionKey: otherTarget.sessionKey,
      sessionSecrets: { target: otherTarget },
    });
    const otherStore = await execToolInTurn(
      turn("alice"),
      { command: "echo ok" },
      { storeScope: OTHER_STORE },
    );

    expect(delivered.env[KEY]).toBe(value);
    expect(otherAgent.env[KEY]).toBeUndefined();
    expect(mocks.spawnInputs.at(-1)?.env?.[KEY]).toBeUndefined();
    expectNoLeak({ ...delivered.surfaces, otherAgent: otherAgent.surfaces, otherStore });
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
    activateProxy();
    const { env, warnings, surfaces } = await launch(turn("alice"));

    expect(resolveSecretSentinel(env.GH_TOKEN!)).toBe(value);
    expect(resolveSecretSentinel(env.NODE_OPTIONS!)).toBe(`n-${value}`);
    expect(warnings).toEqual([]);
    expectNoLeak(surfaces);
  });
});
