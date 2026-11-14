import { randomUUID } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GATEWAY_OWNER_PROFILE_ID } from "../../packages/gateway-protocol/src/schema/user-profile-constants.js";
import {
  clearRuntimeConfigSnapshot,
  setRuntimeConfigSnapshot,
} from "../config/runtime-snapshot.js";
import { resolveSessionStorePathCore } from "../config/sessions/paths.js";
import {
  assignSessionOwner,
  loadSessionEntry,
  replaceSessionEntry,
} from "../config/sessions/session-accessor.js";
import type { SessionEntry } from "../config/sessions/types.js";
import type { SessionBindingRecord } from "../infra/outbound/session-binding-service.js";
import { isSecretValueRegisteredForRedaction } from "../logging/secret-redaction-registry.js";
import type { SpawnInput } from "../process/supervisor/types.js";
import {
  looksLikeSecretSentinel,
  resolveSecretSentinel,
  sealSecretSentinel,
} from "../secrets/sentinel.js";
import { INTERNAL_MESSAGE_CHANNEL } from "../utils/message-channel-constants.js";
import type { CapturedEnvironment } from "./bash-tools.exec-env.test-support.js";
import { runtimeManagedRun } from "./bash-tools.exec-runtime.test-support.js";
import {
  activateProxy,
  addMember,
  AGENT,
  ALICE,
  aliceSession,
  entries,
  execToolInTurn,
  expectNoLeak,
  human,
  installBindingOwner,
  installSessionSecretsHarness,
  KEY,
  launch,
  launchIn,
  logs,
  OTHER_STORE,
  people,
  probe,
  providerCalls,
  registered,
  revoked,
  sandboxBackend as sandbox,
  SESSION,
  SESSION_ID,
  store,
  target,
  turn,
  value,
  vault,
  writeSession,
} from "./bash-tools.exec.session-secrets.test-support.js";
import { createOperationalRunInstanceRef } from "./operational-run-instance.js";
import { readSessionSecretsStatus } from "./session-secrets.js";

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
  /** PTY construction fails before launch, so runExecProcess retries without a PTY. */
  failPty: false,
  storeBindings: new Map<string, SessionBindingRecord[]>(),
}));

// mock-isolation: Each test installs its own plugin hooks instead of the global registry.
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
// mock-isolation: The generic binding store runs on the Gateway's state-worker broker, which
// vitest worker threads lack; tests stage its records per session key, registered binding
// owners stay real, and the E2E covers the store itself.
vi.mock("../infra/outbound/current-conversation-bindings.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../infra/outbound/current-conversation-bindings.js")>()),
  listGenericCurrentConversationBindingsBySessionsAsync: async (keys: readonly string[]) =>
    keys.map((key) => mocks.storeBindings.get(key) ?? []),
}));
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
      if (mocks.failPty && input.mode === "pty") {
        throw new Error("PTY unavailable");
      }
      mocks.spawnInputs.push({
        env: input.env ? { ...(input.env as Record<string, string>) } : {},
      });
      return runtimeManagedRun(input, "ok\n");
    },
    cancel: vi.fn(),
    cancelScope: vi.fn(),
  }),
}));

installSessionSecretsHarness(mocks);

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
    // parentSessionKey alone is no spawn: people's own New Chat, child and fork carry it.
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

describe("sessions channel traffic can reach use no one's secrets", () => {
  afterEach(() => clearRuntimeConfigSnapshot());

  const MAIN = "main-session";
  const CHANNEL = "channel-session";
  type Session = { mainKey?: string; scope?: "global" };
  it.each<[string, string, Session | undefined, string | undefined]>([
    // Alice sent the first message in each of these; DMs or groups can still land there.
    ["the agent's main session", "agent:main:main", undefined, MAIN],
    // Own agents: one store with both main rows needs a doctor migration under mainKey "work".
    ["the main session under a custom mainKey", "agent:work1:work", { mainKey: "work" }, MAIN],
    // The upstream main alias stays the main session when mainKey changes.
    ["the main alias under a custom mainKey", "agent:work2:main", { mainKey: "work" }, MAIN],
    // Slack Assistant DM threads and Telegram DM topics thread under the main session.
    [
      "a thread under the main session",
      "agent:main:work:thread:1700000000.000100",
      { mainKey: "work" },
      MAIN,
    ],
    // Under the global scope every inbound message lands in the one `global` session.
    ["the global session", "global", { scope: "global" }, MAIN],
    ["a per-peer DM", "agent:main:direct:+15550001", undefined, CHANNEL],
    ["a per-channel-peer DM", "agent:main:whatsapp:direct:+15550001", undefined, CHANNEL],
    ["a per-account DM", "agent:main:telegram:default:direct:12345", undefined, CHANNEL],
    ["a group", "agent:main:whatsapp:group:120363@g.us", undefined, CHANNEL],
    [
      "a bound thread",
      "agent:main:slack:channel:c0123:thread:1700000000.000100",
      undefined,
      CHANNEL,
    ],
    // Controls: ordinary sessions still deliver, and only the configured main key is main.
    ["Alice's dashboard session", "agent:main:dashboard:control", undefined, undefined],
    ["a session named like a custom mainKey", "agent:main:work", undefined, undefined],
    [
      "the dashboard under a custom mainKey",
      "agent:main:dashboard:control",
      { mainKey: "work" },
      undefined,
    ],
  ])("%s", async (_label, sessionKey, session, excluded) => {
    const delivers = !excluded;
    if (session) {
      setRuntimeConfigSnapshot({ session });
    }
    // `global` names no agent; it lives in its own agent's store here.
    const agentId = sessionKey.split(":")[1] ?? "scoped";
    const where = {
      storeScope: resolveSessionStorePathCore(undefined, { agentId }),
      agentId,
      sessionKey,
    };
    // A Gateway persists the main alias under the configured mainKey.
    const storedKey = session?.mainKey
      ? sessionKey.replace(/:main$/, `:${session.mainKey}`)
      : sessionKey;
    await replaceSessionEntry(
      { agentId, sessionKey: storedKey, storePath: where.storeScope },
      { sessionId: SESSION_ID, updatedAt: Date.now(), createdActor: ALICE },
    );
    const launchAs = (person: keyof typeof people | undefined, extra = {}) =>
      launch(turn(person, agentId), { sessionKey, sessionSecrets: { target: where }, ...extra });
    const results = [];
    for (const person of ["alice", "bob", undefined] as const) {
      results.push(await launchAs(person));
    }
    // Unsupported launches stay silent there too: nothing was withheld.
    const sandboxed = await launchAs("alice", { sandbox });
    const status = await readSessionSecretsStatus(where, people.alice);

    expect(results.map(({ env }) => env[KEY])).toEqual(
      results.map(() => (delivers ? value : undefined)),
    );
    expect(results.flatMap(({ warnings }) => warnings)).toEqual([]);
    expect(sandboxed.warnings).toEqual(
      delivers
        ? [`Session secrets were not provided to this command: sandbox exec is not supported.`]
        : [],
    );
    // Status says why; commands get no notice.
    expect(status).toEqual(
      delivers ? { creatorProfileId: people.alice, entryNames: [KEY] } : { excluded },
    );
    if (!delivers) {
      // Refused before anything is read, as for a creator without entries.
      expect(providerCalls).toEqual([]);
    }
    expectNoLeak({
      ...Object.fromEntries(results.map(({ surfaces }, index) => [index, surfaces])),
      status,
    });
  });
});

describe("sessions bound to a channel conversation use no one's secrets", () => {
  let owner: ReturnType<typeof installBindingOwner>;
  beforeEach(() => {
    owner = installBindingOwner();
  });
  afterEach(() => owner.uninstall());

  it("a thread-bound subagent gets nothing while bound, and her entries again once unbound", async () => {
    const subagent = `agent:main:subagent:${randomUUID()}`;
    const unbound = `agent:main:subagent:${randomUUID()}`;
    // Spawned in Alice's session, so they inherit her entries.
    const createdActor = { type: "agent" as const, id: "main", delegatedBy: ALICE };
    for (const sessionKey of [subagent, unbound]) {
      await writeSession(sessionKey, {
        createdActor,
        spawnedBy: SESSION,
        parentSessionKey: SESSION,
      });
    }
    owner.bind(subagent);
    const whileBound = await probe(subagent);
    const control = await probe(unbound);
    owner.unbindAll();
    const afterUnbind = await probe(subagent);

    expect(whileBound.values).toEqual([undefined, undefined, undefined]);
    expect(whileBound.status).toBeUndefined();
    for (const result of [control, afterUnbind]) {
      expect(result.values).toEqual([value, value, value]);
      expect(result.status).toMatchObject({ creatorProfileId: people.alice });
    }
    // Like a creator without entries: nothing is said.
    expect([whileBound, control, afterUnbind].flatMap(({ warnings }) => warnings)).toEqual([]);
    expectNoLeak({ ...whileBound.surfaces, status: whileBound.status });
  });

  it("a sub-agent of a bound session gets nothing, silently", async () => {
    const parent = await aliceSession();
    const child = `agent:main:subagent:${randomUUID()}`;
    await writeSession(child, {
      createdActor: { type: "agent", id: "main", delegatedBy: ALICE },
      spawnedBy: parent,
    });
    owner.bind(parent, undefined, "slack");
    const result = await probe(child);
    expect(result.values).toEqual([undefined, undefined, undefined]);
    expect(result.status).toBeUndefined();
    expect(result.warnings).toEqual([]);
    expectNoLeak(result.surfaces);
  });

  it("a binding to the internal channel alone does not count; one external binding does", async () => {
    // A plugin session catalog binds a continued session to its own Control UI conversation.
    const catalog = await aliceSession();
    owner.bind(catalog, { pluginBindingOwner: "plugin" }, INTERNAL_MESSAGE_CHANNEL);
    const internalOnly = await probe(catalog);
    const both = await aliceSession();
    owner.bind(both, undefined, INTERNAL_MESSAGE_CHANNEL);
    owner.bind(both, undefined, "slack");
    const withExternal = await probe(both);

    expect(internalOnly.values).toEqual([value, value, value]);
    expect(internalOnly.status).toMatchObject({ creatorProfileId: people.alice });
    expect(withExternal.values).toEqual([undefined, undefined, undefined]);
    expect(withExternal.status).toBeUndefined();
    expect([...internalOnly.warnings, ...withExternal.warnings]).toEqual([]);
    expectNoLeak({ ...withExternal.surfaces, status: withExternal.status });
  });

  it("a dashboard session a plugin bound gets nothing, sandboxed launches silently", async () => {
    const sessionKey = await aliceSession();
    owner.bind(sessionKey, { pluginBindingOwner: "plugin", pluginId: "example" });
    const bound = await probe(sessionKey);
    const sandboxed = await launch(turn("alice"), {
      sessionKey,
      sessionSecrets: { target: target(sessionKey) },
      sandbox,
    } as never);

    expect(bound.values).toEqual([undefined, undefined, undefined]);
    expect([...bound.warnings, ...sandboxed.warnings]).toEqual([]);
    expect(bound.status).toBeUndefined();
    expect(providerCalls).toEqual([]);
    expectNoLeak(bound.surfaces);
  });

  it("an external binding in the binding store stops delivery before the vault is read", async () => {
    const sessionKey = await aliceSession();
    // What the generic current-conversation store holds for a channel bound without an owner.
    mocks.storeBindings.set(sessionKey, [
      {
        bindingId: `generic:${randomUUID()}`,
        targetSessionKey: sessionKey,
        targetKind: "session",
        status: "active",
        boundAt: Date.now(),
        conversation: { channel: "telegram", accountId: "default", conversationId: "-100123" },
      },
    ]);
    const bound = await probe(sessionKey);
    const callsWhileBound = [...providerCalls];
    const control = await probe(await aliceSession());

    expect(bound.values).toEqual([undefined, undefined, undefined]);
    expect(bound.status).toBeUndefined();
    expect(bound.warnings).toEqual([]);
    expect(callsWhileBound).toEqual([]);
    expect(control.values).toEqual([value, value, value]);
    expectNoLeak(bound.surfaces);
  });

  it("when bindings cannot be listed, nothing is delivered and the launch still runs", async () => {
    const sessionKey = await aliceSession();
    owner.owner.failing = true;
    const failing = await probe(sessionKey);
    owner.owner.failing = false;
    const recovered = await probe(sessionKey);

    expect(failing.values).toEqual([undefined, undefined, undefined]);
    expect(failing.warnings).toEqual([]);
    expect(failing.status).toBeUndefined();
    expect(recovered.values).toEqual([value, value, value]);
    expectNoLeak(failing.surfaces);
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

  it("a PTY fallback reads the entries once and reuses them for the retry", async () => {
    entries(
      { name: KEY, value, allowedHosts: ["api.example.test"] },
      { name: "bad-name", kind: "env", value: `bad-${value}` },
    );
    activateProxy();
    mocks.failPty = true;
    const { env, warnings, surfaces } = await launch(turn("alice"), { usePty: true });

    expect(providerCalls).toEqual([`readEntries:${people.alice}`]);
    expect(warnings).toEqual([
      expect.stringContaining("one entry with an invalid name"),
      expect.stringContaining("retrying without PTY"),
    ]);
    // Each attempt gets its own grant for the same sentinel: the failed attempt's is revoked
    // before the retry, the retry's when its command exits.
    expect(registered).toHaveLength(2);
    expect(registered[1]).toEqual(registered[0]);
    expect(revoked).toEqual([0, 1]);
    expect(env[KEY]).toBe(registered[1]![0]!.sentinel);
    expect(resolveSecretSentinel(env[KEY]!)).toBe(value);
    expectNoLeak({ ...surfaces, env });
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

  it("protected entries may use credential names but not names that change how commands run", async () => {
    // Credential names on the override denylist stay usable, as for team-store secrets.
    const allowed = ["GH_TOKEN", "NPM_TOKEN", "AWS_SESSION_TOKEN"];
    // A sentinel here would break or redirect every command in the creator's sessions.
    const refused = [
      "PATH",
      "HOME",
      "NODE_OPTIONS",
      "LD_PRELOAD",
      "GIT_SSH_COMMAND",
      "HTTPS_PROXY",
      // OpenClaw sets these itself; a grant would override them.
      "OPENCLAW_SHELL",
      "OPENCLAW_GATEWAY_TOKEN",
    ];
    entries(
      ...[...allowed, ...refused].map((name) => ({
        name,
        value: `${name}-${value}`,
        allowedHosts: ["api.example.test"],
      })),
    );
    activateProxy();
    const { env, warnings, surfaces } = await launch(turn("alice"));

    for (const name of allowed) {
      expect(resolveSecretSentinel(env[name]!), name).toBe(`${name}-${value}`);
    }
    for (const name of refused) {
      expect(looksLikeSecretSentinel(env[name] ?? ""), name).toBe(false);
    }
    // OpenClaw's own marker survives: grant env would otherwise win the merge.
    expect(env.OPENCLAW_SHELL).toBe("exec");
    expect(registered[0]!.map((binding) => binding.name).toSorted()).toEqual(allowed.toSorted());
    expect(warnings).toEqual([
      `Warning: session secret entries were not provided: ${refused
        .map((name) => `${name} (reserved name)`)
        .toSorted()
        .join(", ")}.`,
    ]);
    expectNoLeak(surfaces);
  });
});
