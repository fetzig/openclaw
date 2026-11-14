import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, beforeEach, expect, vi } from "vitest";
import { resolveSessionStorePathCore } from "../config/sessions/paths.js";
import { replaceSessionEntry } from "../config/sessions/session-accessor.js";
import { addSessionMember } from "../config/sessions/session-sharing-store.native.js";
import type { SessionEntry } from "../config/sessions/types.js";
import {
  registerSessionBindingAdapterV2,
  unregisterSessionBindingAdapter,
  type SessionBindingAdapterV2,
  type SessionBindingRecord,
} from "../infra/outbound/session-binding-service.js";
import type { SecretEgressSentinelBinding } from "../secrets/egress-proxy/proxy-server.js";
import {
  clearSecretEgressProxy,
  publishSecretEgressProxy,
} from "../secrets/egress-proxy/registry.js";
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
import type { ExecToolDefaults } from "./bash-tools.exec-types.js";
import { createOperationalRunInstanceRef } from "./operational-run-instance.js";
import {
  readSessionSecretsStatus,
  setSessionSecretValueProviderForTest,
  type SessionSecretEntry,
} from "./session-secrets.js";
import type { ExtensionContext } from "./sessions/index.js";
import { withGatewayToolCallerIdentity } from "./tools/gateway-caller-context.js";

/**
 * The session-secrets suite's shared harness: Alice, Bob and Carol as verified profiles,
 * Alice's session, a synthetic vault provider, launches through runExecProcess, and leak
 * checks. Exported `let` bindings are live: hooks reset them for every test.
 */
/** Mock state each session-secrets test file hoists and shares with its `vi.mock` factories. */
export type SessionSecretsMocks = {
  hookRunner:
    | {
        hasHooks: (name: string) => boolean;
        runResolveExecEnv: ReturnType<typeof vi.fn>;
        runBeforeToolCall: ReturnType<typeof vi.fn>;
      }
    | undefined;
  gatewayParams: CapturedEnvironment[];
  nodeHostParams: CapturedEnvironment[];
  spawnInputs: Array<{ env?: Record<string, string> }>;
  durableInputs: Array<{ env?: Record<string, string> }>;
  /** PTY construction fails before launch, so runExecProcess retries without a PTY. */
  failPty: boolean;
  /** Records the generic binding store returns per session key. */
  storeBindings: Map<string, SessionBindingRecord[]>;
};
let mocks: SessionSecretsMocks;

let createExecTool: typeof import("./bash-tools.exec-run.js").createExecTool;
let toToolDefinitions: typeof import("./agent-tool-definition-adapter.js").toToolDefinitions;

export const AGENT = "main";
export const SESSION = "agent:main:dashboard:vault";
export const SESSION_ID = "vault-session";
export const OTHER_STORE = "/synthetic/session-secrets/other-sessions";
export const KEY = "VAULT_TEST_TOKEN";
/** Verified Gateway profiles, created in beforeAll; Alice's old profile was merged into hers. */
export const people = { alice: "", aliceOld: "", bob: "", carol: "" };
export const human = (id: string) => ({ type: "human", source: "profile", id }) as const;
export let ALICE: ReturnType<typeof human>;
let state: OpenClawTestState;
let releaseProfileCatalog: (() => void) | undefined;
export let store: string;
export let value: string;
export let logs: string[];
/** Bindings each launch registered with the egress proxy, when one is active. */
export let registered: SecretEgressSentinelBinding[][];
/** Indexes into `registered` whose grant was revoked. */
export let revoked: number[];
let proxy:
  | { registerProcess: (bindings?: readonly SecretEgressSentinelBinding[]) => unknown }
  | undefined;

export const target = (sessionKey = SESSION) => ({ storeScope: store, agentId: AGENT, sessionKey });
/** The synthetic vault: each profile's current entries, changed between launches by tests. */
export const vault = new Map<string, readonly SessionSecretEntry[]>();
/** Alice's entries from now on. */
export const entries = (...list: SessionSecretEntry[]) => vault.set(people.alice, list);
/** Every provider call, names and values alike. */
export let providerCalls: string[];
export const authority = (profileId: string) =>
  createAdmittedRunOperatorAuthority({ profileId, scopes: [], assertCurrent: () => {} });

/** One admitted turn; `profileId` is whoever prompted it. */
export const turn = (person: keyof typeof people | undefined, agentId = AGENT) => ({
  agentId,
  sessionKey: SESSION,
  operationalRunInstance: createOperationalRunInstanceRef(`run-${randomUUID()}`),
  ...(person ? { operatorAuthority: authority(people[person]) } : {}),
});

/** A Gateway egress proxy stand-in that records each launch's bindings. */
export function activateProxy() {
  proxy = {
    registerProcess: (bindings = []) => {
      const index = registered.push([...bindings]) - 1;
      return {
        env: { HTTPS_PROXY: "http://openclaw:token@127.0.0.1:9" },
        revoke: () => void revoked.push(index),
      };
    },
  };
  publishSecretEgressProxy(proxy as never);
}

/** Launches one command through runExecProcess as the given turn; returns every observable surface. */
export async function launch(
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
export function expectNoLeak(surfaces: Record<string, unknown>) {
  for (const [name, surface] of Object.entries(surfaces)) {
    expect(JSON.stringify(surface) ?? "", `${name} leaked the value`).not.toContain(value);
  }
}

/** Runs the exec tool inside a session turn of the given store, as an agent turn does. */
export async function execToolInTurn(
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

export async function writeSession(sessionKey: string, fields: Partial<SessionEntry>) {
  await replaceSessionEntry(
    { agentId: AGENT, sessionKey, storePath: store },
    { sessionId: SESSION_ID, updatedAt: Date.now(), ...fields },
  );
}

/** A fresh session of Alice's with the given fields; returns its key. */
export async function aliceSession(fields: Partial<SessionEntry> = {}) {
  const sessionKey = `agent:main:dashboard:alice-${randomUUID()}`;
  await writeSession(sessionKey, { createdActor: ALICE, ...fields });
  return sessionKey;
}
export const launchIn = (sessionKey: string, person: keyof typeof people | undefined) =>
  launch(turn(person), { sessionKey, sessionSecrets: { target: target(sessionKey) } });
/** Launches by Alice, Bob and no person, and the status Alice sees. */
export async function probe(sessionKey: string) {
  const results = [];
  for (const person of ["alice", "bob", undefined] as const) {
    results.push(await launchIn(sessionKey, person));
  }
  return {
    values: results.map(({ env }) => env[KEY]),
    warnings: results.flatMap(({ warnings }) => warnings),
    status: await readSessionSecretsStatus(target(sessionKey), people.alice),
    surfaces: Object.fromEntries(results.map(({ surfaces }, index) => [index, surfaces])),
  };
}
export const addMember = (sessionKey: string, person: keyof typeof people) =>
  addSessionMember(
    { agentId: AGENT, sessionKey, storePath: store },
    { identityId: people[person], addedBy: people.alice },
  );

/** Registers the suite's hooks; each test file passes its hoisted `vi.mock` state. */
export function installSessionSecretsHarness(suiteMocks: SessionSecretsMocks) {
  mocks = suiteMocks;
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
    revoked = [];
    mocks.failPty = false;
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
    providerCalls = [];
    setSessionSecretValueProviderForTest({
      listNames: (profileId) => {
        providerCalls.push(`listNames:${profileId}`);
        return (vault.get(profileId) ?? []).map(({ name, kind = "secret", allowedHosts }) => ({
          name,
          kind,
          allowedHosts,
        }));
      },
      readEntries: (profileId) => {
        providerCalls.push(`readEntries:${profileId}`);
        return vault.get(profileId) ?? [];
      },
    });
    entries({ name: KEY, kind: "env", value });
    mocks.spawnInputs.length = 0;
    mocks.durableInputs.length = 0;
    mocks.gatewayParams.length = 0;
    mocks.hookRunner = undefined;
    mocks.storeBindings.clear();
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
}

/** A sandbox backend for launches that must get nothing and say why. */
export const sandboxBackend = {
  containerName: "sandbox",
  workspaceDir: "/workspace",
  containerWorkdir: "/workspace",
  buildExecSpec: async ({ env }: { env: Record<string, string> }) => ({
    argv: ["sh", "-c", "echo ok"],
    env,
    stdinMode: "pipe-closed" as const,
  }),
};

/**
 * A channel's binding owner, registered in the process-wide adapter registry as a
 * thread-binding or plugin adapter registers it; tests bind and unbind sessions, or make
 * listing fail.
 */
export function installBindingOwner(ownerChannel = "matrix") {
  const bindings: SessionBindingRecord[] = [];
  const owner = { failing: false };
  const listBySession = (key: string) => {
    if (owner.failing) {
      throw new Error("binding store unavailable");
    }
    return bindings.filter((binding) => binding.targetSessionKey === key);
  };
  const adapter: SessionBindingAdapterV2 = {
    version: 2,
    channel: ownerChannel,
    accountId: "default",
    assertCurrent: () => {},
    listBySession,
    listBySessionAsync: async (key) => listBySession(key),
    resolveByConversation: () => null,
    resolveByConversationAsync: async () => null,
    inspectByConversationAsync: async () => null,
    inspectByConversationsAsync: async (refs) => ({
      bindings: refs.map(() => null),
      assertCurrent: () => {},
    }),
    touchAsync: async () => {},
  };
  registerSessionBindingAdapterV2(adapter);
  // In a Gateway, internal-channel bindings live in the generic store; the service merges
  // every owner's records, so this owner can stand in for either.
  const bind = (
    targetSessionKey: string,
    metadata?: Record<string, unknown>,
    channel = ownerChannel,
  ) =>
    bindings.push({
      bindingId: `binding-${randomUUID()}`,
      targetSessionKey,
      targetKind: "session",
      status: "active",
      boundAt: Date.now(),
      conversation: { channel, accountId: "default", conversationId: `${channel}-${randomUUID()}` },
      ...(metadata ? { metadata } : {}),
    });
  return {
    bind,
    owner,
    unbindAll: () => void bindings.splice(0),
    uninstall: () =>
      unregisterSessionBindingAdapter({ channel: ownerChannel, accountId: "default", adapter }),
  };
}
