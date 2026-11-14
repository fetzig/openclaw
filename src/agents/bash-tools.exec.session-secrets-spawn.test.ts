// Spike (openclaw#197297): sessions spawned from another session use what their parent uses.
import { randomUUID } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { resolveSessionStorePathCore } from "../config/sessions/paths.js";
import { replaceSessionEntry } from "../config/sessions/session-accessor.js";
import type { SessionBindingRecord } from "../infra/outbound/session-binding-service.js";
import type { SpawnInput } from "../process/supervisor/types.js";
import type { CapturedEnvironment } from "./bash-tools.exec-env.test-support.js";
import { runtimeManagedRun } from "./bash-tools.exec-runtime.test-support.js";
import {
  AGENT,
  ALICE,
  aliceSession,
  expectNoLeak,
  human,
  installSessionSecretsHarness,
  KEY,
  launch,
  people,
  probe,
  providerCalls,
  sandboxBackend as sandbox,
  SESSION_ID,
  store,
  target,
  turn,
  value,
  vault,
  writeSession,
} from "./bash-tools.exec.session-secrets.test-support.js";
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

describe("spawned sessions use what their parent session uses", () => {
  /** A sub-agent spawned in `parent` by Bob's turn: upstream attributes it to Bob. */
  async function spawnIn(parent: string, store_ = store, agentId = AGENT) {
    const sessionKey = `agent:${agentId}:subagent:${randomUUID()}`;
    await replaceSessionEntry(
      { agentId, sessionKey, storePath: store_ },
      {
        sessionId: SESSION_ID,
        updatedAt: Date.now(),
        createdActor: { type: "agent", id: agentId, delegatedBy: human(people.bob) },
        spawnedBy: parent,
        parentSessionKey: parent,
      },
    );
    return sessionKey;
  }

  beforeEach(() => {
    // Bob has entries too: a child that used its own creator would get his.
    vault.set(people.bob, [{ name: KEY, kind: "env", value: `bob-${value}` }]);
  });

  it("a sub-agent and its sub-agent spawned by Bob's turns in Alice's session use hers", async () => {
    const aliceKey = await aliceSession({ visibility: "shared" });
    const child = await spawnIn(aliceKey);
    const grandchild = await spawnIn(child);
    const results = { child: await probe(child), grandchild: await probe(grandchild) };

    for (const result of Object.values(results)) {
      expect(result.values).toEqual([value, value, value]);
      expect(result.status).toEqual({ creatorProfileId: people.alice, entryNames: [KEY] });
      expect(result.warnings).toEqual([]);
      expectNoLeak(result.surfaces);
    }
  });

  it("a sub-agent in another agent reads its parent from that agent's store", async () => {
    // The child runs as agent "coder"; its parent is Alice's session of agent "main".
    const aliceKey = await aliceSession();
    const coderStore = resolveSessionStorePathCore(undefined, { agentId: "coder" });
    const child = await spawnIn(aliceKey, coderStore, "coder");
    const coderTarget = { storeScope: coderStore, agentId: "coder", sessionKey: child };
    const { env, surfaces } = await launch(turn("bob", "coder"), {
      sessionKey: child,
      sessionSecrets: { target: coderTarget },
    });
    expect(env[KEY]).toBe(value);
    expectNoLeak(surfaces);
  });

  it.each<[string, string, string]>([
    ["the main session", "agent:main:main", "main-session"],
    ["a channel DM", "agent:main:whatsapp:direct:+15550001", "channel-session"],
  ])("children of %s get nothing, and status says why", async (_label, parent, reason) => {
    // Alice created the parent herself; only its key excludes it.
    await writeSession(parent, { createdActor: ALICE });
    const child = await spawnIn(parent);
    const grandchild = await spawnIn(child);
    const parentStatus = await readSessionSecretsStatus(target(parent), people.alice);
    const results = { child: await probe(child), grandchild: await probe(grandchild) };
    const sandboxed = await launch(turn("alice"), {
      sessionKey: child,
      sessionSecrets: { target: target(child) },
      sandbox,
    } as never);

    expect(parentStatus).toEqual({ excluded: reason });
    for (const result of Object.values(results)) {
      expect(result.values).toEqual([undefined, undefined, undefined]);
      expect(result.status).toEqual({ excluded: "inherited", from: parent });
      expectNoLeak(result.surfaces);
    }
    // No notice on exec, sandboxed or not, and nothing was read.
    expect([...results.child.warnings, ...results.grandchild.warnings]).toEqual([]);
    expect(sandboxed.warnings).toEqual([]);
    expect(providerCalls).toEqual([]);
  });

  it("an unreadable parent, a cycle or a parent without a person give nothing", async () => {
    const deleted = await spawnIn(`agent:main:dashboard:deleted-${randomUUID()}`);
    // The parent's agent has no such session in its store.
    const elsewhere = await spawnIn(`agent:coder:dashboard:${randomUUID()}`);
    const loopA = `agent:main:subagent:${randomUUID()}`;
    const loopB = await spawnIn(loopA);
    await writeSession(loopA, { createdActor: ALICE, spawnedBy: loopB });
    const agentParent = `agent:main:dashboard:${randomUUID()}`;
    await writeSession(agentParent, { createdActor: { type: "agent", id: "main" } });
    const orphan = await spawnIn(agentParent);

    for (const sessionKey of [deleted, elsewhere, loopA, loopB, orphan]) {
      const result = await probe(sessionKey);
      expect(result.values, sessionKey).toEqual([undefined, undefined, undefined]);
      expect(result.status, sessionKey).toBeUndefined();
      expect(result.warnings, sessionKey).toEqual([]);
    }
  });

  it("a chain of 16 spawn hops delivers; 17 do not", async () => {
    // Upstream caps spawn depth at 5; a longer chain is malformed, so it gets nothing.
    const chain = [await aliceSession()];
    for (let hop = 1; hop <= 17; hop += 1) {
      chain.push(await spawnIn(chain.at(-1)!));
    }
    const atCap = await probe(chain[16]!);
    const pastCap = await probe(chain[17]!);

    expect(atCap.values).toEqual([value, value, value]);
    expect(atCap.status).toMatchObject({ creatorProfileId: people.alice });
    expect(pastCap.values).toEqual([undefined, undefined, undefined]);
    expect(pastCap.status).toBeUndefined();
    expect([...atCap.warnings, ...pastCap.warnings]).toEqual([]);
    expectNoLeak(pastCap.surfaces);
  });
});
