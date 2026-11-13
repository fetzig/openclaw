// Spike (openclaw#197297): a requester-bound exec grant through a real in-process Gateway.
// Alice and Bob sign in as distinct people; the model is scripted and issues real exec
// tool calls on the Gateway host. Only the value provider and the grant setter are
// test stand-ins, because vault storage and its RPCs do not exist yet.
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, expect, it } from "vitest";
import {
  enableRequesterGrantForTest,
  readRequesterGrantHoldersForTest,
  resetRequesterGrantsForTest,
  setRequesterGrantValueProviderForTest,
} from "../../../../src/agents/requester-grants.js";
import { resolveSessionStorePathCore } from "../../../../src/config/sessions/paths.js";
import { listDirectoryTreeStrict } from "../../../../src/infra/directory-walk.js";
import {
  getLogger,
  getResolvedLoggerFileTarget,
  resetLogger,
  setLoggerOverride,
} from "../../../../src/logging/logger.js";
import { createDeferred } from "../../../helpers/promise.js";
import {
  BOB,
  replyText,
  roleTexts,
  userTexts,
  withPeopleGateway,
  writeToolCall,
  type ProviderRequest,
  type SteeringSession,
} from "./gateway-session-steering.test-support.js";

const TEST_TIMEOUT_MS = 180_000;
const KEY = "VAULT_TEST_TOKEN";
// Proves presence by hash and absence by a fixed marker; the value itself is never printed.
const PROBE = `if [ -n "$${KEY}" ]; then printf 'vault:present:%s\\n' "$(printf %s "$${KEY}" | sha256sum | cut -d' ' -f1)"; else echo vault:absent; fi`;

type People = Parameters<Parameters<typeof withPeopleGateway>[1]>[0];

afterEach(() => {
  resetRequesterGrantsForTest();
  setRequesterGrantValueProviderForTest(undefined);
  resetLogger();
});

/**
 * Starts a scenario: a random value for Alice's verified profile, a full-session grant on a
 * fresh session in the agent's default store, and capture of every log record and console write.
 */
async function prepare(gateway: People) {
  const value = `vt-${randomUUID()}`;
  const hash = createHash("sha256").update(value).digest("hex");
  const { profile } = await gateway.alice.request<{ profile: { id: string } }>("users.self", {});
  setRequesterGrantValueProviderForTest({
    readEntries: (holder): Record<string, string> =>
      holder === profile.id ? { [KEY]: value } : {},
  });
  const session = gateway.session();
  const target = {
    // The default store the Gateway uses for agent "main" in this state directory.
    storeScope: resolveSessionStorePathCore(undefined, { agentId: "main" }),
    agentId: "main",
    sessionKey: session.sessionKey,
  };
  enableRequesterGrantForTest({ holderProfileId: profile.id, target, mode: "full-session" });
  // A decoy for the same agent and key in another store. It must outlive Bob's input, which
  // shows the breaker revoked by the session's own store rather than in every store.
  const decoy = { ...target, storeScope: `${target.storeScope}.other-store` };
  enableRequesterGrantForTest({ holderProfileId: profile.id, target: decoy, mode: "full-session" });
  const logs: unknown[] = [];
  setLoggerOverride({ level: "trace", consoleLevel: "silent" });
  getLogger().attachTransport((record) => void logs.push(record));
  const writes: string[] = [];
  const restoreWrites = [process.stdout, process.stderr].map((stream) => {
    const write = stream.write.bind(stream);
    stream.write = ((chunk: unknown, ...rest: unknown[]) => {
      writes.push(String(chunk));
      return write(chunk as string, ...(rest as []));
    }) as typeof stream.write;
    return () => {
      stream.write = write;
    };
  });
  return {
    hash,
    session,
    holders: () => readRequesterGrantHoldersForTest(target),
    decoyHolders: () => readRequesterGrantHoldersForTest(decoy),
    profileId: profile.id,
    /** The value may reach only the spawned process: never chat, events, model, logs or disk. */
    expectNoLeak: async () => {
      for (const restore of restoreWrites) {
        restore();
      }
      const surfaces: Record<string, unknown> = {
        "chat.history": await session.history(),
        "Gateway events": gateway.events,
        "model requests": gateway.model.requests,
        "log records": logs,
        "stdout/stderr": writes,
      };
      for (const [name, surface] of Object.entries(surfaces)) {
        expect(JSON.stringify(surface), `${name} leaked the grant value`).not.toContain(value);
      }
      // Positive controls: these surfaces carry the command's output, so the value would show.
      for (const name of ["chat.history", "model requests"]) {
        expect(JSON.stringify(surfaces[name]), `${name} lacks the probe output`).toContain(hash);
      }
      expect(logs.length).toBeGreaterThan(0);
      // Transcripts, session databases and any log files under the isolated HOME.
      let filesWithProbeOutput = 0;
      for (const entry of await listDirectoryTreeStrict(gateway.home)) {
        if (!entry.dirent.isFile()) {
          continue;
        }
        const filePath = path.join(gateway.home, entry.relativePath);
        const bytes = await fs.readFile(filePath).catch(() => Buffer.alloc(0));
        expect(bytes.includes(value), `${filePath} leaked the grant value`).toBe(false);
        filesWithProbeOutput += bytes.includes(hash) ? 1 : 0;
      }
      expect(filesWithProbeOutput, "no state file holds the probe output").toBeGreaterThan(0);
      // The Gateway's own log file, wherever logging resolved it.
      const logFile = await fs.readFile(getResolvedLoggerFileTarget().file).catch(() => "");
      expect(String(logFile), "the Gateway log file leaked the grant value").not.toContain(value);
    },
  };
}

/** Probe output of each exec call in the conversation the model last received, in order. */
function probeOutputs(session: SteeringSession): string[] {
  return (session.requests().at(-1)?.input ?? [])
    .filter((item) => item.type === "function_call_output")
    .flatMap(
      (item) => JSON.stringify(item.output).match(/vault:(?:present:[0-9a-f]{64}|absent)/g) ?? [],
    );
}

const hasProbeOutput = (request: ProviderRequest, count: number) =>
  request.input.filter((item) => item.type === "function_call_output").length >= count;

it(
  "delivers Alice's value to her own turn and not to her turn after Bob's message",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    withPeopleGateway({ exec: { mode: "full" } }, async (gateway) => {
      const { hash, session, holders, decoyHolders, profileId, expectNoLeak } =
        await prepare(gateway);
      gateway.model.script(
        async (_request, response) => writeToolCall(response, "exec", { command: PROBE }),
        async (_request, response) => replyText(response, "Alice's first check ran."),
        async (_request, response) => replyText(response, "Bob's turn answered."),
        async (_request, response) => writeToolCall(response, "exec", { command: PROBE }),
        async (_request, response) => replyText(response, "Alice's second check ran."),
      );

      const first = await session.send("Alice runs the vault check.");
      expect(await session.wait(first.runId)).toMatchObject({ status: "ok" });
      expect(holders()).toHaveLength(1);

      const bob = await gateway.connectAs(BOB);
      const bobTurn = await session.send("Bob asks something in Alice's session.", bob);
      expect(await session.wait(bobTurn.runId)).toMatchObject({ status: "ok" });
      expect(holders()).toEqual([]);
      expect(decoyHolders()).toEqual([profileId]);

      const second = await session.send("Alice runs the vault check again.");
      expect(await session.wait(second.runId)).toMatchObject({ status: "ok" });

      expect(probeOutputs(session)).toEqual([`vault:present:${hash}`, "vault:absent"]);
      expect(roleTexts(await session.history(), "assistant")).toContain(
        "Alice's second check ran.",
      );
      await expectNoLeak();
    }),
);

it(
  "ends Alice's grant inside her running turn once Bob's steer is admitted",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    withPeopleGateway(
      { allowCollaborativeSteering: true, exec: { mode: "full" } },
      async (gateway) => {
        const { hash, session, holders, decoyHolders, profileId, expectNoLeak } =
          await prepare(gateway);
        const bobText = "Bob steers Alice's running job.";
        const afterFirstProbe = createDeferred();
        const steerAdmitted = createDeferred();
        let bobSeen = false;
        gateway.model.script(
          async (_request, response) => writeToolCall(response, "exec", { command: PROBE }),
          // Holds the turn between two exec calls until Bob's steer has been admitted.
          async (request, response) => {
            expect(hasProbeOutput(request, 1)).toBe(true);
            afterFirstProbe.resolve();
            await steerAdmitted.promise;
            writeToolCall(response, "exec", { command: PROBE });
          },
          async (request, response) => {
            bobSeen = userTexts(request).some((text) => text.includes(bobText));
            if (!bobSeen) {
              writeToolCall(response, "session_status", {});
              return "repeat";
            }
            replyText(response, "Alice's job finished with Bob's note.");
            return undefined;
          },
        );

        const run = await session.send("Alice starts the long vault job.");
        await afterFirstProbe.promise;
        expect(holders()).toHaveLength(1);
        const bob = await gateway.connectAs(BOB);
        const steered = await session.send(bobText, bob);
        // The breaker trips when the running turn admits the steer, not when it consumes it.
        const deadline = Date.now() + 20_000;
        while (holders().length > 0 && Date.now() < deadline) {
          await delay(25);
        }
        const revokedBeforeNextLaunch = holders().length === 0;
        steerAdmitted.resolve();

        expect(await session.wait(run.runId)).toMatchObject({ status: "ok" });
        expect(revokedBeforeNextLaunch).toBe(true);
        expect(decoyHolders()).toEqual([profileId]);
        expect(bobSeen).toBe(true);
        expect(session.executedRuns()).toEqual([run.runId]);
        expect(session.executedRuns()).not.toContain(steered.runId);
        expect(probeOutputs(session)).toEqual([`vault:present:${hash}`, "vault:absent"]);
        await expectNoLeak();
      },
    ),
);
