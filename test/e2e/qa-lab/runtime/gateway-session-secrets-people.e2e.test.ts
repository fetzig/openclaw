// Spike (openclaw#197297): creator-bound session secrets through a real in-process Gateway.
// Alice and Bob sign in as distinct people; the model is scripted and issues real exec
// tool calls on the Gateway host, whose real egress proxy substitutes protected entries.
// Only the value provider is a test stand-in, because vault storage and its RPCs do not
// exist yet. There is no switch: Alice storing entries is the opt-in.
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs/promises";
import { createServer, type Server } from "node:https";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  readSessionSecretsStatus,
  setSessionSecretValueProviderForTest,
  type SessionSecretEntry,
} from "../../../../src/agents/session-secrets.js";
import { resolveSessionStorePathCore } from "../../../../src/config/sessions/paths.js";
import { loadSessionEntry } from "../../../../src/config/sessions/session-accessor.js";
import { listDirectoryTreeStrict } from "../../../../src/infra/directory-walk.js";
import {
  getSessionBindingService,
  registerSessionBindingAdapterV2,
  unregisterSessionBindingAdapter,
  type SessionBindingAdapterV2,
  type SessionBindingRecord,
} from "../../../../src/infra/outbound/session-binding-service.js";
import {
  getLogger,
  getResolvedLoggerFileTarget,
  resetLogger,
  setLoggerOverride,
} from "../../../../src/logging/logger.js";
import { generateLocalProxyLeaf } from "../../../../src/proxy-capture/ca.js";
import { INTERNAL_MESSAGE_CHANNEL } from "../../../../src/utils/message-channel-constants.js";
import {
  BOB,
  replyText,
  withPeopleGateway,
  writeToolCall,
  type SteeringSession,
} from "./gateway-session-steering.test-support.js";

const TEST_TIMEOUT_MS = 180_000;
const SECRET = "VAULT_TEST_TOKEN";
const PLAIN = "VAULT_PLAIN_TOKEN";
const ALLOWED_HOST = "localhost";
const DENIED_HOST = "127.0.0.1";

type People = Parameters<Parameters<typeof withPeopleGateway>[1]>[0];
type Received = { host: string; path: string; authorization?: string };

const servers: Server[] = [];

afterEach(async () => {
  setSessionSecretValueProviderForTest(undefined);
  resetLogger();
  await Promise.all(
    servers.splice(0).map((server) => {
      const closed = once(server, "close");
      server.close();
      server.closeAllConnections();
      return closed;
    }),
  );
});

/**
 * Two HTTPS origins with leaves signed by the Gateway's own egress-proxy CA, which its
 * upstream TLS trusts. Each records what it received.
 */
async function startOrigins(home: string) {
  const proxyRoot = path.join(home, ".openclaw", "secret-egress-proxy");
  const proxyDir = (await fs.readdir(proxyRoot)).find((name) => name.startsWith("gateway-"));
  const ca = {
    certPath: path.join(proxyRoot, proxyDir!, "root-ca.pem"),
    keyPath: path.join(proxyRoot, proxyDir!, "root-ca-key.pem"),
  };
  const received: Received[] = [];
  const origin = async (hostname: string) => {
    const certDir = path.join(home, `origin-${hostname}`);
    await fs.mkdir(certDir, { recursive: true, mode: 0o700 });
    const server = createServer(
      await generateLocalProxyLeaf({ certDir, ca, hostname }),
      (request, response) => {
        received.push({
          host: hostname,
          path: request.url ?? "",
          ...(request.headers.authorization
            ? { authorization: request.headers.authorization }
            : {}),
        });
        response.end("ok");
      },
    );
    servers.push(server);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Expected a local HTTPS origin");
    }
    return `https://${hostname}:${address.port}`;
  };
  return { allowed: await origin(ALLOWED_HOST), denied: await origin(DENIED_HOST), received };
}

/**
 * Prints the protected entry as the command sees it, proves the plaintext entry by hash,
 * and sends the protected entry to an allowed and a denied host through the proxy. The
 * harness sets NO_PROXY for its own clients, so the command clears it for curl.
 */
function probe(origins: { allowed: string; denied: string }) {
  const curl = (url: string, auth: boolean) =>
    `$(env -u NO_PROXY -u no_proxy curl -s -o /dev/null -w '%{http_code}' ${auth ? `-H "Authorization: Bearer $${SECRET}"` : ""} ${url})`;
  return [
    `printf 'secret-env:%s\\n' "$${SECRET}"`,
    `if [ -n "$${PLAIN}" ]; then printf 'plain:present:%s\\n' "$(printf %s "$${PLAIN}" | sha256sum | cut -d' ' -f1)"; else echo plain:absent; fi`,
    `printf 'allowed:%s\\n' "${curl(`${origins.allowed}/allowed`, true)}"`,
    `printf 'denied:%s\\n' "${curl(`${origins.denied}/denied`, true)}"`,
    `printf 'control:%s\\n' "${curl(`${origins.denied}/control`, false)}"`,
  ].join("; ");
}

/**
 * Starts a scenario: Alice stores random protected and plaintext entries, a fresh session
 * in the agent's store, and capture of every log record and console write.
 */
async function prepare(gateway: People, sessionStore?: string) {
  const secretValue = `vs-${randomUUID()}`;
  const plainValue = `vp-${randomUUID()}`;
  const plainHash = createHash("sha256").update(plainValue).digest("hex");
  const { profile } = await gateway.alice.request<{ profile: { id: string } }>("users.self", {});
  // Alice's vault; she deletes entries during the scenario.
  let vault: SessionSecretEntry[] = [
    { name: SECRET, value: secretValue, allowedHosts: [ALLOWED_HOST] },
    { name: PLAIN, kind: "env", value: plainValue },
  ];
  const read = (profileId: string) => (profileId === profile.id ? vault : []);
  setSessionSecretValueProviderForTest({
    listNames: (profileId) =>
      read(profileId).map(({ name, kind = "secret", allowedHosts }) => ({
        name,
        kind,
        allowedHosts,
      })),
    readEntries: read,
  });
  const session = gateway.session();
  const target = {
    // The store the Gateway uses for agent "main": the default one or `session.store`.
    storeScope: resolveSessionStorePathCore(sessionStore, { agentId: "main" }),
    agentId: "main",
    sessionKey: session.sessionKey,
  };
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
    plainHash,
    secretValue,
    session,
    target,
    profileId: profile.id,
    /** Read-only status as a session participant sees it. */
    status: (requesterProfileId: string) => readSessionSecretsStatus(target, requesterProfileId),
    deleteEntry: (name: string) => {
      vault = vault.filter((entry) => entry.name !== name);
    },
    /** Values may reach only the spawned process and the allowed host: never chat, events, model, logs or disk. */
    expectNoLeak: async (
      options: { historyBeforeReset?: unknown; historyShowsProbe?: boolean } = {},
    ) => {
      for (const restore of restoreWrites) {
        restore();
      }
      const surfaces: Record<string, unknown> = {
        "chat.history": [options.historyBeforeReset, await session.history()],
        "Gateway events": gateway.events,
        "model requests": gateway.model.requests,
        "log records": logs,
        "stdout/stderr": writes,
      };
      for (const [name, surface] of Object.entries(surfaces)) {
        for (const value of [secretValue, plainValue]) {
          expect(JSON.stringify(surface), `${name} leaked a value`).not.toContain(value);
        }
      }
      // Positive controls: these surfaces carry the command's output, so a value would show.
      // Scheduled runs record only their result in chat.history, not tool output.
      for (const name of [
        ...(options.historyShowsProbe === false ? [] : ["chat.history"]),
        "model requests",
      ]) {
        expect(JSON.stringify(surfaces[name]), `${name} lacks the probe output`).toContain(
          plainHash,
        );
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
        for (const value of [secretValue, plainValue]) {
          expect(bytes.includes(value), `${filePath} leaked a value`).toBe(false);
        }
        filesWithProbeOutput += bytes.includes(plainHash) ? 1 : 0;
      }
      expect(filesWithProbeOutput, "no state file holds the probe output").toBeGreaterThan(0);
      const logFile = String(await fs.readFile(getResolvedLoggerFileTarget().file).catch(() => ""));
      for (const value of [secretValue, plainValue]) {
        expect(logFile, "the Gateway log file leaked a value").not.toContain(value);
      }
    },
  };
}

/** Each exec call's output in the conversation the model last received, in order. */
function execOutputs(session: Pick<SteeringSession, "requests">): string[] {
  return (session.requests().at(-1)?.input ?? [])
    .filter((item) => item.type === "function_call_output")
    .map((item) => JSON.stringify(item.output));
}

/** One probe line's value; outputs are JSON-encoded, so lines end at `\n` or the string. */
const line = (output: string, label: string) =>
  new RegExp(`${label}:([^\\\\"]*)`).exec(output)?.[1];

/** The exec output of the most recent tool call any session sent the model. */
const lastExec = (gateway: People) =>
  execOutputs({ requests: () => gateway.model.requests }).at(-1)!;

const CUSTOM_STORE = "~/custom-sessions/{agentId}/sessions.json";

const PEOPLE_GATEWAY = {
  exec: { mode: "full" },
  secrets: { egressProxy: { enabled: true } },
} as const;

it(
  "every command in Alice's session uses her current entries, whoever sends and whatever changes",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    // A custom session.store: the launch reads the creator from the store the Gateway uses.
    withPeopleGateway({ ...PEOPLE_GATEWAY, sessionStore: CUSTOM_STORE }, async (gateway) => {
      const origins = await startOrigins(gateway.home);
      const { plainHash, secretValue, session, profileId, status, deleteEntry, expectNoLeak } =
        await prepare(gateway, CUSTOM_STORE);
      const command = probe(origins);
      const exec = async (_request: unknown, response: Parameters<typeof replyText>[0]) =>
        writeToolCall(response, "exec", { command });
      gateway.model.script(
        async (_request, response) => replyText(response, "Session created."),
        exec,
        async (_request, response) => replyText(response, "Bob's check ran."),
        exec,
        async (_request, response) => replyText(response, "Alice's draft check ran."),
        exec,
        async (_request, response) => replyText(response, "Bob's check after /new ran."),
        exec,
        async (_request, response) => replyText(response, "Bob's check after the deletion ran."),
      );
      const setVisibility = (visibility: string) =>
        gateway.alice.request("session.visibility.set", {
          sessionKey: session.sessionKey,
          visibility,
        });
      const run = async (message: string, client?: Awaited<ReturnType<People["connectAs"]>>) => {
        const sent = await session.send(message, client);
        expect(await session.wait(sent.runId)).toMatchObject({ status: "ok" });
        return lastExec(gateway);
      };
      // toEqual treats an undefined authorization as absent.
      const lastReceived = (count: number) => origins.received.slice(-count);
      const delivered = [
        { host: ALLOWED_HOST, path: "/allowed", authorization: `Bearer ${secretValue}` },
        // The denied host never sees the request that carried the sentinel; only the control.
        { host: DENIED_HOST, path: "/control", authorization: undefined },
      ];

      const created = await session.send("Alice opens the session.");
      expect(await session.wait(created.runId)).toMatchObject({ status: "ok" });
      await setVisibility("shared");
      const bob = await gateway.connectAs(BOB);
      const { profile: bobProfile } = await bob.request<{ profile: { id: string } }>(
        "users.self",
        {},
      );
      // No enable step: storing entries was the opt-in. Participants see names, never values.
      const expectedStatus = { creatorProfileId: profileId, entryNames: [PLAIN, SECRET] };
      expect(await status(profileId)).toEqual(expectedStatus);
      expect(await status(bobProfile.id)).toEqual(expectedStatus);

      const bobShared = await run("Bob runs the vault check in Alice's Shared session.", bob);
      expect(line(bobShared, "secret-env")).toMatch(/^oc-sent-v2\.[A-Za-z0-9_-]+\.end$/);
      expect(line(bobShared, "plain")).toBe(`present:${plainHash}`);
      expect(line(bobShared, "allowed")).toBe("200");
      expect(line(bobShared, "denied")).not.toBe("200");
      expect(line(bobShared, "control")).toBe("200");
      expect(lastReceived(2)).toEqual(delivered);

      // Visibility changes do nothing: Draft, then Shared again.
      await setVisibility("draft");
      const aliceDraft = await run("Alice runs the check in her Draft.");
      expect(line(aliceDraft, "secret-env")).toMatch(/^oc-sent-v2\./);
      expect(lastReceived(2)).toEqual(delivered);
      await setVisibility("shared");

      // `/new` answers without a model turn; the reset session keeps its creator.
      const historyBeforeReset = await session.history();
      const reset = await session.send("/new");
      expect(await session.wait(reset.runId)).toMatchObject({ status: "ok" });
      const bobAfterReset = await run("Bob checks again after /new.", bob);
      expect(line(bobAfterReset, "secret-env")).toMatch(/^oc-sent-v2\./);
      expect(line(bobAfterReset, "plain")).toBe(`present:${plainHash}`);
      expect(lastReceived(2)).toEqual(delivered);

      // Deleting the entry is the opt-out, read at Bob's next launch without a notice.
      deleteEntry(SECRET);
      expect(await status(bobProfile.id)).toEqual({
        creatorProfileId: profileId,
        entryNames: [PLAIN],
      });
      const bobAfterDelete = await run("Bob checks after Alice deleted her token.", bob);
      expect(line(bobAfterDelete, "secret-env")).toBe("");
      expect(line(bobAfterDelete, "plain")).toBe(`present:${plainHash}`);
      expect(bobAfterDelete).not.toContain("Session secrets");
      expect(lastReceived(3)).toEqual([
        { host: ALLOWED_HOST, path: "/allowed", authorization: "Bearer" },
        { host: DENIED_HOST, path: "/denied", authorization: "Bearer" },
        { host: DENIED_HOST, path: "/control", authorization: undefined },
      ]);
      expect(
        origins.received.filter((request) => request.authorization === `Bearer ${secretValue}`),
      ).toHaveLength(3);
      await expectNoLeak({ historyBeforeReset });
    }),
);

it(
  "the main session and a Slack-bound session get none of Alice's entries; webchat-bound and dashboard do",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    withPeopleGateway(PEOPLE_GATEWAY, async (gateway) => {
      const origins = await startOrigins(gateway.home);
      const { plainHash, secretValue, session, target, profileId, status, expectNoLeak } =
        await prepare(gateway);
      // Channel DMs route here under the default dmScope "main".
      const main = gateway.session("agent:main:main");
      const command = probe(origins);
      gateway.model.script(
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "The main-session check ran."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "The dashboard check ran."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "The webchat-bound check ran."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "The Slack-bound check ran."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "The unbound check ran."),
      );

      const inMain = await main.send("Alice runs the vault check in the agent's main session.");
      expect(await main.wait(inMain.runId)).toMatchObject({ status: "ok" });
      const mainOutput = lastExec(gateway);
      // Alice's message created the main session, so the creator rule alone would apply.
      const mainTarget = { ...target, sessionKey: main.sessionKey };
      expect(
        loadSessionEntry({
          agentId: "main",
          sessionKey: main.sessionKey,
          storePath: target.storeScope,
        })?.createdActor,
      ).toMatchObject({ type: "human", source: "profile", id: profileId });
      expect(await readSessionSecretsStatus(mainTarget, profileId)).toBeUndefined();
      expect(line(mainOutput, "secret-env")).toBe("");
      expect(line(mainOutput, "plain")).toBe("absent");
      expect(mainOutput).not.toContain("Session secrets");

      const inDashboard = await session.send(
        "Alice runs the vault check in her dashboard session.",
      );
      expect(await session.wait(inDashboard.runId)).toMatchObject({ status: "ok" });
      const dashboardOutput = lastExec(gateway);
      expect(await status(profileId)).toEqual({
        creatorProfileId: profileId,
        entryNames: [PLAIN, SECRET],
      });
      expect(line(dashboardOutput, "secret-env")).toMatch(/^oc-sent-v2\./);
      expect(line(dashboardOutput, "plain")).toBe(`present:${plainHash}`);
      expect(
        origins.received.map(({ host, path: requestPath, authorization }) => [
          host,
          requestPath,
          authorization,
        ]),
      ).toEqual([
        [ALLOWED_HOST, "/allowed", "Bearer"],
        [DENIED_HOST, "/denied", "Bearer"],
        [DENIED_HOST, "/control", undefined],
        [ALLOWED_HOST, "/allowed", `Bearer ${secretValue}`],
        [DENIED_HOST, "/control", undefined],
      ]);

      // A plugin session catalog binds a continued session to the Control UI's own
      // (internal) conversation, through the real binding store: that does not count.
      await getSessionBindingService().bind({
        targetSessionKey: session.sessionKey,
        targetKind: "session",
        conversation: {
          channel: INTERNAL_MESSAGE_CHANNEL,
          accountId: "default",
          conversationId: session.sessionKey,
        },
        placement: "current",
      });
      const inInternal = await session.send("Alice runs the check while bound to webchat.");
      expect(await session.wait(inInternal.runId)).toMatchObject({ status: "ok" });
      const internalOutput = lastExec(gateway);
      const internalStatus = await status(profileId);
      // An external channel's binding owner (as Slack's thread bindings register one in the
      // Gateway process) routes a Slack thread into the same session: that does.
      const slack = bindSlackThread(session.sessionKey);
      const inExternal = await session.send("Alice runs the check while a Slack thread is bound.");
      expect(await session.wait(inExternal.runId)).toMatchObject({ status: "ok" });
      const externalOutput = lastExec(gateway);
      const externalStatus = await status(profileId);
      slack.unbind();
      const inUnbound = await session.send("Alice runs the check after the Slack thread unbound.");
      expect(await session.wait(inUnbound.runId)).toMatchObject({ status: "ok" });
      const unboundOutput = lastExec(gateway);
      slack.uninstall();

      expect(internalStatus?.creatorProfileId).toBe(profileId);
      expect(externalStatus).toBeUndefined();
      for (const output of [internalOutput, unboundOutput]) {
        expect(line(output, "secret-env")).toMatch(/^oc-sent-v2\./);
        expect(line(output, "plain")).toBe(`present:${plainHash}`);
      }
      expect(line(externalOutput, "secret-env")).toBe("");
      expect(line(externalOutput, "plain")).toBe("absent");
      expect(externalOutput).not.toContain("Session secrets");
      expect(origins.received.slice(5).map(({ authorization }) => authorization)).toEqual([
        `Bearer ${secretValue}`,
        undefined,
        "Bearer",
        "Bearer",
        undefined,
        `Bearer ${secretValue}`,
        undefined,
      ]);
      await expectNoLeak();
    }),
);

/**
 * A Slack binding owner holding one thread bound to `sessionKey`, registered in the
 * Gateway's process-wide adapter registry as a channel's thread bindings would be.
 */
function bindSlackThread(sessionKey: string) {
  const bindings: SessionBindingRecord[] = [
    {
      bindingId: `slack-${randomUUID()}`,
      targetSessionKey: sessionKey,
      targetKind: "session",
      status: "active",
      boundAt: Date.now(),
      conversation: { channel: "slack", accountId: "default", conversationId: "C0123:1700.0001" },
    },
  ];
  const listBySession = (key: string) =>
    bindings.filter((binding) => binding.targetSessionKey === key);
  const adapter: SessionBindingAdapterV2 = {
    version: 2,
    channel: "slack",
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
  return {
    unbind: () => void bindings.splice(0),
    uninstall: () =>
      unregisterSessionBindingAdapter({ channel: "slack", accountId: "default", adapter }),
  };
}

type CronRun = { ok: boolean; enqueued: boolean; runId: string };
type CronJobRow = { id: string; name: string };

it(
  "cron: runs in a session Alice created, or a run session stamped with her, get her entries",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    withPeopleGateway({ ...PEOPLE_GATEWAY, cron: true }, async (gateway) => {
      const origins = await startOrigins(gateway.home);
      const { plainHash, secretValue, session, expectNoLeak } = await prepare(gateway);
      const command = probe(origins);
      type Turn = Parameters<typeof gateway.model.script>[number];
      const reply =
        (text: string): Turn =>
        async (_request, response) =>
          replyText(response, text);
      const exec: Turn = async (_request, response) => writeToolCall(response, "exec", { command });
      // Jobs are scheduled by the model from a person's own turn (the automations tool).
      const schedule =
        (name: string, job: object): Turn =>
        async (_request, response) =>
          writeToolCall(response, "automations", {
            action: "add",
            job: {
              name,
              schedule: { kind: "every", everyMs: 86_400_000 },
              payload: { kind: "agentTurn", message: `${name}: run the vault check.` },
              delivery: { mode: "none" },
              ...job,
            },
          });
      const bobSession = gateway.session();
      gateway.model.script(
        reply("Draft created."),
        schedule("Alice's session job", { sessionTarget: `session:${session.sessionKey}` }),
        schedule("Alice's isolated job", { sessionTarget: "isolated" }),
        schedule("Alice's current job", { sessionTarget: "current" }),
        reply("Alice scheduled three jobs."),
        exec,
        reply("Alice's session job ran."),
        exec,
        reply("Alice's isolated job ran."),
        exec,
        reply("Alice's current job ran."),
        reply("Bob's session exists."),
        schedule("Bob's job in Alice's draft", { sessionTarget: `session:${session.sessionKey}` }),
        schedule("Bob's isolated job", { sessionTarget: "isolated" }),
        reply("Bob scheduled two jobs."),
        exec,
        reply("Bob's job in Alice's draft ran."),
        exec,
        reply("Bob's isolated job ran."),
      );
      const created = await session.send("Alice opens a draft for scheduled checks.");
      expect(await session.wait(created.runId)).toMatchObject({ status: "ok" });
      await gateway.alice.request("session.visibility.set", {
        sessionKey: session.sessionKey,
        visibility: "draft",
      });
      const scheduled = await session.send("Alice schedules her vault checks.");
      expect(await session.wait(scheduled.runId)).toMatchObject({ status: "ok" });

      /** Runs a job now as `client` and returns the exec output its turn produced. */
      const runJob = async (client: typeof gateway.alice, name: string) => {
        const { jobs } = await client.request<{ jobs: CronJobRow[] }>("cron.list", {
          includeDisabled: true,
        });
        const job = jobs.find((candidate) => candidate.name === name);
        expect(job, name).toBeDefined();
        const run = await client.request<CronRun>("cron.run", { id: job!.id, mode: "force" });
        expect(run, name).toMatchObject({ ok: true, enqueued: true });
        await expect
          .poll(
            async () =>
              (
                await client.request<{ entries: Array<{ runId?: string; status?: string }> }>(
                  "cron.runs",
                  { id: job!.id, runId: run.runId, limit: 1 },
                )
              ).entries.find((entry) => entry.runId === run.runId)?.status,
            { timeout: 60_000, interval: 250 },
          )
          .toBe("ok");
        return lastExec(gateway);
      };
      const deliveredToAllowed = () =>
        origins.received.filter((request) => request.authorization === `Bearer ${secretValue}`)
          .length;

      // Alice's session job runs in her session; isolated and current runs use a fresh
      // `cron:<jobId>` session that upstream stamps with the job owner's profile.
      for (const [index, name] of [
        "Alice's session job",
        "Alice's isolated job",
        "Alice's current job",
      ].entries()) {
        const output = await runJob(gateway.alice, name);
        expect(line(output, "secret-env"), name).toMatch(/^oc-sent-v2\./);
        expect(line(output, "plain"), name).toBe(`present:${plainHash}`);
        expect(deliveredToAllowed(), name).toBe(index + 1);
      }

      // Bob cannot send in Alice's Draft, yet cron lets him schedule a job into it (cron
      // does not check session sharing on `session:<key>`). Its run is in Alice's session,
      // so it gets her entries: the creator rule ignores who caused the turn.
      const bob = await gateway.connectAs(BOB);
      const bobOpened = await bobSession.send("Bob opens his own session.", bob);
      expect(await bobSession.wait(bobOpened.runId)).toMatchObject({ status: "ok" });
      const bobTurn = await bobSession.send("Bob schedules checks.", bob);
      expect(await bobSession.wait(bobTurn.runId)).toMatchObject({ status: "ok" });
      const bobInAliceDraft = await runJob(bob, "Bob's job in Alice's draft");
      expect(line(bobInAliceDraft, "secret-env")).toMatch(/^oc-sent-v2\./);
      expect(line(bobInAliceDraft, "plain")).toBe(`present:${plainHash}`);
      expect(deliveredToAllowed()).toBe(4);
      // Bob's isolated job runs in a session stamped with Bob, who stored nothing.
      const bobIsolated = await runJob(bob, "Bob's isolated job");
      expect(line(bobIsolated, "secret-env")).toBe("");
      expect(line(bobIsolated, "plain")).toBe("absent");
      expect(deliveredToAllowed()).toBe(4);
      await expectNoLeak({ historyShowsProbe: false });
    }),
);
