// Spike (openclaw#197297): creator-bound session secrets through a real in-process Gateway.
// Alice and Bob sign in as distinct people; the model is scripted and issues real exec
// tool calls on the Gateway host, whose real egress proxy substitutes protected entries.
// Only the value provider and the enable setter are test stand-ins, because vault storage
// and its RPCs do not exist yet.
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs/promises";
import { createServer, type Server } from "node:https";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  disableSessionSecrets,
  enableSessionSecretsForTest,
  readSessionSecretsCreatorForTest,
  resetSessionSecretsForTest,
  SESSION_SECRETS_NO_PERSON_NOTICE,
  SESSION_SECRETS_OFF_NOTICE,
  setSessionSecretValueProviderForTest,
} from "../../../../src/agents/session-secrets.js";
import { resolveSessionStorePathCore } from "../../../../src/config/sessions/paths.js";
import { listDirectoryTreeStrict } from "../../../../src/infra/directory-walk.js";
import {
  getLogger,
  getResolvedLoggerFileTarget,
  resetLogger,
  setLoggerOverride,
} from "../../../../src/logging/logger.js";
import { generateLocalProxyLeaf } from "../../../../src/proxy-capture/ca.js";
import {
  BOB,
  replyText,
  roleTexts,
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
  resetSessionSecretsForTest();
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
 * Starts a scenario: random values for Alice's protected and plaintext entries, a fresh
 * session in the agent's default store, and capture of every log record and console write.
 */
async function prepare(gateway: People, sessionStore?: string) {
  const secretValue = `vs-${randomUUID()}`;
  const plainValue = `vp-${randomUUID()}`;
  const plainHash = createHash("sha256").update(plainValue).digest("hex");
  const { profile } = await gateway.alice.request<{ profile: { id: string } }>("users.self", {});
  setSessionSecretValueProviderForTest({
    readEntries: (profileId) =>
      profileId === profile.id
        ? [
            { name: SECRET, value: secretValue, allowedHosts: [ALLOWED_HOST] },
            { name: PLAIN, kind: "env", value: plainValue },
          ]
        : [],
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
    creator: () => readSessionSecretsCreatorForTest(target),
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

const CUSTOM_STORE = "~/custom-sessions/{agentId}/sessions.json";

const PEOPLE_GATEWAY = {
  exec: { mode: "full" },
  secrets: { egressProxy: { enabled: true } },
} as const;

it(
  "Bob's turn in Alice's session uses her entries until she turns them off",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    withPeopleGateway(PEOPLE_GATEWAY, async (gateway) => {
      const origins = await startOrigins(gateway.home);
      const { plainHash, secretValue, session, target, profileId, creator, expectNoLeak } =
        await prepare(gateway);
      const command = probe(origins);
      gateway.model.script(
        async (_request, response) => replyText(response, "Session created."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "Bob's check ran."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "Bob's second check ran."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "The check after /new ran."),
      );

      const created = await session.send("Alice opens the session.");
      expect(await session.wait(created.runId)).toMatchObject({ status: "ok" });
      const bob = await gateway.connectAs(BOB);
      // Only the creator can turn them on; Bob cannot, even in a session he can send in.
      const { profile: bobProfile } = await bob.request<{ profile: { id: string } }>(
        "users.self",
        {},
      );
      await expect(
        enableSessionSecretsForTest({ requesterProfileId: bobProfile.id, target }),
      ).rejects.toThrow("Only the session's creator");
      await enableSessionSecretsForTest({ requesterProfileId: profileId, target });
      expect(creator()).toBe(profileId);

      const bobTurn = await session.send("Bob runs the vault check in Alice's session.", bob);
      expect(await session.wait(bobTurn.runId)).toMatchObject({ status: "ok" });
      const [during] = execOutputs(session);
      const sentinel = line(during!, "secret-env");
      expect(sentinel).toMatch(/^oc-sent-v2\.[A-Za-z0-9_-]+\.end$/);
      expect(line(during!, "plain")).toBe(`present:${plainHash}`);
      expect(line(during!, "allowed")).toBe("200");
      expect(line(during!, "denied")).not.toBe("200");
      expect(line(during!, "control")).toBe("200");
      // The allowed host received Alice's real value; the denied host received nothing
      // from the request that carried the sentinel, only the control request.
      expect(origins.received).toEqual([
        { host: ALLOWED_HOST, path: "/allowed", authorization: `Bearer ${secretValue}` },
        { host: DENIED_HOST, path: "/control" },
      ]);

      disableSessionSecrets(target, profileId);
      const afterOff = await session.send("Bob checks again after Alice turned them off.", bob);
      expect(await session.wait(afterOff.runId)).toMatchObject({ status: "ok" });
      const [, after] = execOutputs(session);
      expect(line(after!, "secret-env")).toBe("");
      expect(line(after!, "plain")).toBe("absent");
      expect(after).toContain(SESSION_SECRETS_OFF_NOTICE);
      // Without session secrets the command sends an empty bearer to both hosts.
      expect(origins.received.slice(2)).toEqual([
        { host: ALLOWED_HOST, path: "/allowed", authorization: "Bearer" },
        { host: DENIED_HOST, path: "/denied", authorization: "Bearer" },
        { host: DENIED_HOST, path: "/control" },
      ]);
      expect(roleTexts(await session.history(), "assistant")).toContain("Bob's second check ran.");

      // A reset starts a new session incarnation: session secrets end with the old one.
      const historyBeforeReset = await session.history();
      await enableSessionSecretsForTest({ requesterProfileId: profileId, target });
      // `/new` answers without a model turn and keeps the session's key and sessionId.
      const reset = await session.send("/new");
      expect(await session.wait(reset.runId)).toMatchObject({ status: "ok" });
      const again = await session.send("Alice checks again in the new session.");
      expect(await session.wait(again.runId)).toMatchObject({ status: "ok" });
      // The new incarnation's model requests no longer carry earlier messages.
      const [afterReset] = execOutputs({ requests: () => gateway.model.requests });
      expect(afterReset).toBeDefined();
      expect(line(afterReset!, "secret-env")).toBe("");
      expect(line(afterReset!, "plain")).toBe("absent");
      expect(afterReset).toContain(SESSION_SECRETS_OFF_NOTICE);
      expect(creator()).toBeUndefined();
      expect(origins.received.slice(5).map((request) => request.authorization)).toEqual([
        "Bearer",
        "Bearer",
        undefined,
      ]);
      await expectNoLeak({ historyBeforeReset });
    }),
);

it(
  "a visibility change that lets more people send ends them from the next launch",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    // A custom session.store: the hook and the launch must name the same physical session.
    withPeopleGateway({ ...PEOPLE_GATEWAY, sessionStore: CUSTOM_STORE }, async (gateway) => {
      const origins = await startOrigins(gateway.home);
      const { plainHash, session, target, profileId, creator, expectNoLeak } = await prepare(
        gateway,
        CUSTOM_STORE,
      );
      const command = probe(origins);
      gateway.model.script(
        async (_request, response) => replyText(response, "Draft created."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "Alice's draft check ran."),
        async (_request, response) => writeToolCall(response, "exec", { command }),
        async (_request, response) => replyText(response, "Bob's check ran."),
      );
      const setVisibility = (visibility: string) =>
        gateway.alice.request("session.visibility.set", {
          sessionKey: session.sessionKey,
          visibility,
        });

      const created = await session.send("Alice opens a draft.");
      expect(await session.wait(created.runId)).toMatchObject({ status: "ok" });
      await setVisibility("read-only");
      await enableSessionSecretsForTest({ requesterProfileId: profileId, target });
      // Narrowing who can send (Read-only to Draft) or keeping it leaves them on.
      await setVisibility("draft");
      await setVisibility("draft");
      expect(creator()).toBe(profileId);

      const aliceTurn = await session.send("Alice runs the check in her draft.");
      expect(await session.wait(aliceTurn.runId)).toMatchObject({ status: "ok" });
      await setVisibility("shared");
      // Ending is one check at launch: status reads on until the next command starts.
      expect(creator()).toBe(profileId);

      const bob = await gateway.connectAs(BOB);
      const bobTurn = await session.send("Bob runs the check after Alice shared it.", bob);
      expect(await session.wait(bobTurn.runId)).toMatchObject({ status: "ok" });
      expect(creator()).toBeUndefined();
      const [draft, shared] = execOutputs(session);
      expect(line(draft!, "plain")).toBe(`present:${plainHash}`);
      expect(line(draft!, "secret-env")).toMatch(/^oc-sent-v2\./);
      expect(line(shared!, "secret-env")).toBe("");
      expect(line(shared!, "plain")).toBe("absent");
      expect(shared).toContain(SESSION_SECRETS_OFF_NOTICE);
      await expectNoLeak();
    }),
);

type CronRun = { ok: boolean; enqueued: boolean; runId: string };
type CronJobRow = { id: string; name: string };

it(
  "cron: Alice's job in her session gets them; isolated, current and Bob's jobs get nothing",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    withPeopleGateway({ ...PEOPLE_GATEWAY, cron: true }, async (gateway) => {
      const origins = await startOrigins(gateway.home);
      const { plainHash, secretValue, session, target, profileId, creator, expectNoLeak } =
        await prepare(gateway);
      const command = probe(origins);
      type Turn = Parameters<typeof gateway.model.script>[number];
      const reply =
        (text: string): Turn =>
        async (_request, response) =>
          replyText(response, text);
      const exec: Turn = async (_request, response) => writeToolCall(response, "exec", { command });
      // Jobs are scheduled from a person's own turn, which records that person as the
      // job's operator source; its runs act for them.
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
        schedule("Bob's job", { sessionTarget: `session:${session.sessionKey}` }),
        reply("Bob scheduled a job."),
        exec,
        reply("Bob's job ran."),
      );
      const created = await session.send("Alice opens a draft for scheduled checks.");
      expect(await session.wait(created.runId)).toMatchObject({ status: "ok" });
      await gateway.alice.request("session.visibility.set", {
        sessionKey: session.sessionKey,
        visibility: "draft",
      });
      await enableSessionSecretsForTest({ requesterProfileId: profileId, target });
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
        return execOutputs({ requests: () => gateway.model.requests }).at(-1)!;
      };

      const inSession = await runJob(gateway.alice, "Alice's session job");
      expect(line(inSession, "secret-env")).toMatch(/^oc-sent-v2\./);
      expect(line(inSession, "plain")).toBe(`present:${plainHash}`);
      expect(origins.received[0]).toEqual({
        host: ALLOWED_HOST,
        path: "/allowed",
        authorization: `Bearer ${secretValue}`,
      });
      // A fresh session per run: secrets start off there and are never inherited. The run
      // still acts for Alice, so this is not the no-person refusal.
      for (const name of ["Alice's isolated job", "Alice's current job"]) {
        const output = await runJob(gateway.alice, name);
        expect(line(output, "secret-env"), name).toBe("");
        expect(line(output, "plain"), name).toBe("absent");
        expect(output, name).not.toContain(SESSION_SECRETS_NO_PERSON_NOTICE);
      }

      // Bob cannot send in Alice's Draft, yet cron lets him schedule a job into it (as of
      // this spike, cron does not check session sharing). The job's run acts for him.
      const bob = await gateway.connectAs(BOB);
      const bobTurn = await bobSession.send("Bob schedules a check in Alice's draft.", bob);
      expect(await bobSession.wait(bobTurn.runId)).toMatchObject({ status: "ok" });
      const bobRun = await runJob(bob, "Bob's job");
      expect(line(bobRun, "secret-env")).toBe("");
      expect(line(bobRun, "plain")).toBe("absent");
      expect(bobRun).toContain(SESSION_SECRETS_NO_PERSON_NOTICE);
      expect(
        origins.received.filter((request) => request.authorization === `Bearer ${secretValue}`),
      ).toHaveLength(1);
      expect(creator()).toBe(profileId);
      await expectNoLeak({ historyShowsProbe: false });
    }),
);
