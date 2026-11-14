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
async function prepare(gateway: People) {
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
    // The default store the Gateway uses for agent "main" in this state directory.
    storeScope: resolveSessionStorePathCore(undefined, { agentId: "main" }),
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
        for (const value of [secretValue, plainValue]) {
          expect(JSON.stringify(surface), `${name} leaked a value`).not.toContain(value);
        }
      }
      // Positive controls: these surfaces carry the command's output, so a value would show.
      for (const name of ["chat.history", "model requests"]) {
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
function execOutputs(session: SteeringSession): string[] {
  return (session.requests().at(-1)?.input ?? [])
    .filter((item) => item.type === "function_call_output")
    .map((item) => JSON.stringify(item.output));
}

/** One probe line's value; outputs are JSON-encoded, so lines end at `\n` or the string. */
const line = (output: string, label: string) =>
  new RegExp(`${label}:([^\\\\"]*)`).exec(output)?.[1];

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
      await expectNoLeak();
    }),
);

it(
  "a visibility change that lets more people send ends them from the next launch",
  { timeout: TEST_TIMEOUT_MS },
  () =>
    withPeopleGateway(PEOPLE_GATEWAY, async (gateway) => {
      const origins = await startOrigins(gateway.home);
      const { plainHash, session, target, profileId, creator, expectNoLeak } =
        await prepare(gateway);
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
      await setVisibility("draft");
      await enableSessionSecretsForTest({ requesterProfileId: profileId, target });
      // Narrowing or keeping who can send leaves them on.
      await setVisibility("draft");
      expect(creator()).toBe(profileId);

      const aliceTurn = await session.send("Alice runs the check in her draft.");
      expect(await session.wait(aliceTurn.runId)).toMatchObject({ status: "ok" });
      await setVisibility("shared");
      expect(creator()).toBeUndefined();

      const bob = await gateway.connectAs(BOB);
      const bobTurn = await session.send("Bob runs the check after Alice shared it.", bob);
      expect(await session.wait(bobTurn.runId)).toMatchObject({ status: "ok" });
      const [draft, shared] = execOutputs(session);
      expect(line(draft!, "plain")).toBe(`present:${plainHash}`);
      expect(line(shared!, "plain")).toBe("absent");
      expect(shared).toContain(SESSION_SECRETS_OFF_NOTICE);
      await expectNoLeak();
    }),
);
