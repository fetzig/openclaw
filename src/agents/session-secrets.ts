import { sessionIsolationProfileId } from "../config/sessions/session-entry-provenance.js";
/**
 * Spike (openclaw#197297): creator-bound session secrets.
 *
 * The verified profile that created a session can turn on its personal entries for that
 * session. While on, every Gateway-host exec launch in the session gets them, whoever
 * prompted the turn. `secret` entries reach commands only as sentinels that the egress
 * proxy resolves for their allowed hosts; `env` entries are plaintext. Values are read
 * from a provider at launch only and never stored here. State is process memory: a
 * Gateway restart turns everything off.
 */
import type { SessionEntry } from "../config/sessions/types.js";
import {
  isDangerousHostEnvOverrideVarName,
  isDangerousHostEnvVarName,
  isGatewayCredentialEnvVarName,
} from "../infra/host-env-security.js";
import { registerSecretValueForRedaction } from "../logging/secret-redaction-registry.js";
import { normalizeAgentId } from "../routing/session-key.js";
import type { SecretEgressSentinelBinding } from "../secrets/egress-proxy/proxy-server.js";
import { isSecretEgressProxyActive } from "../secrets/egress-proxy/registry.js";
import { sealSecretSentinel } from "../secrets/sentinel.js";
import { normalizeSecretAllowedHosts } from "../secrets/store/secret-store-validation.js";
import { getCurrentSessionControllerOwner } from "../sessions/session-controller.context.js";
import {
  getSessionControllerEntryForOperation,
  isCurrentSessionControllerOperation,
} from "../sessions/session-controller.identity.js";
import { resolveGlobalSingleton } from "../shared/global-singleton.js";

/**
 * One physical session: the session store it lives in, its agent and its key. The same
 * agent and key in two session stores are two sessions and never share session secrets.
 */
export type SessionSecretsTarget = Readonly<{
  storeScope: string;
  agentId?: string;
  sessionKey: string;
}>;

/** A vault entry as the provider returns it. `kind` defaults to the protected `secret`. */
export type SessionSecretEntry = Readonly<{
  name: string;
  value: string;
  kind?: "secret" | "env";
  allowedHosts?: readonly string[];
}>;

/** Where values come from: a vault plugin later; synthetic in the spike. */
export type SessionSecretValueProvider = {
  readEntries(
    profileId: string,
  ): Promise<readonly SessionSecretEntry[]> | readonly SessionSecretEntry[];
};

/** Captured when the exec tool runs and carried to the launch, also after an approval wait. */
export type SessionSecretsLaunch = Readonly<{
  /** Session store of the turn that ran the tool; absent outside a session turn. */
  storeScope?: string;
  /** Names owned by OpenClaw or set for this call (per-call or plugin env); never values. */
  reservedKeys?: readonly string[];
}>;

type SessionSecrets = {
  readonly creatorProfileId: string;
  /** The session incarnation they were turned on for; a reset session gets none. */
  readonly sessionId: string;
  /** targetKey() of the session. */
  readonly key: string;
  readonly entryNames?: readonly string[];
};

export const SESSION_SECRETS_OFF_NOTICE = "Session secrets are off; this command ran without them.";
export const SESSION_SECRETS_ENDED_ERROR =
  "Session secrets ended before the command started; it was not run. Ask the session creator to turn them on again.";

const MAX_VALUE_BYTES = 16 * 1024;
const MAX_ENTRIES = 64;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
/** OpenClaw-owned names that session secrets can never set, even when no reserved key covers them. */
const OPENCLAW_OWNED_NAMES = new Set(["GH_TOKEN", "GITHUB_TOKEN", "PATH", "HOME"]);
/**
 * Who can send, by visibility: Draft admits only the creator and admins; Read-only and
 * Suggest add owner and members; Shared adds everyone who can see the session.
 */
const SENDER_REACH = { draft: 0, "read-only": 1, suggest: 1, shared: 2 } as const;
type SessionVisibility = keyof typeof SENDER_REACH;

const state = resolveGlobalSingleton(Symbol.for("openclaw.sessionSecrets"), () => ({
  // storeScope \0 agentId \0 sessionKey -> the session's secrets while on
  sessions: new Map<string, SessionSecrets>(),
  /** Sessions whose secrets ended in this Gateway process, so a later launch can say so. */
  ended: new Set<string>(),
  provider: undefined as SessionSecretValueProvider | undefined,
}));

const agentOf = (target: Omit<SessionSecretsTarget, "storeScope">) =>
  normalizeAgentId(target.agentId ?? target.sessionKey.trim().split(":")[1]);
const targetKey = (target: SessionSecretsTarget) =>
  `${target.storeScope.trim()}\0${agentOf(target)}\0${target.sessionKey.trim()}`;

function end(key: string): void {
  if (state.sessions.delete(key)) {
    state.ended.add(key);
  }
}

/**
 * The only profile that may turn session secrets on: the session's write-once creator,
 * when it is a verified Gateway profile. Channel senders, agents, automations, delegated
 * creations and child sessions have none. The assignable owner never counts.
 */
export function resolveSessionSecretsCreator(
  entry: Pick<SessionEntry, "createdActor" | "spawnedBy" | "parentSessionKey"> | undefined,
): string | undefined {
  const actor = entry?.createdActor;
  if (!actor || actor.delegatedBy || entry.spawnedBy || entry.parentSessionKey) {
    return undefined;
  }
  return sessionIsolationProfileId(actor)?.trim() || undefined;
}

/**
 * Test-only stand-in for the creator-only RPC: the requester comes from the caller's
 * verified profile, and the session entry is read here, never taken from the caller.
 */
export async function enableSessionSecretsForTest(params: {
  requesterProfileId: string;
  target: SessionSecretsTarget;
  entryNames?: readonly string[];
}): Promise<void> {
  const { loadSessionEntry } = await import("../config/sessions/session-accessor.js");
  const entry = loadSessionEntry({
    agentId: agentOf(params.target),
    sessionKey: params.target.sessionKey,
    storePath: params.target.storeScope,
  });
  const creator = resolveSessionSecretsCreator(entry);
  if (!entry?.sessionId || !creator || creator !== params.requesterProfileId) {
    throw new Error("Only the session's creator can turn on session secrets.");
  }
  const key = targetKey(params.target);
  state.ended.delete(key);
  state.sessions.set(key, {
    creatorProfileId: creator,
    sessionId: entry.sessionId,
    key,
    ...(params.entryNames ? { entryNames: Object.freeze([...params.entryNames]) } : {}),
  });
}

/** The creator turns session secrets off; nobody else can. */
export function disableSessionSecrets(
  target: SessionSecretsTarget,
  requesterProfileId: string,
): void {
  const key = targetKey(target);
  if (state.sessions.get(key)?.creatorProfileId === requesterProfileId) {
    end(key);
  }
}

/** A visibility change that lets more people send ends session secrets from the next launch. */
export function endSessionSecretsIfSendersWiden(
  target: SessionSecretsTarget,
  previous: SessionVisibility,
  next: SessionVisibility,
): void {
  if (SENDER_REACH[next] > SENDER_REACH[previous]) {
    end(targetKey(target));
  }
}

export function setSessionSecretValueProviderForTest(
  provider: SessionSecretValueProvider | undefined,
): void {
  state.provider = provider;
}

/** Whose secrets the session uses, never values. */
export function readSessionSecretsCreatorForTest(target: SessionSecretsTarget): string | undefined {
  return state.sessions.get(targetKey(target))?.creatorProfileId;
}

/** Gateway restart: the registry is memory-only. */
export function resetSessionSecretsForTest(): void {
  state.sessions.clear();
  state.ended.clear();
}

function rejectionReason(name: string, value: string): string | undefined {
  if (!ENV_NAME.test(name)) {
    return "invalid name";
  }
  const upper = name.toUpperCase();
  if (
    OPENCLAW_OWNED_NAMES.has(upper) ||
    upper.startsWith("OPENCLAW_") ||
    isDangerousHostEnvVarName(name) ||
    isDangerousHostEnvOverrideVarName(name) ||
    isGatewayCredentialEnvVarName(name)
  ) {
    return "reserved name";
  }
  if (value.includes("\0")) {
    return "NUL byte";
  }
  if (Buffer.byteLength(value) > MAX_VALUE_BYTES) {
    return "too large";
  }
  return undefined;
}

function allowedHostsOf(entry: SessionSecretEntry): string[] | undefined {
  try {
    const hosts = normalizeSecretAllowedHosts(entry.allowedHosts ?? []);
    return hosts.length > 0 ? hosts : undefined;
  } catch {
    return undefined;
  }
}

/** Captures the physical session the current turn runs in, from its session controller entry. */
export function captureSessionSecretsLaunch(reservedKeys: readonly string[]): SessionSecretsLaunch {
  const owner = getCurrentSessionControllerOwner();
  return {
    reservedKeys,
    storeScope:
      owner && isCurrentSessionControllerOperation(owner)
        ? getSessionControllerEntryForOperation(owner).target?.storeScope
        : undefined,
  };
}

/**
 * Launch-time lookup, called inside runExecProcess immediately before spawn. Returns the
 * env to merge (plaintext `env` entries and `secret` sentinels), the egress-proxy bindings
 * for the sentinels, and a synchronous re-check for the final spawn boundary.
 */
export async function resolveSessionSecretsLaunch(
  caller: Readonly<{ agentId?: string; sessionKey?: string }> | undefined,
  launch: Readonly<{
    sessionId?: string;
    /** Sandbox and durable launches never receive values. */
    sandbox?: unknown;
    durable?: unknown;
    sessionSecrets?: SessionSecretsLaunch;
    /** Team-store bindings for this launch; a session secret of the same name replaces one. */
    secretEgressBindings?: readonly SecretEgressSentinelBinding[];
    warnings: string[];
  }>,
): Promise<
  | {
      env: Record<string, string>;
      /** Every binding the launch registers with the egress proxy; absent: register none. */
      bindings?: readonly SecretEgressSentinelBinding[];
      assertCurrent: () => void;
    }
  | undefined
> {
  const storeScope = launch.sessionSecrets?.storeScope;
  if (!caller?.sessionKey || !storeScope) {
    return undefined;
  }
  const key = targetKey({ storeScope, agentId: caller.agentId, sessionKey: caller.sessionKey });
  const secrets = state.sessions.get(key);
  // A reset or replaced session is a new incarnation with its own creator.
  if (!secrets || secrets.sessionId !== launch.sessionId) {
    if (state.ended.has(key)) {
      launch.warnings.push(SESSION_SECRETS_OFF_NOTICE);
    }
    return undefined;
  }
  const unsupported = launch.sandbox ? "sandbox" : launch.durable ? "durable" : undefined;
  if (unsupported) {
    launch.warnings.push(
      `Session secrets were not provided to this command: ${unsupported} exec is not supported.`,
    );
    return undefined;
  }
  const entries = (await state.provider?.readEntries(secrets.creatorProfileId)) ?? [];
  const proxyActive = isSecretEgressProxyActive();
  const reserved = new Set(launch.sessionSecrets?.reservedKeys?.map((name) => name.toUpperCase()));
  const env: Record<string, string> = {};
  const bindings: SecretEgressSentinelBinding[] = [];
  const rejected: string[] = [];
  const withheld: string[] = [];
  let count = 0;
  for (const entry of entries) {
    const { name, value } = entry;
    if (secrets.entryNames && !secrets.entryNames.includes(name)) {
      continue;
    }
    const kind = entry.kind ?? "secret";
    const allowedHosts = kind === "secret" ? allowedHostsOf(entry) : undefined;
    const reason =
      rejectionReason(name, value) ??
      (kind === "secret" && !allowedHosts ? "no valid allowed hosts" : undefined) ??
      (++count > MAX_ENTRIES ? "too many" : undefined);
    if (reason) {
      rejected.push(ENV_NAME.test(name) ? `${name} (${reason})` : "one entry with an invalid name");
      continue;
    }
    // OpenClaw-set, per-call and plugin values win over session secrets.
    if (reserved.has(name.toUpperCase())) {
      continue;
    }
    if (kind === "env") {
      registerSecretValueForRedaction(value);
      env[name] = value;
    } else if (!proxyActive) {
      withheld.push(name);
    } else {
      // sealSecretSentinel registers the value for redaction; commands see only the sentinel.
      const sentinel = sealSecretSentinel(value, { label: `exec-session:${name}` });
      env[name] = sentinel;
      bindings.push({ name, sentinel, allowedHosts: allowedHosts ?? [] });
    }
  }
  if (rejected.length > 0) {
    launch.warnings.push(
      `Warning: session secret entries were not provided: ${rejected.toSorted().join(", ")}.`,
    );
  }
  if (withheld.length > 0) {
    launch.warnings.push(
      `Warning: protected session secrets were not provided because the secret egress proxy is disabled: ${withheld.toSorted().join(", ")}.`,
    );
  }
  const teamBindings = launch.secretEgressBindings?.filter(
    (binding) => !Object.hasOwn(env, binding.name),
  );
  return {
    env,
    ...(teamBindings || bindings.length > 0
      ? { bindings: [...(teamBindings ?? []), ...bindings] }
      : {}),
    assertCurrent: () => {
      if (state.sessions.get(key) !== secrets) {
        throw new Error(SESSION_SECRETS_ENDED_ERROR);
      }
    },
  };
}
