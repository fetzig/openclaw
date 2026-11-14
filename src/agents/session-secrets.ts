/**
 * Spike (openclaw#197297): creator-bound session secrets.
 *
 * Every Gateway-host exec launch in a session whose creator is a verified person gets that
 * person's current vault entries, whoever or whatever caused the turn. There is no switch:
 * storing entries is the opt-in and deleting them the opt-out. Each launch resolves the
 * creator from the session entry and reads the entries once; nothing is kept in between.
 * `secret` entries reach commands only as sentinels that the egress proxy resolves for
 * their allowed hosts; `env` entries are plaintext. Sessions that inbound channel traffic
 * can reach get none.
 */
import { GATEWAY_OWNER_PROFILE_ID } from "../../packages/gateway-protocol/src/schema/user-profile-constants.js";
import { getRuntimeConfigSnapshot } from "../config/runtime-snapshot.js";
import { resolveCanonicalMainSessionKey } from "../config/sessions/main-session-key.js";
import { canonicalizeMainSessionAlias } from "../config/sessions/main-session.js";
import { sessionCreatorProfileId } from "../config/sessions/session-entry-provenance.js";
import type { SessionEntry } from "../config/sessions/types.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { createSyntheticPluginRuntimeClient } from "../gateway/server-plugin-runtime-client.js";
import { prepareSessionMutationFacts } from "../gateway/session-sharing-preparation.js";
import { createSessionListEntryFilter } from "../gateway/session-sharing-read.js";
import { canonicalizeSessionKeyForAgent } from "../gateway/session-store-key.js";
import {
  isDangerousHostEnvOverrideVarName,
  isDangerousHostEnvVarName,
  isGatewayCredentialEnvVarName,
} from "../infra/host-env-security.js";
import { registerSecretValueForRedaction } from "../logging/secret-redaction-registry.js";
import { normalizeAgentId } from "../routing/session-key.js";
import type { SecretEgressSentinelBinding } from "../secrets/egress-proxy/proxy-server.js";
import { isSecretEgressProxyActive } from "../secrets/egress-proxy/registry.js";
import { ENV_SECRET_REF_ID_RE } from "../secrets/ref-contract.js";
import { sealSecretSentinel } from "../secrets/sentinel.js";
import { SECRET_STORE_VALUE_MAX_BYTES } from "../secrets/store/secret-store-validation-error.js";
import { normalizeSecretAllowedHosts } from "../secrets/store/secret-store-validation.js";
import { deriveSessionChatTypeFromKey } from "../sessions/session-chat-type-shared.js";
import { getCurrentSessionControllerOwner } from "../sessions/session-controller.context.js";
import {
  getSessionControllerEntryForOperation,
  isCurrentSessionControllerOperation,
} from "../sessions/session-controller.identity.js";
import { parseThreadSessionSuffix } from "../sessions/session-key-utils.js";
import { resolveGlobalSingleton } from "../shared/global-singleton.js";
import { readResidentUserProfileIdentity } from "../state/user-profile-list.js";
import { isInternalMessageChannel } from "../utils/message-channel.js";
import { getInProcessGatewayToolContext } from "./tools/in-process-gateway.js";

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

/** An entry without its value: what status and the agent's list may show. */
export type SessionSecretEntryMetadata = Readonly<{
  name: string;
  kind: "secret" | "env";
  allowedHosts?: readonly string[];
}>;

/** Where entries come from: a vault plugin later; synthetic in the spike. */
export type SessionSecretValueProvider = {
  /** Metadata only, for status and unsupported-launch warnings. */
  listNames(
    profileId: string,
  ): Promise<readonly SessionSecretEntryMetadata[]> | readonly SessionSecretEntryMetadata[];
  /** Values: read only at launch. */
  readEntries(
    profileId: string,
  ): Promise<readonly SessionSecretEntry[]> | readonly SessionSecretEntry[];
};

/** Captured when the exec tool runs and carried to the launch, also after an approval wait. */
export type SessionSecretsLaunch = Readonly<{
  /** The session controller target of the turn that ran the tool; absent outside a session turn. */
  target?: SessionSecretsTarget;
  /** Names owned by OpenClaw or set for this call (per-call or plugin env); never values. */
  reservedKeys?: readonly string[];
}>;

const MAX_ENTRIES = 64;
/** OpenClaw-owned names that session secrets can never set, even when no reserved key covers them. */
const OPENCLAW_OWNED_NAMES = new Set(["GH_TOKEN", "GITHUB_TOKEN", "PATH", "HOME"]);

const state = resolveGlobalSingleton(Symbol.for("openclaw.sessionSecrets"), () => ({
  provider: undefined as SessionSecretValueProvider | undefined,
}));

const agentOf = (target: SessionSecretsTarget) =>
  normalizeAgentId(target.agentId ?? target.sessionKey.trim().split(":")[1]);

function currentConfig(): OpenClawConfig {
  const gateway = getInProcessGatewayToolContext();
  return (
    (gateway ? (gateway.getCommittedRuntimeConfig ?? gateway.getRuntimeConfig)() : undefined) ??
    getRuntimeConfigSnapshot() ??
    {}
  );
}

/**
 * Whose secrets a session uses: its write-once creator, by upstream's creator rule
 * (`sessionCreatorProfileId`, which follows an agent's delegation to the person), when that
 * is a verified Gateway profile. A merged profile resolves to its current canonical profile,
 * whose vault is read. Channel senders, agents, automations and the shared Gateway owner
 * profile (every token or password connection) have none. The assignable owner never counts.
 */
export function resolveSessionSecretsCreator(
  entry: Pick<SessionEntry, "createdActor"> | undefined,
): string | undefined {
  const creatorId = sessionCreatorProfileId(entry?.createdActor);
  const profileId = creatorId ? readResidentUserProfileIdentity(creatorId)?.profileId : undefined;
  return profileId &&
    creatorId !== GATEWAY_OWNER_PROFILE_ID &&
    profileId !== GATEWAY_OWNER_PROFILE_ID
    ? profileId
    : undefined;
}

/**
 * Sessions that inbound channel traffic can reach, by key, never use anyone's secrets,
 * whoever created them: the agent's main session under the configured `session.mainKey`
 * and scope (DMs with dmScope "main", groups with groupScope "main", or every message
 * under the global scope) and threads under it (Slack assistant DM threads, Telegram DM
 * topics), and every channel-peer key (DM, group or channel, threads included). Keys never
 * change, so the rule cannot drift with routing state. Conversation bindings, which can
 * point a channel at any key, are checked separately (`isBoundToConversation`).
 */
function isChannelRoutedSession(cfg: OpenClawConfig, target: SessionSecretsTarget): boolean {
  const agentId = agentOf(target);
  const sessionKey = canonicalizeSessionKeyForAgent(agentId, target.sessionKey.trim());
  const base = canonicalizeMainSessionAlias({
    cfg,
    agentId,
    sessionKey: parseThreadSessionSuffix(sessionKey).baseSessionKey ?? sessionKey,
  });
  return (
    base ===
      resolveCanonicalMainSessionKey({
        agentId,
        mainKey: cfg.session?.mainKey,
        sessionScope: cfg.session?.scope,
      }) || deriveSessionChatTypeFromKey(sessionKey) !== "unknown"
  );
}

/**
 * Conversation bindings route a channel conversation to any key: thread-bound subagents,
 * plugin binds, migrated bindings. A session bound to an external channel gets nothing, and
 * so does one whose bindings cannot be listed. Bindings to the internal channel are the
 * Control UI itself (a plugin session catalog binds a continued session to it), so they do
 * not count. A binding made after a launch applies from the next launch.
 */
async function isBoundToConversation(target: SessionSecretsTarget): Promise<boolean> {
  const agentId = agentOf(target);
  try {
    const { listSessionBindingsBySessionAsync } =
      await import("../infra/outbound/session-binding-service.js");
    const bindings = await listSessionBindingsBySessionAsync(
      canonicalizeSessionKeyForAgent(agentId, target.sessionKey.trim()),
    );
    return bindings.some((binding) => !isInternalMessageChannel(binding.conversation.channel));
  } catch {
    return true;
  }
}

async function readSessionEntry(target: SessionSecretsTarget) {
  const { loadSessionEntry } = await import("../config/sessions/session-accessor.js");
  // The accessor canonicalizes agent-relative aliases itself.
  return loadSessionEntry({
    agentId: agentOf(target),
    sessionKey: target.sessionKey.trim(),
    storePath: target.storeScope,
  });
}

/**
 * Read-only status for one session participant: whose secrets the session uses and their
 * names, never values. Undefined when the requester cannot see the session (the sharing
 * owner's read check) or the creator has no entries.
 */
export async function readSessionSecretsStatus(
  target: SessionSecretsTarget,
  requesterProfileId: string,
): Promise<{ creatorProfileId: string; entryNames: string[] } | undefined> {
  const provider = state.provider;
  if (!provider) {
    return undefined;
  }
  const cfg = currentConfig();
  if (isChannelRoutedSession(cfg, target)) {
    return undefined;
  }
  const agentId = agentOf(target);
  const sessionKey = canonicalizeSessionKeyForAgent(agentId, target.sessionKey.trim());
  const facts = await prepareSessionMutationFacts({ cfg, agentId, sessionKey }).catch(
    () => undefined,
  );
  if (!facts) {
    return undefined;
  }
  let creatorProfileId: string | undefined;
  try {
    const { target: session, membership } = facts.readCurrent(cfg);
    const client = createSyntheticPluginRuntimeClient({
      operatorRoleActor: { kind: "operator", profileId: requesterProfileId },
      scopes: ["operator.read"],
    });
    const visible = createSessionListEntryFilter({ cfg, client, membership });
    if (visible?.(sessionKey, session.entry, membership.has(requesterProfileId)) === false) {
      return undefined;
    }
    creatorProfileId = resolveSessionSecretsCreator(session.entry);
  } finally {
    facts.release();
  }
  if (!creatorProfileId || (await isBoundToConversation(target))) {
    return undefined;
  }
  const entryNames = (await provider.listNames(creatorProfileId)).map((entry) => entry.name);
  return entryNames.length > 0
    ? { creatorProfileId, entryNames: entryNames.toSorted() }
    : undefined;
}

export function setSessionSecretValueProviderForTest(
  provider: SessionSecretValueProvider | undefined,
): void {
  state.provider = provider;
}

/**
 * Mirrors the team store: names match its pattern and values its 64 KiB limit; plaintext
 * `env` entries also pass the host-env denylist, while `secret` entries are sentinels, not
 * live credentials, so names such as GH_TOKEN stay usable.
 */
function rejectionReason(name: string, value: string, kind: "secret" | "env"): string | undefined {
  if (!ENV_SECRET_REF_ID_RE.test(name)) {
    return "invalid name";
  }
  const upper = name.toUpperCase();
  if (
    kind === "env" &&
    (OPENCLAW_OWNED_NAMES.has(upper) ||
      upper.startsWith("OPENCLAW_") ||
      isDangerousHostEnvVarName(name) ||
      isDangerousHostEnvOverrideVarName(name) ||
      isGatewayCredentialEnvVarName(name))
  ) {
    return "reserved name";
  }
  if (value.includes("\0")) {
    return "NUL byte";
  }
  if (Buffer.byteLength(value) > SECRET_STORE_VALUE_MAX_BYTES) {
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
  const target =
    owner && isCurrentSessionControllerOperation(owner)
      ? getSessionControllerEntryForOperation(owner).target
      : undefined;
  return {
    reservedKeys,
    ...(target
      ? {
          target: {
            storeScope: target.storeScope,
            agentId: target.agentId,
            sessionKey: target.sessionKey,
          },
        }
      : {}),
  };
}

/**
 * Launch-time lookup, called inside runExecProcess immediately before spawn. Resolves the
 * session's creator and reads their current entries once. Returns the env to merge
 * (plaintext `env` entries and `secret` sentinels) and the egress-proxy bindings for the
 * sentinels; undefined when the session uses no one's secrets or the creator has none.
 */
export async function resolveSessionSecretsLaunch(
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
    }
  | undefined
> {
  const target = launch.sessionSecrets?.target;
  if (!target) {
    return undefined;
  }
  const provider = state.provider;
  // Checked before anything is read: like a creator without entries, silently nothing.
  const creatorProfileId =
    provider && !isChannelRoutedSession(currentConfig(), target)
      ? resolveSessionSecretsCreator(await readSessionEntry(target))
      : undefined;
  if (!provider || !creatorProfileId || (await isBoundToConversation(target))) {
    return undefined;
  }
  const unsupported = launch.sandbox ? "sandbox" : launch.durable ? "durable" : undefined;
  if (unsupported) {
    // A creator without entries gets nothing and no notice.
    if ((await provider.listNames(creatorProfileId)).length > 0) {
      launch.warnings.push(
        `Session secrets were not provided to this command: ${unsupported} exec is not supported.`,
      );
    }
    return undefined;
  }
  const entries = await provider.readEntries(creatorProfileId);
  if (entries.length === 0) {
    return undefined;
  }
  const proxyActive = isSecretEgressProxyActive();
  const reserved = new Set(launch.sessionSecrets?.reservedKeys?.map((name) => name.toUpperCase()));
  const env: Record<string, string> = {};
  const bindings: SecretEgressSentinelBinding[] = [];
  const rejected: string[] = [];
  const withheld: string[] = [];
  let count = 0;
  for (const entry of entries) {
    const { name, value } = entry;
    const kind = entry.kind ?? "secret";
    const allowedHosts = kind === "secret" ? allowedHostsOf(entry) : undefined;
    const reason =
      rejectionReason(name, value, kind) ??
      (kind === "secret" && !allowedHosts ? "no valid allowed hosts" : undefined) ??
      (++count > MAX_ENTRIES ? "too many" : undefined);
    if (reason) {
      rejected.push(
        ENV_SECRET_REF_ID_RE.test(name) ? `${name} (${reason})` : "one entry with an invalid name",
      );
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
  };
}
