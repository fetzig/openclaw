/**
 * Spike (openclaw#197297): creator-bound session secrets.
 *
 * The verified profile that created a session can turn on its personal entries for that
 * session. While on, every Gateway-host exec launch in the session gets them when its run
 * acts for a person who may send there, whoever that is. `secret` entries reach commands only as sentinels that the egress
 * proxy resolves for their allowed hosts; `env` entries are plaintext. Values are read
 * from a provider at launch only and never stored here. State is process memory: a
 * Gateway restart turns everything off.
 *
 * Ending is one check at launch, never a hook per writer: the sharing owner decides who
 * may send now, and secrets end once that reaches anyone it did not reach when they were
 * turned on, or no longer reaches the creator.
 */
import { GATEWAY_OWNER_PROFILE_ID } from "../../packages/gateway-protocol/src/schema/user-profile-constants.js";
import { getRuntimeConfigSnapshot } from "../config/runtime-snapshot.js";
import type { SessionEntry } from "../config/sessions/types.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { resolveOperatorRolePolicyForAssignment } from "../gateway/operator-role-policy.js";
import { createSyntheticPluginRuntimeClient } from "../gateway/server-plugin-runtime-client.js";
import { isSessionCreatorProfile } from "../gateway/session-creator.js";
import { authorizePreparedSessionMutation } from "../gateway/session-sharing-policy.js";
import { prepareSessionMutationFacts } from "../gateway/session-sharing-preparation.js";
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
import { getCurrentSessionControllerOwner } from "../sessions/session-controller.context.js";
import {
  getSessionControllerEntryForOperation,
  isCurrentSessionControllerOperation,
} from "../sessions/session-controller.identity.js";
import { resolveGlobalSingleton } from "../shared/global-singleton.js";
import {
  listResidentUserProfileDisplayFacts,
  prepareUserProfileCatalog,
  readResidentUserProfileIdentity,
} from "../state/user-profile-list.js";
import type { AdmittedRunOperatorAuthority } from "./admitted-run-context.js";
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

/** Where values come from: a vault plugin later; synthetic in the spike. */
export type SessionSecretValueProvider = {
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

type SessionSecrets = {
  /** The verified profile that turned them on: the creator or a profile merged with it. */
  readonly creatorProfileId: string;
  /**
   * The session incarnation they were turned on for; a reset session gets none. `/new`
   * keeps a dashboard session's sessionId and rotates only its lifecycleRevision.
   */
  readonly sessionId: string;
  readonly lifecycleRevision?: string;
  /** Profiles that could send when they were turned on; anyone else who can send ends them. */
  readonly senders: ReadonlySet<string>;
  /** sessionSecretsKey() of the session. */
  readonly key: string;
  readonly entryNames?: readonly string[];
};

export const SESSION_SECRETS_OFF_NOTICE = "Session secrets are off; this command ran without them.";
export const SESSION_SECRETS_NO_PERSON_NOTICE =
  "[REDACTED:secret-value] secrets were not provided: this run does not act for a person who may send in this session.";
export const SESSION_SECRETS_ENDED_ERROR =
  "Session secrets ended before the command started; it was not run. Ask the session creator to turn them on again.";

const MAX_ENTRIES = 64;
/** OpenClaw-owned names that session secrets can never set, even when no reserved key covers them. */
const OPENCLAW_OWNED_NAMES = new Set(["GH_TOKEN", "GITHUB_TOKEN", "PATH", "HOME"]);

const state = resolveGlobalSingleton(Symbol.for("openclaw.sessionSecrets"), () => ({
  // storeScope \0 agentId \0 sessionKey -> the session's secrets while on
  sessions: new Map<string, SessionSecrets>(),
  /** Sessions whose secrets ended in this Gateway process, so a later launch can say so. */
  ended: new Set<string>(),
  provider: undefined as SessionSecretValueProvider | undefined,
}));

const agentOf = (target: SessionSecretsTarget) =>
  normalizeAgentId(target.agentId ?? target.sessionKey.trim().split(":")[1]);

/**
 * The one registry key for a session, whoever names it: the enable request and the launch
 * (session controller target). Keys are canonicalized for their agent, so an alias such
 * as `dashboard:x` and `agent:main:dashboard:x` agree.
 */
export function sessionSecretsKey(target: SessionSecretsTarget): string {
  const agentId = agentOf(target);
  const sessionKey = canonicalizeSessionKeyForAgent(agentId, target.sessionKey.trim());
  return `${target.storeScope.trim()}\0${agentId}\0${sessionKey}`;
}

function currentConfig(): OpenClawConfig {
  const gateway = getInProcessGatewayToolContext();
  return (
    (gateway ? (gateway.getCommittedRuntimeConfig ?? gateway.getRuntimeConfig)() : undefined) ??
    getRuntimeConfigSnapshot() ??
    {}
  );
}

/**
 * The session as the sharing owner sees it now, and who may send in it: for each verified
 * person, the same check that admits their run in the session (visibility, membership,
 * operator roles, config). Connection-level admins and token connections are not people
 * and are left out; they can send in every session regardless.
 */
async function readSessionSenders(
  target: SessionSecretsTarget,
  person: Pick<AdmittedRunOperatorAuthority, "profileId" | "scopes"> | undefined,
) {
  const cfg = currentConfig();
  const agentId = agentOf(target);
  const sessionKey = canonicalizeSessionKeyForAgent(agentId, target.sessionKey.trim());
  const facts = await prepareSessionMutationFacts({ cfg, agentId, sessionKey });
  const catalog = await prepareUserProfileCatalog();
  try {
    const current = facts.readCurrent(cfg);
    const maySend = (profileId: string, scopes: readonly string[]) => {
      const profile = readResidentUserProfileIdentity(profileId);
      if (!profile || profile.profileId === GATEWAY_OWNER_PROFILE_ID) {
        return false;
      }
      const client = createSyntheticPluginRuntimeClient({
        operatorRoleActor: { kind: "operator", profileId },
        scopes: [...scopes],
      });
      const policy = resolveOperatorRolePolicyForAssignment(
        profile.profileId,
        profile.role,
        cfg,
        profile.githubLogin ?? null,
      );
      return !authorizePreparedSessionMutation({ cfg, agentId, sessionKey, client }, current, {
        policy,
        aliases: profile.aliases,
      });
    };
    const senders = new Set(
      listResidentUserProfileDisplayFacts()
        .map((profile) => profile.id)
        .filter(
          (id) =>
            readResidentUserProfileIdentity(id)?.profileId === id &&
            maySend(id, ["operator.write"]),
        ),
    );
    return {
      entry: current.target.entry,
      senders,
      /** The given person's canonical profile, when they may send in the session now. */
      sender:
        person && maySend(person.profileId, person.scopes)
          ? readResidentUserProfileIdentity(person.profileId)?.profileId
          : undefined,
    };
  } finally {
    catalog.release();
    facts.release();
  }
}

function end(key: string): void {
  if (state.sessions.delete(key)) {
    state.ended.add(key);
  }
}

/**
 * Only the session's write-once creator, when it is a verified person's Gateway profile,
 * may turn session secrets on, by upstream's creator rule: a profile merged with the
 * creator and a creation an agent made for the person count; child and cron sessions
 * qualify the same way. Channel senders, agents, automations and the shared Gateway owner
 * profile (every token or password connection) have none. The assignable owner never counts.
 */
export function isSessionSecretsCreator(
  entry: Pick<SessionEntry, "createdActor"> | undefined,
  requesterProfileId: string,
): boolean {
  return (
    requesterProfileId !== GATEWAY_OWNER_PROFILE_ID &&
    isSessionCreatorProfile(entry?.createdActor, requesterProfileId)
  );
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
  const read = await readSessionSenders(params.target, {
    profileId: params.requesterProfileId,
    scopes: ["operator.write"],
  }).catch(() => undefined);
  const { entry, senders, sender } = read ?? {};
  // The creator must also be able to send now; secrets start off and are never inherited.
  if (
    !entry?.sessionId ||
    !senders ||
    !isSessionSecretsCreator(entry, params.requesterProfileId) ||
    !sender ||
    !senders.has(sender)
  ) {
    throw new Error("Only the session's creator can turn on session secrets.");
  }
  const key = sessionSecretsKey(params.target);
  state.ended.delete(key);
  state.sessions.set(key, {
    creatorProfileId: params.requesterProfileId,
    sessionId: entry.sessionId,
    ...(entry.lifecycleRevision ? { lifecycleRevision: entry.lifecycleRevision } : {}),
    senders,
    key,
    ...(params.entryNames ? { entryNames: Object.freeze([...params.entryNames]) } : {}),
  });
}

/** The creator turns session secrets off; nobody else can. */
export function disableSessionSecrets(
  target: SessionSecretsTarget,
  requesterProfileId: string,
): void {
  const key = sessionSecretsKey(target);
  if (state.sessions.get(key)?.creatorProfileId === requesterProfileId) {
    end(key);
  }
}

export function setSessionSecretValueProviderForTest(
  provider: SessionSecretValueProvider | undefined,
): void {
  state.provider = provider;
}

/** Whose secrets the session uses, never values. */
export function readSessionSecretsCreatorForTest(target: SessionSecretsTarget): string | undefined {
  return state.sessions.get(sessionSecretsKey(target))?.creatorProfileId;
}

/** Gateway restart: the registry is memory-only. */
export function resetSessionSecretsForTest(): void {
  state.sessions.clear();
  state.ended.clear();
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
 * Launch-time lookup, called inside runExecProcess immediately before spawn. Returns the
 * env to merge (plaintext `env` entries and `secret` sentinels), the egress-proxy bindings
 * for the sentinels, and a synchronous re-check for the final spawn boundary.
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
  /** The launching run's operator authority: the person it acts for, if any. */
  operatorAuthority?: Pick<AdmittedRunOperatorAuthority, "profileId" | "scopes">,
): Promise<
  | {
      env: Record<string, string>;
      /** Every binding the launch registers with the egress proxy; absent: register none. */
      bindings?: readonly SecretEgressSentinelBinding[];
      assertCurrent: () => void;
    }
  | undefined
> {
  const target = launch.sessionSecrets?.target;
  if (!target) {
    return undefined;
  }
  const key = sessionSecretsKey(target);
  let secrets = state.sessions.get(key);
  // One read of the session and its senders per launch, only while they are on.
  const current = secrets
    ? await readSessionSenders(target, operatorAuthority).catch(() => undefined)
    : undefined;
  if (
    secrets &&
    // A reset or replaced session is a new incarnation, and an unreadable one ends them too.
    (!current ||
      secrets.sessionId !== launch.sessionId ||
      current.entry.sessionId !== secrets.sessionId ||
      current.entry.lifecycleRevision !== secrets.lifecycleRevision ||
      // More people can send now, or the creator no longer can.
      [...current.senders].some((id) => !secrets!.senders.has(id)) ||
      !current.senders.has(secrets.creatorProfileId))
  ) {
    end(key);
    secrets = undefined;
  }
  if (!secrets) {
    // The first launch after they ended says so, once.
    if (state.ended.delete(key)) {
      launch.warnings.push(SESSION_SECRETS_OFF_NOTICE);
    }
    return undefined;
  }
  // Only a run acting for a person who may send in this session gets them.
  if (!current?.sender) {
    launch.warnings.push(SESSION_SECRETS_NO_PERSON_NOTICE);
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
    assertCurrent: () => {
      if (state.sessions.get(key) !== secrets) {
        throw new Error(SESSION_SECRETS_ENDED_ERROR);
      }
    },
  };
}
