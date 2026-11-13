import { registerAgentRunDelegatedAuthorityClosedHandler } from "../infra/agent-run-registry.js";
/**
 * Spike (openclaw#197297): in-memory, requester-bound exec grants.
 *
 * A grant lets one verified operator profile ("holder") deliver its own secret
 * entries into Gateway-host exec launches of one session. Values are read from a
 * provider at launch only, merged into the spawn env, and never stored here.
 * The registry is process memory: a Gateway restart drops every grant.
 */
import {
  isDangerousHostEnvOverrideVarName,
  isDangerousHostEnvVarName,
  isGatewayCredentialEnvVarName,
} from "../infra/host-env-security.js";
import { registerSecretValueForRedaction } from "../logging/secret-redaction-registry.js";
import { normalizeAgentId } from "../routing/session-key.js";
import { getCurrentSessionControllerOwner } from "../sessions/session-controller.context.js";
import {
  getSessionControllerEntryForOperation,
  isCurrentSessionControllerOperation,
} from "../sessions/session-controller.identity.js";
import { resolveGlobalSingleton } from "../shared/global-singleton.js";
import type { AdmittedRunOperatorAuthority } from "./admitted-run-operator-authority.types.js";
import {
  currentOperationalRunSequence,
  readOperationalRunSequence,
  type OperationalRunInstanceRef,
} from "./operational-run-instance.js";

export type RequesterGrantMode = "single-turn" | "full-session";
/**
 * One physical session: the session store it lives in, its agent and its key. The same
 * agent and key in two session stores are two sessions and never share a grant.
 */
export type RequesterGrantTarget = Readonly<{
  storeScope: string;
  agentId?: string;
  sessionKey: string;
}>;

type RequesterGrant = {
  readonly holderProfileId: string;
  /** targetKey() of the session the grant belongs to. */
  readonly key: string;
  readonly mode: RequesterGrantMode;
  readonly entryNames?: readonly string[];
  readonly createdSeq: number;
  readonly expiresAt: number;
  pinnedRunInstanceId?: string;
};

/** Captured when the exec tool runs and carried to the launch, also after an approval wait. */
export type RequesterGrantLaunch = Readonly<{
  /** Session store of the turn that ran the tool; absent outside a session turn. */
  storeScope?: string;
  /** Names owned by OpenClaw or set explicitly for this call; values never travel. */
  reservedKeys?: readonly string[];
}>;

/** Where values come from: core vault storage or a plugin later; synthetic in the spike. */
export type RequesterGrantValueProvider = {
  readEntries(holderProfileId: string): Promise<Record<string, string>> | Record<string, string>;
};

const DEFAULT_EXPOSURE_TTL_MS = 60 * 60 * 1000;
const MAX_VALUE_BYTES = 16 * 1024;
const MAX_ENTRIES = 64;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
/** OpenClaw-owned names that a grant can never set, even when no reserved key covers them. */
const OPENCLAW_OWNED_NAMES = new Set(["GH_TOKEN", "GITHUB_TOKEN", "PATH", "HOME"]);

const state = resolveGlobalSingleton(Symbol.for("openclaw.requesterGrants"), () => ({
  // storeScope \0 agentId \0 sessionKey -> holderProfileId -> grant
  grants: new Map<string, Map<string, RequesterGrant>>(),
  provider: undefined as RequesterGrantValueProvider | undefined,
  runEndObserver: undefined as (() => void) | undefined,
}));

const agentOf = (target: Omit<RequesterGrantTarget, "storeScope">) =>
  normalizeAgentId(target.agentId ?? target.sessionKey.trim().split(":")[1]);
const targetKey = (target: RequesterGrantTarget) =>
  `${target.storeScope.trim()}\0${agentOf(target)}\0${target.sessionKey.trim()}`;

function isLive(grant: RequesterGrant): boolean {
  const current = state.grants.get(grant.key);
  return current?.get(grant.holderProfileId) === grant && Date.now() < grant.expiresAt;
}

function removeGrant(grant: RequesterGrant): void {
  const holders = state.grants.get(grant.key);
  if (holders?.get(grant.holderProfileId) === grant) {
    holders.delete(grant.holderProfileId);
    if (holders.size === 0) {
      state.grants.delete(grant.key);
    }
  }
}

/** Single-turn grants end with their pinned run's outer delegated authority. */
function observeRunEnd(): void {
  state.runEndObserver ??= registerAgentRunDelegatedAuthorityClosedHandler(
    (authority, approvalReason) => {
      if (approvalReason) {
        return; // An approval lease closing is not the end of the run.
      }
      for (const holders of state.grants.values()) {
        for (const grant of holders.values()) {
          if (grant.pinnedRunInstanceId === authority.operationalRunInstance.instanceId) {
            removeGrant(grant);
          }
        }
      }
    },
  );
}

/**
 * Test-only stand-in for the owner-only RPC. The real RPC derives the holder from
 * the caller's verified profile, never from a parameter.
 */
export function enableRequesterGrantForTest(params: {
  holderProfileId: string;
  target: RequesterGrantTarget;
  mode: RequesterGrantMode;
  entryNames?: readonly string[];
  ttlMs?: number;
}): void {
  const key = targetKey(params.target);
  const holders = state.grants.get(key) ?? new Map<string, RequesterGrant>();
  state.grants.set(key, holders);
  holders.set(params.holderProfileId, {
    holderProfileId: params.holderProfileId,
    key,
    mode: params.mode,
    ...(params.entryNames ? { entryNames: Object.freeze([...params.entryNames]) } : {}),
    // Every run created after this point has a higher sequence number.
    createdSeq: currentOperationalRunSequence(),
    expiresAt: Date.now() + (params.ttlMs ?? DEFAULT_EXPOSURE_TTL_MS),
  });
}

export function disableRequesterGrant(target: RequesterGrantTarget, holderProfileId: string): void {
  const grant = state.grants.get(targetKey(target))?.get(holderProfileId);
  if (grant) {
    removeGrant(grant);
  }
}

/**
 * Breaker: another sender (or an unverified one) entering the session ends other holders' grants.
 * An input without a known session store ends them in every store with that agent and key.
 */
export function revokeOtherRequesterGrants(
  target: Omit<RequesterGrantTarget, "storeScope"> & { storeScope?: string },
  senderProfileId: string | undefined,
): void {
  const { storeScope } = target;
  const suffix = `\0${agentOf(target)}\0${target.sessionKey.trim()}`;
  for (const [key, holders] of state.grants) {
    if (storeScope ? key !== targetKey({ ...target, storeScope }) : !key.endsWith(suffix)) {
      continue;
    }
    for (const grant of holders.values()) {
      if (grant.holderProfileId !== senderProfileId) {
        removeGrant(grant);
      }
    }
  }
}

export function setRequesterGrantValueProviderForTest(
  provider: RequesterGrantValueProvider | undefined,
): void {
  state.provider = provider;
}

export function readRequesterGrantHoldersForTest(target: RequesterGrantTarget): string[] {
  return [...(state.grants.get(targetKey(target))?.keys() ?? [])].toSorted();
}

/** Gateway restart: the registry is memory-only. */
export function resetRequesterGrantsForTest(): void {
  state.grants.clear();
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

/**
 * Captures the physical session the current turn runs in. Its store comes from the same
 * session controller entry whose inputs trip the breaker, so lookup and revocation agree.
 */
export function captureRequesterGrantLaunch(reservedKeys: readonly string[]): RequesterGrantLaunch {
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
 * Launch-time lookup, called inside runExecProcess immediately before spawn.
 * Returns the env to merge and a synchronous re-check for the final spawn boundary.
 */
export async function resolveRequesterGrantLaunch(
  caller:
    | Readonly<{
        agentId?: string;
        sessionKey?: string;
        operatorAuthority?: AdmittedRunOperatorAuthority;
        operationalRunInstance?: OperationalRunInstanceRef;
      }>
    | undefined,
  launch: Readonly<{
    /** Sandbox and durable launches never receive values. */
    sandbox?: unknown;
    durable?: unknown;
    requesterGrant?: RequesterGrantLaunch;
    warnings: string[];
  }>,
): Promise<{ env: Record<string, string>; assertCurrent: () => void } | undefined> {
  const profileId = caller?.operatorAuthority?.profileId;
  const run = caller?.operationalRunInstance;
  const storeScope = launch.requesterGrant?.storeScope;
  if (!caller?.sessionKey || !profileId || !storeScope) {
    return undefined;
  }
  const grant = state.grants
    .get(targetKey({ storeScope, agentId: caller.agentId, sessionKey: caller.sessionKey }))
    ?.get(profileId);
  if (!grant) {
    return undefined;
  }
  if (Date.now() >= grant.expiresAt) {
    removeGrant(grant);
    return undefined;
  }
  const runSeq = run ? readOperationalRunSequence(run) : undefined;
  if (
    !run ||
    runSeq === undefined ||
    grant.createdSeq >= runSeq ||
    (grant.mode === "single-turn" &&
      grant.pinnedRunInstanceId !== undefined &&
      grant.pinnedRunInstanceId !== run.instanceId)
  ) {
    return undefined;
  }
  const unsupported = launch.sandbox ? "sandbox" : launch.durable ? "durable" : undefined;
  if (unsupported) {
    launch.warnings.push(
      `Warning: your session secrets were not provided to this command: ${unsupported} exec is not supported.`,
    );
    return undefined;
  }
  if (grant.mode === "single-turn" && grant.pinnedRunInstanceId === undefined) {
    grant.pinnedRunInstanceId = run.instanceId;
    observeRunEnd();
  }
  const entries = (await state.provider?.readEntries(grant.holderProfileId)) ?? {};
  // The grant may have ended while the provider was reading.
  if (!isLive(grant)) {
    return undefined;
  }
  const reserved = new Set(launch.requesterGrant?.reservedKeys?.map((key) => key.toUpperCase()));
  const env: Record<string, string> = {};
  const rejected: string[] = [];
  let count = 0;
  for (const [name, value] of Object.entries(entries)) {
    if (grant.entryNames && !grant.entryNames.includes(name)) {
      continue;
    }
    const reason = rejectionReason(name, value) ?? (++count > MAX_ENTRIES ? "too many" : undefined);
    if (reason) {
      rejected.push(ENV_NAME.test(name) ? `${name} (${reason})` : "one entry with an invalid name");
      continue;
    }
    if (reserved.has(name.toUpperCase())) {
      continue;
    }
    registerSecretValueForRedaction(value);
    env[name] = value;
  }
  if (rejected.length > 0) {
    launch.warnings.push(
      `Warning: session secret entries were not provided: ${rejected.toSorted().join(", ")}.`,
    );
  }
  return {
    env,
    assertCurrent: () => {
      if (!isLive(grant)) {
        throw new Error(
          "Session secrets were revoked before the command started; it was not run. Re-enable them and retry.",
        );
      }
    },
  };
}
