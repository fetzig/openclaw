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
import { resolveGlobalSingleton } from "../shared/global-singleton.js";
import type { AdmittedRunOperatorAuthority } from "./admitted-run-operator-authority.types.js";
import {
  currentOperationalRunSequence,
  readOperationalRunSequence,
  type OperationalRunInstanceRef,
} from "./operational-run-instance.js";

export type RequesterGrantMode = "single-turn" | "full-session";
export type RequesterGrantTarget = Readonly<{ agentId?: string; sessionKey: string }>;

type RequesterGrant = {
  readonly holderProfileId: string;
  readonly agentId: string;
  readonly sessionKey: string;
  readonly mode: RequesterGrantMode;
  readonly entryNames?: readonly string[];
  readonly createdSeq: number;
  readonly expiresAt: number;
  pinnedRunInstanceId?: string;
};

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
  // agentId \0 sessionKey -> holderProfileId -> grant
  grants: new Map<string, Map<string, RequesterGrant>>(),
  provider: undefined as RequesterGrantValueProvider | undefined,
  runEndObserver: undefined as (() => void) | undefined,
}));

const keyOf = (agentId: string, sessionKey: string) => `${agentId}\0${sessionKey}`;
const targetKey = (target: RequesterGrantTarget) => {
  const sessionKey = target.sessionKey.trim();
  return keyOf(normalizeAgentId(target.agentId ?? sessionKey.split(":")[1]), sessionKey);
};

function isLive(grant: RequesterGrant): boolean {
  const current = state.grants.get(keyOf(grant.agentId, grant.sessionKey));
  return current?.get(grant.holderProfileId) === grant && Date.now() < grant.expiresAt;
}

function removeGrant(grant: RequesterGrant): void {
  const key = keyOf(grant.agentId, grant.sessionKey);
  const holders = state.grants.get(key);
  if (holders?.get(grant.holderProfileId) === grant) {
    holders.delete(grant.holderProfileId);
    if (holders.size === 0) {
      state.grants.delete(key);
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
  const [agentId, sessionKey] = key.split("\0") as [string, string];
  const holders = state.grants.get(key) ?? new Map<string, RequesterGrant>();
  state.grants.set(key, holders);
  holders.set(params.holderProfileId, {
    holderProfileId: params.holderProfileId,
    agentId,
    sessionKey,
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

/** Breaker: another sender (or an unverified one) entering the session ends other holders' grants. */
export function revokeOtherRequesterGrants(
  target: RequesterGrantTarget,
  senderProfileId: string | undefined,
): void {
  const holders = state.grants.get(targetKey(target));
  for (const grant of holders?.values() ?? []) {
    if (grant.holderProfileId !== senderProfileId) {
      removeGrant(grant);
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
    /** Names owned by OpenClaw or set explicitly for this call; values never travel. */
    requesterGrantReservedKeys?: readonly string[];
    warnings: string[];
  }>,
): Promise<{ env: Record<string, string>; assertCurrent: () => void } | undefined> {
  const profileId = caller?.operatorAuthority?.profileId;
  const run = caller?.operationalRunInstance;
  if (!caller?.sessionKey || !profileId) {
    return undefined;
  }
  const grant = state.grants
    .get(targetKey({ agentId: caller.agentId, sessionKey: caller.sessionKey }))
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
  const reserved = new Set(launch.requesterGrantReservedKeys?.map((key) => key.toUpperCase()));
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
