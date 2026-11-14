/**
 * Spike (openclaw#197297): in-memory, requester-bound exec grants.
 *
 * A grant lets one verified operator profile ("holder") deliver its own secret
 * entries into Gateway-host exec launches of one session, whoever runs the turn.
 * Values are read from a provider at launch only, merged into the spawn env, and
 * never stored here. The registry is process memory: a Gateway restart drops every grant.
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
  readonly entryNames?: readonly string[];
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

const MAX_VALUE_BYTES = 16 * 1024;
const MAX_ENTRIES = 64;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
/** OpenClaw-owned names that a grant can never set, even when no reserved key covers them. */
const OPENCLAW_OWNED_NAMES = new Set(["GH_TOKEN", "GITHUB_TOKEN", "PATH", "HOME"]);

const state = resolveGlobalSingleton(Symbol.for("openclaw.requesterGrants"), () => ({
  // storeScope \0 agentId \0 sessionKey -> the session's one grant
  grants: new Map<string, RequesterGrant>(),
  provider: undefined as RequesterGrantValueProvider | undefined,
}));

const agentOf = (target: Omit<RequesterGrantTarget, "storeScope">) =>
  normalizeAgentId(target.agentId ?? target.sessionKey.trim().split(":")[1]);
const targetKey = (target: RequesterGrantTarget) =>
  `${target.storeScope.trim()}\0${agentOf(target)}\0${target.sessionKey.trim()}`;

function isLive(grant: RequesterGrant): boolean {
  return state.grants.get(grant.key) === grant;
}

/**
 * Test-only stand-in for the owner-only RPC. The real RPC derives the holder from
 * the caller's verified profile, never from a parameter.
 */
export function enableRequesterGrantForTest(params: {
  holderProfileId: string;
  target: RequesterGrantTarget;
  entryNames?: readonly string[];
}): void {
  const key = targetKey(params.target);
  state.grants.set(key, {
    holderProfileId: params.holderProfileId,
    key,
    ...(params.entryNames ? { entryNames: Object.freeze([...params.entryNames]) } : {}),
  });
}

export function disableRequesterGrant(target: RequesterGrantTarget): void {
  state.grants.delete(targetKey(target));
}

export function setRequesterGrantValueProviderForTest(
  provider: RequesterGrantValueProvider | undefined,
): void {
  state.provider = provider;
}

export function readRequesterGrantHoldersForTest(target: RequesterGrantTarget): string[] {
  const grant = state.grants.get(targetKey(target));
  return grant ? [grant.holderProfileId] : [];
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
 * Captures the physical session the current turn runs in, from its session controller entry.
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
  caller: Readonly<{ agentId?: string; sessionKey?: string }> | undefined,
  launch: Readonly<{
    /** Sandbox and durable launches never receive values. */
    sandbox?: unknown;
    durable?: unknown;
    requesterGrant?: RequesterGrantLaunch;
    warnings: string[];
  }>,
): Promise<{ env: Record<string, string>; assertCurrent: () => void } | undefined> {
  const storeScope = launch.requesterGrant?.storeScope;
  if (!caller?.sessionKey || !storeScope) {
    return undefined;
  }
  const grant = state.grants.get(
    targetKey({ storeScope, agentId: caller.agentId, sessionKey: caller.sessionKey }),
  );
  if (!grant) {
    return undefined;
  }
  const unsupported = launch.sandbox ? "sandbox" : launch.durable ? "durable" : undefined;
  if (unsupported) {
    launch.warnings.push(
      `Warning: your session secrets were not provided to this command: ${unsupported} exec is not supported.`,
    );
    return undefined;
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
