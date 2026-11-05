import {
  isDangerousHostEnvVarName,
  isDangerousHostEnvOverrideVarName,
} from "../infra/host-env-security.js";
import { ENV_SECRET_REF_ID_RE } from "./ref-contract.js";

export const USER_VAULT_PREFIX = "vault:";
export const USER_VAULT_VALUE_MAX_BYTES = 64 * 1024;
export const USER_VAULT_DEFAULT_LIMITS = { maxEntries: 100, maxBytes: 1024 * 1024 };
export type UserVaultLimits = { maxEntries: number; maxBytes: number };
export type UserVaultEntryMetadata = {
  name: string;
  bytes: number;
  createdAtMs: number;
  updatedAtMs: number;
};

export function assertUserVaultName(name: string): void {
  if (!ENV_SECRET_REF_ID_RE.test(name)) {
    throw new Error("User vault names must be environment variable identifiers.");
  }
  if (isDangerousHostEnvVarName(name) || isDangerousHostEnvOverrideVarName(name)) {
    throw new Error("User vault name is reserved by host environment policy.");
  }
}

export function assertUserVaultValue(value: string): void {
  if (Buffer.byteLength(value, "utf8") > USER_VAULT_VALUE_MAX_BYTES) {
    throw new Error("User vault values must not exceed 64 KiB.");
  }
  if (value.includes("\0")) {
    throw new Error("User vault values cannot contain NUL bytes.");
  }
}
