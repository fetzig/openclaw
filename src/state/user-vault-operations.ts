import { createSqliteWorkerWriteAdmission } from "../infra/sqlite-worker-store.js";
import { registerSecretValueForRedaction } from "../logging/secret-redaction-registry.js";
import {
  assertUserVaultName,
  assertUserVaultValue,
  USER_VAULT_DEFAULT_LIMITS,
  type UserVaultLimits,
} from "../secrets/user-vault-validation.js";
import type { OpenClawStateDatabaseOptions } from "./openclaw-state-db.js";
import { captureOpenClawStateWorkerContext } from "./openclaw-state-worker-context.js";
import type { OpenClawStateWorkerOperations } from "./openclaw-state-worker-contract.js";
import { runOpenClawStateWorkerOperation } from "./openclaw-state-worker-store.js";

type Options = Pick<OpenClawStateDatabaseOptions, "path" | "env">;
type Operation = "userVault.list" | "userVault.snapshot" | "userVault.set" | "userVault.delete";

async function execute<Key extends Operation>(
  type: Key,
  input: OpenClawStateWorkerOperations[Key]["input"],
  assertCurrent: () => void,
  options: Options,
) {
  const context = captureOpenClawStateWorkerContext(options);
  const assertLive = () => {
    context.admission.assertCurrent();
    assertCurrent();
  };
  assertLive();
  const result = await runOpenClawStateWorkerOperation(
    context,
    (scope) => scope.execute({ type, input }),
    {
      assertCurrent: assertLive,
      createAdmission: createSqliteWorkerWriteAdmission(assertLive, [
        context.admission.databasePath,
      ]),
    },
  );
  assertLive();
  return result;
}

export function listUserVault(profileId: string, assertCurrent: () => void, options: Options = {}) {
  return execute("userVault.list", { profileId }, assertCurrent, options);
}

/** Private host-only snapshot. Never return values through a Gateway RPC. */
export async function snapshotUserVault(
  profileId: string,
  assertCurrent: () => void,
  options: Options = {},
) {
  const entries = await execute("userVault.snapshot", { profileId }, assertCurrent, options);
  for (const value of Object.values(entries)) {
    registerSecretValueForRedaction(value);
  }
  return entries;
}

export async function setUserVaultEntry(
  params: {
    profileId: string;
    name: string;
    value: string;
    limits?: UserVaultLimits;
    assertCurrent: () => void;
  },
  options: Options = {},
) {
  assertUserVaultName(params.name);
  assertUserVaultValue(params.value);
  registerSecretValueForRedaction(params.value);
  await execute(
    "userVault.set",
    {
      profileId: params.profileId,
      name: params.name,
      value: params.value,
      limits: params.limits ?? USER_VAULT_DEFAULT_LIMITS,
    },
    params.assertCurrent,
    options,
  );
}

export async function deleteUserVaultEntry(
  profileId: string,
  name: string,
  assertCurrent: () => void,
  options: Options = {},
) {
  assertUserVaultName(name);
  await execute("userVault.delete", { profileId, name }, assertCurrent, options);
}
