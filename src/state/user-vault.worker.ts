import { executeSqliteQuerySync, getNodeSqliteKysely } from "../infra/kysely-sync.js";
import type { EngineConnection } from "../infra/sql-connection.js";
import { registerSecretValueForRedaction } from "../logging/secret-redaction-registry.js";
import {
  USER_VAULT_PREFIX,
  type UserVaultLimits,
  type UserVaultEntryMetadata,
} from "../secrets/user-vault-validation.js";
import { ensureSecretStoreSchema } from "./openclaw-state-db-schema-additive.js";
import { tableExists } from "./openclaw-state-db-schema-helpers.js";
import type { DB } from "./openclaw-state-db.generated.js";
import { requireOwner } from "./user-secret-owner.kernel.js";
import type { WorkerWriteOperationContext } from "./worker-operation-registry.js";

function vaultDb(db: EngineConnection) {
  return getNodeSqliteKysely<Pick<DB, "secret_store_entries">>(db);
}

function readEntries(db: EngineConnection, owner: string) {
  if (!tableExists(db, "secret_store_entries")) {
    return [];
  }
  return executeSqliteQuerySync(
    db,
    vaultDb(db)
      .selectFrom("secret_store_entries")
      .select(["name", "value", "created_at_ms", "updated_at_ms"])
      .where("scope_kind", "=", "identity")
      .where("scope_id", "=", owner)
      .where("name", ">=", USER_VAULT_PREFIX)
      // The colon successor bounds the exact, case-sensitive namespace.
      .where("name", "<", "vault;")
      .where("deleted_at_ms", "is", null)
      .orderBy("name"),
  ).rows;
}

export const userVaultOperations = {
  "userVault.list": (
    input: { profileId: string },
    context: WorkerWriteOperationContext,
  ): UserVaultEntryMetadata[] => {
    const { db } = context.open();
    return readEntries(db, requireOwner(db, input.profileId)).map((row) => ({
      name: row.name.slice(USER_VAULT_PREFIX.length),
      bytes: Buffer.byteLength(row.value, "utf8"),
      createdAtMs: row.created_at_ms,
      updatedAtMs: row.updated_at_ms,
    }));
  },
  "userVault.snapshot": (
    input: { profileId: string },
    context: WorkerWriteOperationContext,
  ): Record<string, string> => {
    const { db } = context.open();
    const entries = readEntries(db, requireOwner(db, input.profileId));
    for (const entry of entries) {
      registerSecretValueForRedaction(entry.value);
    }
    return Object.fromEntries(
      entries.map((row) => [row.name.slice(USER_VAULT_PREFIX.length), row.value]),
    );
  },
  "userVault.set": (
    input: { profileId: string; name: string; value: string; limits: UserVaultLimits },
    context: WorkerWriteOperationContext,
  ): void => {
    ensureSecretStoreSchema(context.open().db);
    context.writeAdmitted(
      ({ db }) => {
        const owner = requireOwner(db, input.profileId);
        const name = USER_VAULT_PREFIX + input.name;
        const previous = readEntries(db, owner);
        const replacing = previous.some((row) => row.name === name);
        const bytes = previous.reduce(
          (sum, row) => sum + (row.name === name ? 0 : Buffer.byteLength(row.value, "utf8")),
          Buffer.byteLength(input.value, "utf8"),
        );
        if (
          previous.length + (replacing ? 0 : 1) > input.limits.maxEntries ||
          bytes > input.limits.maxBytes
        ) {
          throw new Error("User vault exceeds the configured entry or byte limit.");
        }
        const now = Date.now();
        const mutable = {
          value: input.value,
          kind: "secret",
          allowed_hosts: null,
          deleted_at_ms: null,
          updated_at_ms: now,
          updated_by: owner,
        };
        executeSqliteQuerySync(
          db,
          vaultDb(db)
            .insertInto("secret_store_entries")
            .values({
              scope_kind: "identity",
              scope_id: owner,
              name,
              created_at_ms: now,
              ...mutable,
            })
            .onConflict((conflict) =>
              conflict.columns(["scope_kind", "scope_id", "name"]).doUpdateSet(mutable),
            ),
        );
      },
      { operationLabel: "userVault.set" },
    );
  },
  "userVault.delete": (
    input: { profileId: string; name: string },
    context: WorkerWriteOperationContext,
  ): void => {
    context.writeAdmitted(
      ({ db }) => {
        const owner = requireOwner(db, input.profileId);
        if (!tableExists(db, "secret_store_entries")) {
          return;
        }
        executeSqliteQuerySync(
          db,
          vaultDb(db)
            .deleteFrom("secret_store_entries")
            .where("scope_kind", "=", "identity")
            .where("scope_id", "=", owner)
            .where("name", "=", USER_VAULT_PREFIX + input.name),
        );
      },
      { operationLabel: "userVault.delete" },
    );
  },
};
