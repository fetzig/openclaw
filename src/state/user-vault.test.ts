import { beforeEach, describe, expect, it } from "vitest";
import { openOpenClawStateDatabase } from "./openclaw-state-db.js";
import { connectUserModelAccount } from "./user-model-accounts.js";
import { ensureProfileForEmail } from "./user-profiles.js";
import { useUserStateFixture } from "./user-state.test-support.js";
import {
  listUserVault,
  snapshotUserVault,
  setUserVaultEntry,
  deleteUserVaultEntry,
} from "./user-vault-operations.js";

const fixture = useUserStateFixture("user-vault-");
let options: ReturnType<typeof fixture>;
let alice: string;
let bob: string;
const current = () => {};
beforeEach(() => {
  options = fixture();
  alice = ensureProfileForEmail("alice@example.test", options).id;
  bob = ensureProfileForEmail("bob@example.test", options).id;
});
const set = (
  profileId: string,
  name: string,
  value: string,
  limits?: { maxEntries: number; maxBytes: number },
) => setUserVaultEntry({ profileId, name, value, limits, assertCurrent: current }, options);

describe("user vault", () => {
  it("isolates owners, returns metadata only, and excludes model accounts", async () => {
    connectUserModelAccount(
      {
        ownerProfileId: alice,
        credential: { type: "token", provider: "anthropic", token: "synthetic-model-token" },
        assertCurrent: current,
      },
      options,
    );
    await set(alice, "JIRA_TOKEN", "synthetic-alice");
    await set(bob, "JIRA_TOKEN", "synthetic-bob");
    const metadata = await listUserVault(alice, current, options);
    expect(metadata).toEqual([
      {
        name: "JIRA_TOKEN",
        bytes: 15,
        createdAtMs: expect.any(Number),
        updatedAtMs: expect.any(Number),
      },
    ]);
    expect(JSON.stringify(metadata)).not.toContain("synthetic-");
    expect(await snapshotUserVault(alice, current, options)).toEqual({
      JIRA_TOKEN: "synthetic-alice",
    });
    expect(await snapshotUserVault(bob, current, options)).toEqual({ JIRA_TOKEN: "synthetic-bob" });
  });
  it("uses UTF-8 replacement accounting and configured limits", async () => {
    const limits = { maxEntries: 1, maxBytes: 4 };
    await set(alice, "TOKEN", "éé", limits);
    await expect(set(alice, "TOKEN", "ééé", limits)).rejects.toThrow("limit");
    await expect(set(alice, "OTHER", "a", limits)).rejects.toThrow("limit");
    await set(alice, "TOKEN", "four", limits);
    expect(await snapshotUserVault(alice, current, options)).toEqual({ TOKEN: "four" });
  });
  it.each(["BAD-NAME", "LD_PRELOAD", "NODE_OPTIONS", "GH_TOKEN"])(
    "rejects invalid or reserved name %s",
    async (name) => {
      await expect(set(alice, name, "synthetic")).rejects.toThrow();
    },
  );
  it("permits ordinary TOKEN storage and rejects oversized/NUL values", async () => {
    await set(alice, "JIRA_TOKEN", "synthetic-vault");
    await expect(set(alice, "TOKEN", "a".repeat(65537))).rejects.toThrow("64 KiB");
    await expect(set(alice, "TOKEN", "a\0b")).rejects.toThrow("NUL");
  });
  it("hard deletes only the caller entry", async () => {
    await set(alice, "TOKEN", "synthetic-a");
    await set(bob, "TOKEN", "synthetic-b");
    await deleteUserVaultEntry(alice, "TOKEN", current, options);
    expect(await listUserVault(alice, current, options)).toEqual([]);
    expect(await snapshotUserVault(bob, current, options)).toEqual({ TOKEN: "synthetic-b" });
    const { db } = openOpenClawStateDatabase(options);
    expect(
      db
        .prepare(
          "SELECT name FROM secret_store_entries WHERE scope_kind = 'identity' AND scope_id = ? AND name = 'vault:TOKEN'",
        )
        .get(alice),
    ).toBeUndefined();
  });
  it("refuses a revoked caller before mutation or disclosure", async () => {
    const revoked = () => {
      throw new Error("revoked");
    };
    await expect(
      setUserVaultEntry(
        { profileId: alice, name: "TOKEN", value: "synthetic", assertCurrent: revoked },
        options,
      ),
    ).rejects.toThrow("revoked");
    await expect(snapshotUserVault(alice, revoked, options)).rejects.toThrow("revoked");
    expect(await listUserVault(alice, current, options)).toEqual([]);
  });
});
