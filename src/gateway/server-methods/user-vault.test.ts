import { beforeEach, describe, expect, it, vi } from "vitest";
import type { GatewayRequestHandlerOptions } from "./types.js";
import { userVaultHandlers } from "./user-vault.js";
const state = vi.hoisted(() => ({
  owner: "alice",
  enabled: true,
  revoked: false,
  list: vi.fn(),
  set: vi.fn(),
  remove: vi.fn(),
}));
vi.mock("./personal-profile-authorization.js", () => ({
  preparePersonalProfileAction: async () => {
    if (!state.owner) throw new Error("unverified");
    return {
      owner: state.owner,
      assertCurrent: () => {
        if (state.revoked) throw new Error("revoked");
      },
    };
  },
}));
vi.mock("../../state/user-vault-operations.js", () => ({
  listUserVault: state.list,
  setUserVaultEntry: state.set,
  deleteUserVaultEntry: state.remove,
}));
function call(method: string, params: unknown) {
  const respond = vi.fn();
  const options = {
    params,
    respond,
    context: { getRuntimeConfig: () => ({ secrets: { userVault: { enabled: state.enabled } } }) },
  } as unknown as GatewayRequestHandlerOptions;
  return Promise.resolve(userVaultHandlers[method]!(options)).then(() => respond);
}
beforeEach(() => {
  vi.clearAllMocks();
  state.owner = "alice";
  state.enabled = true;
  state.revoked = false;
  state.list.mockResolvedValue([{ name: "JIRA_TOKEN", bytes: 3, createdAtMs: 1, updatedAtMs: 1 }]);
});
describe("user vault RPC", () => {
  it("uses only the verified caller for metadata and mutations", async () => {
    const listed = await call("userVault.list", {});
    expect(state.list).toHaveBeenCalledWith("alice", expect.any(Function));
    expect(listed).toHaveBeenCalledWith(true, {
      entries: [{ name: "JIRA_TOKEN", bytes: 3, createdAtMs: 1, updatedAtMs: 1 }],
    });
    state.owner = "bob";
    const result = await call("userVault.set", { name: "TOKEN", value: "synthetic-bob" });
    expect(state.set).toHaveBeenCalledWith(
      expect.objectContaining({ profileId: "bob", name: "TOKEN", value: "synthetic-bob" }),
    );
    expect(result).toHaveBeenCalledWith(true, { ok: true });
    expect(JSON.stringify(result.mock.calls)).not.toContain("synthetic-bob");
    await call("userVault.delete", { name: "TOKEN" });
    expect(state.remove).toHaveBeenCalledWith("bob", "TOKEN", expect.any(Function));
  });
  it.each(["userVault.list", "userVault.set", "userVault.delete"])(
    "refuses a supplied owner for %s",
    async (method) => {
      const reply = await call(method, { profileId: "bob", name: "TOKEN", value: "synthetic" });
      expect(reply.mock.calls[0]?.[0]).toBe(false);
      expect(state.list).not.toHaveBeenCalled();
      expect(state.set).not.toHaveBeenCalled();
      expect(state.remove).not.toHaveBeenCalled();
    },
  );
  it.each(["disabled", "unverified", "revoked"])("blocks %s requests", async (kind) => {
    if (kind === "disabled") state.enabled = false;
    if (kind === "unverified") state.owner = "";
    if (kind === "revoked") state.revoked = true;
    const reply = await call("userVault.list", {});
    expect(reply.mock.calls[0]?.[0]).toBe(false);
    expect(state.list).not.toHaveBeenCalled();
  });
  it("does not disclose values or driver errors on failure", async () => {
    state.set.mockRejectedValueOnce(new Error("SQL value=synthetic-private"));
    const reply = await call("userVault.set", { name: "TOKEN", value: "synthetic-private" });
    expect(reply.mock.calls[0]?.[0]).toBe(false);
    expect(JSON.stringify(reply.mock.calls)).not.toContain("synthetic-private");
  });
});
