/* @vitest-environment jsdom */
import { afterEach, expect, it, vi } from "vitest";
import type { GatewayBrowserClient } from "../../api/gateway.ts";
import { registerProfileEnglish } from "../../i18n/locales/en-profile.ts";
import { registerEnglishCatalog, t } from "../../lib/reactive/i18n.ts";
import { mountSolid, cleanupSolid } from "../../test-helpers/mount-solid.ts";
import { createSolidApplicationContextProvider } from "../../test-helpers/solid-application-context.tsx";
import { waitForSolid, flush } from "../../test-helpers/solid-settle.ts";
import { createConnectedContext } from "./profile-page.test-support.tsx";
import { UserVault } from "./user-vault.tsx";
registerEnglishCatalog(registerProfileEnglish);
afterEach(cleanupSolid);
function mount(request: GatewayBrowserClient["request"]) {
  registerEnglishCatalog(registerProfileEnglish);
  const fixture = createConnectedContext(request, { id: "alice", name: "Alice" });
  const provider = createSolidApplicationContextProvider(fixture.context);
  return { fixture, ...mountSolid(() => <UserVault />, { wrapper: provider.wrapper }) };
}
it("lists names without a stored-value reveal and sends masked writes to the self-only RPC", async () => {
  const request = vi.fn(async (method: string) =>
    method === "userVault.list"
      ? { entries: [{ name: "JIRA_TOKEN", bytes: 12, createdAtMs: 1, updatedAtMs: 1 }] }
      : { ok: true },
  );
  const view = mount(request as GatewayBrowserClient["request"]);
  await waitForSolid(() => expect(view.container.textContent).toContain("JIRA_TOKEN"));
  expect(view.container.querySelector('input[name="vault-value"]')?.getAttribute("type")).toBe(
    "password",
  );
  const name = view.container.querySelector<HTMLInputElement>('input[name="vault-name"]')!;
  const value = view.container.querySelector<HTMLInputElement>('input[name="vault-value"]')!;
  name.value = "TOKEN";
  name.dispatchEvent(new Event("input", { bubbles: true }));
  value.value = "synthetic-private";
  value.dispatchEvent(new Event("input", { bubbles: true }));
  await flush();
  view.container
    .querySelector("form")!
    .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await waitForSolid(() =>
    expect(request).toHaveBeenCalledWith("userVault.set", {
      name: "TOKEN",
      value: "synthetic-private",
    }),
  );
  await waitForSolid(() => expect(value.value).toBe(""));
  expect(view.container.textContent).not.toContain("synthetic-private");
});
it("clears private drafts when the authenticated person changes", async () => {
  const request = vi.fn(async () => ({ entries: [] }));
  const view = mount(request as GatewayBrowserClient["request"]);
  await waitForSolid(() => expect(view.container.querySelector("form")).not.toBeNull());
  const value = view.container.querySelector<HTMLInputElement>('input[name="vault-value"]')!;
  value.value = "synthetic-alice";
  value.dispatchEvent(new Event("input", { bubbles: true }));
  await flush();
  view.fixture.emitSnapshot({ selfUser: { id: "bob", name: "Bob" } });
  await waitForSolid(() => expect(value.value).toBe(""));
});
it("does not expose controls to an unidentified connection", async () => {
  const request = vi.fn(async () => ({ entries: [] }));
  const view = mount(request as GatewayBrowserClient["request"]);
  view.fixture.emitSnapshot({ selfUser: null });
  await flush();
  expect(view.container.querySelector("form")).toBeNull();
});

it("never keeps Alice metadata visible while Bob's vault is pending", async () => {
  let resolveBob!: (value: { entries: [] }) => void;
  const bob = new Promise<{ entries: [] }>((resolve) => {
    resolveBob = resolve;
  });
  const request = vi
    .fn()
    .mockResolvedValueOnce({
      entries: [{ name: "ALICE_TOKEN", bytes: 3, createdAtMs: 1, updatedAtMs: 1 }],
    })
    .mockImplementation(() => bob);
  const view = mount(request as GatewayBrowserClient["request"]);
  await waitForSolid(() => expect(view.container.textContent).toContain("ALICE_TOKEN"));
  view.fixture.emitSnapshot({ selfUser: { id: "bob", name: "Bob" } });
  await waitForSolid(() => expect(view.container.textContent).not.toContain("ALICE_TOKEN"));
  resolveBob({ entries: [] });
  await waitForSolid(() =>
    expect(view.container.textContent).toContain(t("profilePage.userVault.empty")),
  );
});
