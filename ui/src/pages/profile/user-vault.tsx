import "../../styles/secrets-store.css";
import { action, createMemo, createSignal, Errored, For, Loading, refresh, Show } from "solid-js";
import type { UserVaultEntryMetadata } from "../../../../src/secrets/user-vault-validation.js";
import { hasOperatorReadAccess } from "../../app/operator-access.ts";
import { RefreshButton } from "../../components/solid/refresh-button.tsx";
import {
  SettingsEmpty,
  SettingsRow,
  SettingsSection,
} from "../../components/solid/settings-ui.tsx";
import { formatUiError } from "../../lib/format-error.ts";
import { projectApplicationConfig, projectGateway } from "../../lib/reactive/application.ts";
import { useApplication } from "../../lib/reactive/context.ts";
import { t } from "../../lib/reactive/i18n.ts";

export function UserVault() {
  const context = useApplication();
  const gateway = projectGateway(context.gateway);
  const config = createMemo(() =>
    context.config ? projectApplicationConfig(context.config) : null,
  );
  const target = createMemo(
    () => {
      const { snapshot, connectionRevision } = gateway.read();
      const { client, selfUser, hello, phase } = snapshot;
      return phase === "connected" &&
        client &&
        selfUser &&
        hasOperatorReadAccess(hello?.auth ?? null)
        ? { client, profileId: selfUser.id, connectionRevision }
        : null;
    },
    {
      equals: (a, b) =>
        a?.client === b?.client &&
        a?.profileId === b?.profileId &&
        a?.connectionRevision === b?.connectionRevision,
    },
  );
  const entries = createMemo(async () => {
    const scope = target();
    if (!scope || config()?.read().userVaultEnabled === false) {
      return [];
    }
    return (await scope.client.request<{ entries: UserVaultEntryMetadata[] }>("userVault.list", {}))
      .entries;
  });
  // Drafts are presentation-only and reset whenever the authenticated target changes.
  const [name, setName] = createSignal(() => {
    target();
    return "";
  });
  const [value, setValue] = createSignal(() => {
    target();
    return "";
  });
  const [error, setError] = createSignal<string | null>(() => {
    target();
    return null;
  });
  const [busy, setBusy] = createSignal(false);
  async function mutate(
    method: "userVault.set" | "userVault.delete",
    params: { name: string; value?: string },
  ) {
    const scope = target();
    if (!scope || busy()) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await scope.client.request(method, params);
      if (target() !== scope) {
        return;
      }
      setValue("");
      await refresh(entries);
    } catch (failure) {
      if (target() === scope) {
        setError(formatUiError(failure));
      }
    } finally {
      setBusy(false);
    }
  }
  const submit = action(function* (event: SubmitEvent) {
    event.preventDefault();
    yield mutate("userVault.set", { name: name(), value: value() });
  });
  return (
    <Show when={target() && config()?.read().userVaultEnabled !== false}>
      <div id="settings-profile-user-vault">
        <SettingsSection
          title={t("profilePage.userVault.title")}
          description={t("profilePage.userVault.description")}
          actions={
            <RefreshButton
              label={t("common.refresh")}
              onClick={() => {
                void refresh(entries);
              }}
              disabled={busy()}
            />
          }
        >
          <Errored fallback={(failure) => <p role="alert">{formatUiError(failure())}</p>}>
            <Loading on={target()} fallback={<p>{t("profilePage.userVault.loading")}</p>}>
              <Show
                when={entries().length > 0}
                fallback={<SettingsEmpty message={t("profilePage.userVault.empty")} />}
              >
                <For each={entries()}>
                  {(entry) => (
                    <SettingsRow
                      title={<code>{entry.name}</code>}
                      control={
                        <button
                          type="button"
                          class="btn danger"
                          disabled={busy()}
                          onClick={() => void mutate("userVault.delete", { name: entry.name })}
                        >
                          {t("profilePage.userVault.remove")}
                        </button>
                      }
                    />
                  )}
                </For>
              </Show>
            </Loading>
          </Errored>
          <form
            onSubmit={(event) => {
              void submit(event);
            }}
            autocomplete="off"
          >
            <label class="secrets-store-field">
              <span>{t("profilePage.userVault.name")}</span>
              <input
                class="settings-input mono"
                name="vault-name"
                required
                value={name()}
                onInput={(event) => setName(event.currentTarget.value)}
                disabled={busy()}
                spellcheck="false"
              />
            </label>
            <label class="secrets-store-field">
              <span>{t("profilePage.userVault.value")}</span>
              <input
                class="settings-input"
                name="vault-value"
                type="password"
                autocomplete="new-password"
                value={value()}
                onInput={(event) => setValue(event.currentTarget.value)}
                disabled={busy()}
              />
            </label>
            <p>{t("profilePage.userVault.warning")}</p>
            <Show when={error()}>{(message) => <p role="alert">{message()}</p>}</Show>
            <button class="btn primary" type="submit" disabled={busy() || !name()}>
              {t("profilePage.userVault.save")}
            </button>
          </form>
        </SettingsSection>
      </div>
    </Show>
  );
}
