import { describe, expect, it } from "vitest";
import { resolveControlUiBootstrapPresentation } from "../gateway/control-ui-bootstrap-presentation.js";
import { SecretsConfigSchema } from "./zod-schema.core.js";
describe("user vault configuration", () => {
  it("does not materialize optional defaults", () => {
    expect(SecretsConfigSchema.parse({})).toEqual({});
    expect(resolveControlUiBootstrapPresentation({}).userVaultEnabled).toBe(true);
  });
  it.each([0, "0", "1h", "1h30m"])("accepts exposure TTL %s", (exposureTtl) => {
    expect(SecretsConfigSchema.safeParse({ userVault: { exposureTtl } }).success).toBe(true);
  });
  it.each([
    { exposureTtl: "-1h" },
    { exposureTtl: "forever" },
    { maxBytes: 0 },
    { maxEntries: 1.5 },
    { unknown: true },
  ])("rejects invalid config %j", (userVault) => {
    expect(SecretsConfigSchema.safeParse({ userVault }).success).toBe(false);
  });
  it("hides the feature when disabled", () => {
    expect(
      resolveControlUiBootstrapPresentation({ secrets: { userVault: { enabled: false } } })
        .userVaultEnabled,
    ).toBe(false);
  });
});
