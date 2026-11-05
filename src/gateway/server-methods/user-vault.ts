import { z } from "zod";
import { ErrorCodes, errorShape } from "../../../packages/gateway-protocol/src/index.js";
import { USER_VAULT_DEFAULT_LIMITS } from "../../secrets/user-vault-validation.js";
import {
  listUserVault,
  setUserVaultEntry,
  deleteUserVaultEntry,
} from "../../state/user-vault-operations.js";
import { preparePersonalProfileAction } from "./personal-profile-authorization.js";
import type { GatewayRequestHandler, GatewayRequestHandlers } from "./types.js";

const emptyParams = z.strictObject({});
const nameParams = z.strictObject({ name: z.string() });
const setParams = nameParams.extend({ value: z.string() });

function handler<Schema extends z.ZodType>(
  schema: Schema,
  action: (
    params: z.output<Schema>,
    options: Parameters<GatewayRequestHandler>[0],
    owner: string,
    assertCurrent: () => void,
  ) => Promise<unknown>,
): GatewayRequestHandler {
  return async (options) => {
    const parsed = schema.safeParse(options.params);
    if (!parsed.success) {
      options.respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "Invalid user vault parameters."),
      );
      return;
    }
    try {
      const authority = await preparePersonalProfileAction(options);
      const assertCurrent = () => {
        authority.assertCurrent();
        if (options.context.getRuntimeConfig().secrets?.userVault?.enabled === false) {
          throw new Error("User vault is disabled by Gateway configuration.");
        }
      };
      assertCurrent();
      const result = await action(parsed.data, options, authority.owner, assertCurrent);
      assertCurrent();
      options.respond(true, result);
    } catch {
      // Storage errors may contain driver details. No request value or SQL reaches RPC errors.
      options.respond(
        false,
        undefined,
        errorShape(
          ErrorCodes.INVALID_REQUEST,
          "User vault request was refused. Verify your profile, vault limits, and Gateway settings.",
        ),
      );
    }
  };
}

export const userVaultHandlers: GatewayRequestHandlers = {
  "userVault.list": handler(emptyParams, async (_params, _options, owner, assertCurrent) => ({
    entries: await listUserVault(owner, assertCurrent),
  })),
  "userVault.set": handler(setParams, async (params, options, owner, assertCurrent) => {
    const config = options.context.getRuntimeConfig().secrets?.userVault;
    await setUserVaultEntry({
      profileId: owner,
      ...params,
      assertCurrent,
      limits: {
        maxEntries: config?.maxEntries ?? USER_VAULT_DEFAULT_LIMITS.maxEntries,
        maxBytes: config?.maxBytes ?? USER_VAULT_DEFAULT_LIMITS.maxBytes,
      },
    });
    return { ok: true };
  }),
  "userVault.delete": handler(nameParams, async (params, _options, owner, assertCurrent) => {
    await deleteUserVaultEntry(owner, params.name, assertCurrent);
    return { ok: true };
  }),
};
