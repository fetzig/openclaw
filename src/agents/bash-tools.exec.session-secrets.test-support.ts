import { randomUUID } from "node:crypto";
import {
  registerSessionBindingAdapterV2,
  unregisterSessionBindingAdapter,
  type SessionBindingAdapterV2,
  type SessionBindingRecord,
} from "../infra/outbound/session-binding-service.js";

/** A sandbox backend for launches that must get nothing and say why. */
export const sandboxBackend = {
  containerName: "sandbox",
  workspaceDir: "/workspace",
  containerWorkdir: "/workspace",
  buildExecSpec: async ({ env }: { env: Record<string, string> }) => ({
    argv: ["sh", "-c", "echo ok"],
    env,
    stdinMode: "pipe-closed" as const,
  }),
};

/**
 * A channel's binding owner, registered in the process-wide adapter registry as a
 * thread-binding or plugin adapter registers it; tests bind and unbind sessions, or make
 * listing fail.
 */
export function installBindingOwner(ownerChannel = "matrix") {
  const bindings: SessionBindingRecord[] = [];
  const owner = { failing: false };
  const listBySession = (key: string) => {
    if (owner.failing) {
      throw new Error("binding store unavailable");
    }
    return bindings.filter((binding) => binding.targetSessionKey === key);
  };
  const adapter: SessionBindingAdapterV2 = {
    version: 2,
    channel: ownerChannel,
    accountId: "default",
    assertCurrent: () => {},
    listBySession,
    listBySessionAsync: async (key) => listBySession(key),
    resolveByConversation: () => null,
    resolveByConversationAsync: async () => null,
    inspectByConversationAsync: async () => null,
    inspectByConversationsAsync: async (refs) => ({
      bindings: refs.map(() => null),
      assertCurrent: () => {},
    }),
    touchAsync: async () => {},
  };
  registerSessionBindingAdapterV2(adapter);
  // In a Gateway, internal-channel bindings live in the generic store; the service merges
  // every owner's records, so this owner can stand in for either.
  const bind = (
    targetSessionKey: string,
    metadata?: Record<string, unknown>,
    channel = ownerChannel,
  ) =>
    bindings.push({
      bindingId: `binding-${randomUUID()}`,
      targetSessionKey,
      targetKind: "session",
      status: "active",
      boundAt: Date.now(),
      conversation: { channel, accountId: "default", conversationId: `${channel}-${randomUUID()}` },
      ...(metadata ? { metadata } : {}),
    });
  return {
    bind,
    owner,
    unbindAll: () => void bindings.splice(0),
    uninstall: () =>
      unregisterSessionBindingAdapter({ channel: ownerChannel, accountId: "default", adapter }),
  };
}
