import type { EngineConnection } from "../infra/sql-connection.js";
import { tableExists } from "./openclaw-state-db-schema-helpers.js";
import { selectResolvedUserProfile, userProfilesDb } from "./user-profiles-internal.js";

export function resolveOwner(db: EngineConnection, profileId: string): string | undefined {
  if (!tableExists(db, "user_profiles")) {
    return undefined;
  }
  const profile = selectResolvedUserProfile(
    db,
    profileId,
    userProfilesDb(db).selectFrom("user_profiles").select(["id", "merged_into"]),
  );
  // Profile display reads may return a stranded tombstone; it cannot own secrets.
  return profile && !profile.merged_into ? profile.id : undefined;
}

export function requireOwner(db: EngineConnection, profileId: string): string {
  const owner = resolveOwner(db, profileId);
  if (!owner) {
    throw new Error("Personal secret owner is unavailable; refresh Profile and try again.");
  }
  return owner;
}
