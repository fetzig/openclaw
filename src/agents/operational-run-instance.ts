import { randomUUID } from "node:crypto";

/** Operational lifecycle correlation. This is never identity or authorization evidence. */
export type OperationalRunInstanceRef = Readonly<{
  instanceId: string;
  runId: string;
}>;

let lastRunSequence = 0;
const runSequences = new WeakMap<OperationalRunInstanceRef, number>();

export function createOperationalRunInstanceRef(runId: string): OperationalRunInstanceRef {
  const ref = Object.freeze({ instanceId: randomUUID(), runId });
  runSequences.set(ref, ++lastRunSequence);
  return ref;
}

/** Creation order only: a value created at sequence N precedes every run with a higher number. */
export function readOperationalRunSequence(ref: OperationalRunInstanceRef): number | undefined {
  return runSequences.get(ref);
}

export function currentOperationalRunSequence(): number {
  return lastRunSequence;
}
