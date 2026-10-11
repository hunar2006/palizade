import type { TaintStore } from "@palizade/taint";
import type { PalizadeConfig } from "./config.js";

export function trackSinkAttempt(store: TaintStore, session: string, signature: string, destinations: string[], limits: PalizadeConfig["limits"]): { rateLimited: boolean; loopDetected: boolean } {
  let result = { rateLimited: false, loopDetected: false };
  store.updateSession(session, (state) => {
    const now = Date.now();
    const calls = [...(state.sinkCalls ?? []).filter((at) => at > now - 60_000), now];
    const known = [...new Set([...(state.destinations ?? []), ...destinations])];
    const repeats = { ...state.repeats };
    const full = repeats[signature] === undefined && Object.keys(repeats).length >= limits.historyEntries;
    if (!full) repeats[signature] = Math.min(1001, (repeats[signature] ?? 0) + 1);
    const overflow = state.trackingOverflow || full || known.length > limits.historyEntries;
    result = {
      rateLimited: Boolean(overflow) || calls.length > limits.sinkCallsPerMinute || known.length > limits.distinctDestinations,
      loopDetected: full || (repeats[signature] ?? 0) > limits.repeatThreshold
    };
    return { ...state, sinkCalls: calls.slice(-limits.historyEntries), destinations: known.slice(0, limits.historyEntries), repeats, trackingOverflow: Boolean(overflow) };
  });
  return result;
}
