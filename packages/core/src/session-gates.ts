import type { TaintStore } from "@palizade/taint";
import type { PalizadeConfig } from "./config.js";

export function trackSinkAttempt(store: TaintStore, session: string, signature: string, destinations: string[], limits: PalizadeConfig["limits"]): { rateLimited: boolean; loopDetected: boolean } {
  let result = { rateLimited: false, loopDetected: false };
  store.updateSession(session, (state) => {
    const now = Date.now();
    const since = now - limits.windowMs;
    const calls = [...(state.sinkCalls ?? []).filter((at) => at > now - 60_000), now];
    // Destinations and repeats count within a sliding window, so a long session is not
    // rate limited forever by work it did hours ago.
    const seen: Record<string, number> = {};
    for (const [key, at] of Object.entries(state.recentDestinations ?? {})) if (at > since) seen[key] = at;
    for (const key of destinations) seen[key] = now;
    const repeats: Record<string, number[]> = {};
    for (const [key, times] of Object.entries(state.recentRepeats ?? {})) {
      const kept = Array.isArray(times) ? times.filter((at) => at > since) : [];
      if (kept.length > 0) repeats[key] = kept;
    }
    // Fail closed when too many distinct calls arrive inside one window to track them all.
    const full = repeats[signature] === undefined && Object.keys(repeats).length >= limits.historyEntries;
    if (!full) repeats[signature] = [...(repeats[signature] ?? []), now].slice(-(limits.repeatThreshold + 1));
    const overflow = full || Object.keys(seen).length > limits.historyEntries;
    result = {
      rateLimited: overflow || calls.length > limits.sinkCallsPerMinute || Object.keys(seen).length > limits.distinctDestinations,
      loopDetected: full || (repeats[signature]?.length ?? 0) > limits.repeatThreshold
    };
    const { repeats: _oldRepeats, destinations: _oldDestinations, ...rest } = state;
    return {
      ...rest,
      sinkCalls: calls.slice(-limits.historyEntries),
      recentDestinations: Object.fromEntries(Object.entries(seen).sort(([, a], [, b]) => b - a).slice(0, limits.historyEntries)),
      recentRepeats: repeats,
      trackingOverflow: overflow
    };
  });
  return result;
}
