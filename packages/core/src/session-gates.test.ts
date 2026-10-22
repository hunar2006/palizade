import { expect, it, vi } from "vitest";
import { InMemoryTaintStore } from "@palizade/taint";
import { trackSinkAttempt } from "./session-gates.js";

const limits = { sinkCallsPerMinute: 2, distinctDestinations: 2, repeatThreshold: 2, historyEntries: 1000, windowMs: 600_000 };
it("counts per-minute sink attempts and expires the rate window", () => {
  let now = Date.now();
  const clock = vi.spyOn(Date, "now").mockImplementation(() => now);
  try {
    const store = new InMemoryTaintStore();
    expect(trackSinkAttempt(store, "s", "1", [], limits).rateLimited).toBe(false);
    expect(trackSinkAttempt(store, "s", "2", [], limits).rateLimited).toBe(false);
    expect(trackSinkAttempt(store, "s", "3", [], limits).rateLimited).toBe(true);
    now += 60001;
    expect(trackSinkAttempt(store, "s", "4", [], limits).rateLimited).toBe(false);
  } finally { clock.mockRestore(); }
});
it("counts distinct destinations and repeated calls while isolating sessions", () => {
  const store = new InMemoryTaintStore();
  expect(trackSinkAttempt(store, "s", "same", ["a"], limits).loopDetected).toBe(false);
  expect(trackSinkAttempt(store, "s", "same", ["b"], limits).loopDetected).toBe(false);
  expect(trackSinkAttempt(store, "s", "same", ["c"], limits)).toEqual({ rateLimited: true, loopDetected: true });
  expect(trackSinkAttempt(store, "other", "same", ["a"], limits)).toEqual({ rateLimited: false, loopDetected: false });
});
it("forgets destinations and repeats older than the window", () => {
  let now = Date.now();
  const clock = vi.spyOn(Date, "now").mockImplementation(() => now);
  try {
    const store = new InMemoryTaintStore();
    const wide = { ...limits, sinkCallsPerMinute: 100 };
    expect(trackSinkAttempt(store, "s", "x", ["a"], wide).rateLimited).toBe(false);
    expect(trackSinkAttempt(store, "s", "x", ["b"], wide).rateLimited).toBe(false);
    expect(trackSinkAttempt(store, "s", "x", ["c"], wide)).toEqual({ rateLimited: true, loopDetected: true });
    now += 600_001;
    expect(trackSinkAttempt(store, "s", "x", ["d"], wide)).toEqual({ rateLimited: false, loopDetected: false });
  } finally { clock.mockRestore(); }
});
it("reads older session state without counting it", () => {
  const store = new InMemoryTaintStore();
  store.updateSession("s", (state) => ({ ...state, repeats: { same: 50 }, destinations: ["a", "b", "c"], trackingOverflow: true }));
  expect(trackSinkAttempt(store, "s", "same", ["a"], limits)).toEqual({ rateLimited: false, loopDetected: false });
  expect(store.getSession("s").repeats).toBeUndefined();
});
