import { expect, it, vi } from "vitest";
import { InMemoryTaintStore } from "@palizade/taint";
import { trackSinkAttempt } from "./session-gates.js";

const limits = { sinkCallsPerMinute: 2, distinctDestinations: 2, repeatThreshold: 2, historyEntries: 1000 };
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
