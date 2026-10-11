import { expect, it, vi } from "vitest";
import { OutboundWindow } from "./window.js";

it("bounds and isolates session/destination windows and expires fragments", () => {
  vi.useFakeTimers();
  try {
    const window = new OutboundWindow();
    const limits = { calls: 2, ttlMs: 1000, maxBytes: 16, maxDestinations: 4 };
    expect(window.append("s", "a", "abcd", limits)).toBeUndefined();
    expect(window.append("s", "b", "efgh", limits)).toBeUndefined();
    expect(window.append("other", "a", "ijkl", limits)).toBeUndefined();
    expect(window.append("s", "a", "efgh", limits)).toBe("abcdefgh");
    expect(window.append("s", "a", "ijkl", limits)).toBe("efghijkl");
    vi.advanceTimersByTime(1001);
    expect(window.append("s", "a", "new", limits)).toBeUndefined();
    expect(() => window.append("s", "a", "x".repeat(17), limits)).toThrow("limit");
  } finally { vi.useRealTimers(); }
});
