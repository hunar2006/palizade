export interface WindowLimits { calls: number; ttlMs: number; maxBytes: number; maxDestinations: number }

export class OutboundWindow {
  // shortcut: independently padded encoded shards may obscure concatenation, add per-shard decoded windows when adaptive evaluation requires them.
  // shortcut: outbound windows are process-local memory only, use an authenticated encrypted shared store for cross-process split correlation.
  private readonly windows = new Map<string, Array<{ text: string; at: number }>>();

  append(session: string, destination: string, text: string, limits: WindowLimits): string | undefined {
    const now = Date.now();
    for (const [key, rows] of this.windows) {
      if (!rows.some((row) => row.at > now - limits.ttlMs)) this.windows.delete(key);
    }
    const key = JSON.stringify([session, destination]);
    if (!this.windows.has(key) && this.windows.size >= limits.maxDestinations) throw new Error("Outbound destination window limit exceeded");
    const rows = (this.windows.get(key) ?? []).filter((row) => row.at > now - limits.ttlMs).slice(-(limits.calls - 1));
    if (limits.calls === 1) rows.length = 0;
    const previous = rows.length;
    rows.push({ text, at: now });
    const combined = rows.map((row) => row.text).join("");
    if (Buffer.byteLength(combined) > limits.maxBytes) throw new Error("Outbound window byte limit exceeded");
    this.windows.set(key, rows);
    return previous ? combined : undefined;
  }
}
