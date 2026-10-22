import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { canonicalEmail, canonicalHost } from "@palizade/taint";
import { extractArgumentFields } from "./arguments.js";
import { SseParser, SseParseError } from "./http.js";
import { LineJsonRpcPeer } from "./stdio.js";

// Seeded so a failure reproduces; change SEED to explore other inputs.
const SEED = 20261021;
function rng(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const ALPHABET = ["a", "Z", "0", " ", ":", "\n", "\r", "{", "}", "\"", "é", "😀", "​", "%", "@", ".", "/", "\\", "\u0000"];
function randomText(next: () => number, max: number): string {
  let out = "";
  const length = Math.floor(next() * max);
  for (let index = 0; index < length; index += 1) out += ALPHABET[Math.floor(next() * ALPHABET.length)]!;
  return out;
}
function splitRandomly(text: string, next: () => number): string[] {
  const chunks: string[] = [];
  let rest = text;
  while (rest.length > 0) {
    // Split on code point boundaries; byte level splits are covered by the stdio test.
    const points = [...rest];
    const take = Math.max(1, Math.floor(next() * Math.min(points.length, 9)));
    chunks.push(points.slice(0, take).join(""));
    rest = points.slice(take).join("");
  }
  return chunks;
}

describe("framing under random chunk boundaries", () => {
  it("SseParser yields the same events however the stream is split", () => {
    const next = rng(SEED);
    for (let round = 0; round < 200; round += 1) {
      const events = Array.from({ length: 1 + Math.floor(next() * 4) }, (_, index) => ({ id: String(index), data: randomText(next, 40).replace(/[\r\n]/gu, " ") || "x" }));
      const stream = events.map((event) => `id: ${event.id}\ndata: ${event.data}\n\n`).join(next() > 0.5 ? "" : ": ping\n\n");
      const whole: unknown[] = [];
      new SseParser({ maxLineBytes: 4096, maxEventBytes: 65536 }).feed(stream, (event) => whole.push(event));
      const pieces: unknown[] = [];
      const parser = new SseParser({ maxLineBytes: 4096, maxEventBytes: 65536 });
      for (const chunk of splitRandomly(stream, next)) parser.feed(chunk, (event) => pieces.push(event));
      expect(pieces).toEqual(whole);
      expect(whole.length).toBe(events.length);
    }
  });

  it("SseParser bounds a line with no newline and an event with no blank line", () => {
    const parser = new SseParser({ maxLineBytes: 64, maxEventBytes: 256 });
    expect(() => { for (let index = 0; index < 100; index += 1) parser.feed("x".repeat(10), () => {}); }).toThrow(SseParseError);
    const events = new SseParser({ maxLineBytes: 64, maxEventBytes: 256 });
    expect(() => { for (let index = 0; index < 100; index += 1) events.feed("data: 0123456789\n", () => {}); }).toThrow(/event exceeded/u);
  });

  it("LineJsonRpcPeer decodes split multi byte characters and ignores garbage lines without crashing", async () => {
    const next = rng(SEED + 1);
    const messages = Array.from({ length: 50 }, (_, index) => ({ jsonrpc: "2.0", id: index, method: "x", params: { text: randomText(next, 30) } }));
    const bytes = Buffer.from(messages.map((message) => JSON.stringify(message)).join("\n") + "\nnot json at all\n", "utf8");
    const input = new PassThrough();
    const peer = new LineJsonRpcPeer(input, new PassThrough());
    const received: unknown[] = [];
    peer.on("message", (message: unknown) => received.push(message));
    peer.on("error", () => {});
    let offset = 0;
    while (offset < bytes.length) {
      const size = 1 + Math.floor(next() * 7);
      input.write(bytes.subarray(offset, offset + size));
      offset += size;
    }
    input.end();
    await new Promise((resolveWait) => setImmediate(resolveWait));
    expect(received).toEqual(messages);
  });
});

describe("parsers never throw on hostile input", () => {
  it("argument extraction, host and email canonicalization", () => {
    const next = rng(SEED + 2);
    for (let round = 0; round < 500; round += 1) {
      const text = randomText(next, 60);
      expect(() => extractArgumentFields({ url: `https://${text}`, to: `${text}@${text}`, nested: [{ deep: text }] }, "send_email")).not.toThrow();
      expect(() => canonicalHost(text)).not.toThrow();
      expect(() => canonicalEmail(text)).not.toThrow();
    }
  });

  it("deeply nested arguments do not overflow the stack", () => {
    let value: unknown = "leaf";
    for (let depth = 0; depth < 5000; depth += 1) value = { child: value };
    expect(() => extractArgumentFields(value, "tool")).not.toThrow();
  });
});
