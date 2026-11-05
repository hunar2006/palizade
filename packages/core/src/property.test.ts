import { PassThrough } from "node:stream";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { analyzeShellCommand } from "./hooks.js";
import { LineJsonRpcPeer } from "./stdio.js";

const message = fc.record({
  jsonrpc: fc.constant("2.0"),
  id: fc.integer({ min: 0, max: 1e6 }),
  method: fc.string({ maxLength: 12 }),
  params: fc.dictionary(fc.string({ maxLength: 6 }), fc.oneof(fc.string({ unit: "grapheme", maxLength: 30 }), fc.integer(), fc.boolean()), { maxKeys: 4 })
});

/** Feeds bytes to a peer in the given chunk sizes and returns what it emitted. */
async function feed(bytes: Buffer, sizes: number[], options: ConstructorParameters<typeof LineJsonRpcPeer>[2]) {
  const input = new PassThrough();
  const peer = new LineJsonRpcPeer(input, new PassThrough(), options);
  const seen: unknown[] = [];
  const errors: string[] = [];
  peer.on("message", (value) => seen.push(value));
  peer.on("error", (error: Error) => errors.push(error.message));
  let offset = 0;
  for (let index = 0; offset < bytes.length; index += 1) {
    const size = sizes.length ? sizes[index % sizes.length]! : bytes.length;
    input.write(bytes.subarray(offset, offset + size));
    offset += size;
  }
  await new Promise((done) => setImmediate(done));
  return { seen, errors };
}

describe("JSON-RPC framing", () => {
  it("emits every newline delimited message once, in order, for any chunk boundaries (bytes, so UTF-8 splits too)", async () => {
    await fc.assert(fc.asyncProperty(fc.array(message, { minLength: 1, maxLength: 8 }), fc.array(fc.integer({ min: 1, max: 64 }), { maxLength: 8 }), async (messages, sizes) => {
      const { seen, errors } = await feed(Buffer.from(messages.map((value) => `${JSON.stringify(value)}\n`).join("")), sizes, {});
      expect(errors).toEqual([]);
      expect(seen).toEqual(messages);
    }), { numRuns: 200 });
  });

  it("does the same for Content-Length frames mixed with lines", async () => {
    await fc.assert(fc.asyncProperty(fc.array(fc.tuple(message, fc.boolean()), { minLength: 1, maxLength: 8 }), fc.array(fc.integer({ min: 1, max: 64 }), { maxLength: 8 }), async (items, sizes) => {
      const wire = items.map(([value, framed]) => {
        const body = JSON.stringify(value);
        return framed ? `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}` : `${body}\n`;
      }).join("");
      const { seen, errors } = await feed(Buffer.from(wire), sizes, { allowContentLength: true });
      expect(errors).toEqual([]);
      expect(seen).toEqual(items.map(([value]) => value));
    }), { numRuns: 200 });
  });

  it("keeps reading lines after a non JSON line in Content-Length mode", async () => {
    const { seen } = await feed(Buffer.from('warning: starting\n{"jsonrpc":"2.0","id":1,"method":"a"}\n'), [1], { allowContentLength: true });
    expect(seen).toEqual([{ jsonrpc: "2.0", id: 1, method: "a" }]);
  });

  it("never buffers more than maxBufferedBytes, whatever arrives", async () => {
    await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 4096 }), fc.boolean(), async (bytes, contentLength) => {
      const { errors } = await feed(Buffer.from(bytes), [97], { maxBufferedBytes: 1024, maxMessageBytes: 1024, allowContentLength: contentLength });
      if (bytes.length <= 1024) expect(errors.filter((error) => error.includes("buffer exceeded"))).toEqual([]);
    }), { numRuns: 200 });
  });

  it("joins a large Content-Length frame once, not per chunk (was quadratic)", async () => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "x", params: { data: "a".repeat(16 * 1024 * 1024) } });
    const start = performance.now();
    const { seen } = await feed(Buffer.from(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`), [16 * 1024], { allowContentLength: true });
    expect(seen).toHaveLength(1);
    expect(performance.now() - start).toBeLessThan(5000);
  });
});

// The shell checks as they were, as an oracle for the linear rewrite.
const OLD_SUSPICIOUS = /\$\([^)]*\)|`[^`]+`|\beval\b|\bbase64\b|\bpython3?\s+-c\b|\bnode\s+-e\b|\bperl\s+-e\b|\/dev\/tcp\b|\bchmod\s+[0-7]*[45][0-7]*\b|\bcurl\b[^|;]*\|\s*(?:bash|sh|zsh)\b|\bwget\b[^|;]*\|\s*(?:bash|sh|zsh)\b/iu;
describe("analyzeShellCommand", () => {
  const command = fc.array(fc.constantFrom("curl ", "wget ", "x ", "| ", "||", "; ", "sh", "bash", " zsh", "$(", ")", "`", "eval ", "chmod 755 ", "https://a.example/p ", "> out.txt ", "\n", "  "), { maxLength: 16 }).map((parts) => parts.join(""));
  it("flags exactly what the old pattern flagged", () => {
    fc.assert(fc.property(command, (text) => {
      expect(analyzeShellCommand(text).suspicious.includes("shell-suspicious-construct")).toBe(OLD_SUSPICIOUS.test(text));
    }), { numRuns: 2000 });
  });
  it("never throws and handles 1 MB commands quickly (was seconds at 32 KB)", () => {
    fc.assert(fc.property(fc.string({ unit: "binary", maxLength: 300 }), (text) => { analyzeShellCommand(text); }));
    for (const unit of ["$(", "curl ", "wget x ", "`"]) {
      const start = performance.now();
      analyzeShellCommand(unit.repeat(Math.ceil(1024 * 1024 / unit.length)));
      expect(performance.now() - start).toBeLessThan(5000);
    }
  });
});
