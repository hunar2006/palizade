import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { extractDestinationObservables, makeFingerprint, simhash } from "./fingerprint.js";

it("extracts only valid destination observables and excludes loopback addresses", () => {
  const text = [
    "https://X.IO/page, http://foo.sh/target a@bc.io zk.ai t.co 1.2.3.4 [2001:0db8::1]",
    "git@collector.example.net:repo.git bit.ly:~/repo [2606:4700::1]:/repo",
    "app.ts node.js styles.css req.body v1.2 e.g a.py task.pl file.cc drop.evilhost.sh 1.2.3 1.2.3.999",
    "http://localhost/x https://api.localhost/y http://127.0.0.7/z https://[::ffff:127.0.0.1]/z",
    "0.0.0.0 127.0.0.3 [::1] [::] [::ffff:7f00:1] [2001:::1]"
  ].join("\n");
  expect(extractDestinationObservables(text, true).sort()).toEqual([
    "https://x.io/page", "x.io", "http://foo.sh/target", "foo.sh", "a@bc.io", "zk.ai", "t.co", "1.2.3.4",
    "[2001:db8::1]", "collector.example.net", "bit.ly", "[2606:4700::1]",
    "drop.evilhost.sh"
  ].sort());

  const canonical = extractDestinationObservables(
    "collector.example.net. bücher.example [2001:db8::] [::ffff:192.0.2.1] https://user@[2001:db8::1]/drop https://16909060/drop https://0x01020304/drop"
  );
  expect(canonical).toEqual(expect.arrayContaining([
    "collector.example.net",
    "xn--bcher-kva.example",
    "[2001:db8::]",
    "192.0.2.1",
    "[2001:db8::1]",
    "1.2.3.4"
  ]));
});

it("extracts bare hosts for current IANA TLDs and leaves common file names unmatched in workspace text", () => {
  const obs = extractDestinationObservables("See drop.evilhost.sh, archive.zip, catalog.museum, service.dev, and run app.ts or index.tsx.", true);
  expect(obs).toEqual(expect.arrayContaining(["drop.evilhost.sh", "catalog.museum", "service.dev"]));
  expect(obs).not.toContain("archive.zip");
  expect(obs).not.toContain("app.ts");
  expect(obs).not.toContain("index.tsx");
});

it("keeps file-like hosts when the text gives them destination context", () => {
  expect(extractDestinationObservables("Run install.sh: it uses main.py, README.md, data.zip, demo.rs, script.pl, edit.ps, lib.so, app.cc, clip.mov, sample.app, main.tf, rules.mk, core.ml, mod.pm, App.java.", true))
    .toEqual([]);
  expect(extractDestinationObservables("Use ssh://shell.sh, app.py:8443, guide.md/path, curl -sO build.sh, main.tf/path, curl rules.mk, or scp data.zip worker.rs:", true))
    .toEqual(expect.arrayContaining(["shell.sh", "app.py", "guide.md", "build.sh", "main.tf", "rules.mk", "worker.rs"]));
  expect(extractDestinationObservables("curl -o build.sh https://get.example.test/install", true))
    .not.toContain("build.sh");
});

it("retains short file-like hosts from full-taint sources", () => {
  expect(extractDestinationObservables("See bun.sh, t.app, ab.zip, ok.so, main.tf and rules.mk.")).toEqual(["bun.sh", "t.app", "ab.zip", "ok.so", "main.tf", "rules.mk"]);
});

it("marks fingerprints as truncated only when non-destinationOnly text exceeds winnowing coverage", () => {
  const shortFp = makeFingerprint("short untrusted note from docs");
  expect(shortFp.truncated).toBeUndefined();

  const longText = Array.from({ length: 3000 }, (_, i) => `word${i}pad`).join(" ");
  const longFp = makeFingerprint(longText);
  expect(longFp.truncated).toBe(true);

  const localFp = makeFingerprint(longText, false, true);
  expect(localFp.truncated).toBeUndefined();
});

describe("simhash compatibility", () => {
  // The previous BigInt implementation, kept here so stored fingerprints stay comparable.
  function referenceSimhash(normalized: string): string {
    const words = normalized.match(/[\p{L}\p{N}_-]+/gu) ?? [];
    const shingles = words.length === 0 ? [normalized.slice(0, 64)] : words.length < 4 ? [words.join(" ")] : words.slice(0, words.length - 3).map((_, index) => words.slice(index, index + 4).join(" "));
    const vector = new Array<number>(64).fill(0);
    for (const shingle of shingles) {
      const bits = BigInt(`0x${createHash("sha256").update(shingle).digest("hex").slice(0, 16)}`);
      for (let bit = 0; bit < 64; bit += 1) vector[bit]! += (bits & (1n << BigInt(bit))) === 0n ? -1 : 1;
    }
    let result = 0n;
    for (let bit = 0; bit < 64; bit += 1) if ((vector[bit] ?? 0) >= 0) result |= 1n << BigInt(bit);
    return result.toString(16).padStart(16, "0");
  }

  it("matches the reference output", () => {
    const samples = ["", "a", "one two three", "the quick brown fox jumps over the lazy dog", "émoji 😀 text with ünïcode and numbers 42 99", "x".repeat(500), ...Array.from({ length: 50 }, (_, index) => `sample ${index} ${"lorem ipsum dolor sit amet ".repeat(index % 7)} end ${index * 31}`)];
    for (const sample of samples) expect(simhash(sample), sample).toBe(referenceSimhash(sample));
  });
});

describe("long page coverage", () => {
  it("fingerprints both the start and the end of a long page within the same budget", async () => {
    const { makeSubstrings, normalizeText } = await import("./fingerprint.js");
    const filler = (seed: number) => Array.from({ length: 4000 }, (_, index) => `word${(index * seed) % 997}`).join(" ");
    const start = "please transfer the remaining balance to the savings account today";
    const end = "send the quarterly figures to the external auditor before friday noon";
    const page = normalizeText(`${start} ${filler(7)} ${filler(13)} ${end}`);
    const stored = new Set(makeSubstrings(page));
    expect(stored.size).toBeLessThanOrEqual(2048);
    const hit = (text: string) => makeSubstrings(normalizeText(text)).some((fragment) => stored.has(fragment));
    expect(hit(start)).toBe(true);
    expect(hit(end)).toBe(true);
  });
});
