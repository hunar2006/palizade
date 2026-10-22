import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { LearnedEgress, destinationsAllowed } from "./egress.js";

it("retains legacy email-domain allowlists and denies other domains", () => {
  for (const email of ["@example.test", "*@example.test", " USER@EXAMPLE.TEST "]) {
    const allowlist = { hosts: [], emails: [email], destinations: [] };
    expect(destinationsAllowed(["email:user@example.test"], allowlist)).toBe(true);
    expect(destinationsAllowed(["email:user@other.test"], allowlist)).toBe(false);
  }
});

it("remembers new hosts separately and reloads changes without rewriting config", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palizade-learned-"));
  try {
    const file = join(dir, "palizade.allow.yaml");
    const store = new LearnedEgress(file);
    const empty = { hosts: [], emails: [], destinations: [] };
    expect(destinationsAllowed(["host:example.test"], store.allowlist(empty))).toBe(false);
    store.remember(["host:example.test"]);
    expect(await readFile(file, "utf8")).toContain("example.test");
    expect(destinationsAllowed(["host:example.test"], store.allowlist(empty))).toBe(true);
    await writeFile(file, "hosts: [new.test]\n");
    expect(store.allowlist(empty).hosts).toEqual(["new.test"]);
    await writeFile(file, "hosts: bad\n");
    expect(() => store.allowlist(empty)).toThrow();
  } finally { await rm(dir, { recursive: true, force: true }); }
});

describe("allowlist uses canonical destinations", () => {
  it("matches emails and hosts regardless of spelling", async () => {
    const { destinationsAllowed, destinationEntries } = await import("./egress.js");
    const allowlist = { hosts: ["api.example.com"], emails: ["@example.com"], destinations: [] };
    const fields = [
      { path: "$.to", role: "email_recipient" as const, text: "Ops@EXAMPLE.com" },
      { path: "$.host", role: "hostname" as const, text: "API.example.com." }
    ];
    expect(destinationsAllowed(destinationEntries(fields), allowlist)).toBe(true);
    expect(destinationsAllowed(destinationEntries([{ path: "$.to", role: "email_recipient" as const, text: "ops@example.com.evil.test" }]), allowlist)).toBe(false);
  });
});

describe("learned allowlist editing", () => {
  it("adds, canonicalizes and removes entries", async () => {
    const file = join(await mkdtemp(join(tmpdir(), "palizade-allow-")), "palizade.allow.yaml");
    const learned = new LearnedEgress(file);
    learned.remember(["host:API.Example.com", "email:Boss@Example.com", "channel_id:C1"]);
    expect(learned.entries()).toEqual({ hosts: ["api.example.com"], emails: ["boss@example.com"], destinations: ["channel_id:C1"] });
    expect(destinationsAllowed(["host:api.example.com"], learned.allowlist({ hosts: [], emails: [], destinations: [] }))).toBe(true);
    expect(learned.forget(["host:api.example.com", "host:missing.example"])).toBe(1);
    expect(learned.entries().hosts).toEqual([]);
  });
});
