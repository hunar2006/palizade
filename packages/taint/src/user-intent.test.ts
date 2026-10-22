import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SqliteTaintStore } from "./sqlite.js";
import { InMemoryTaintStore } from "./store.js";
import { extractStatedObservables, maskStatedObservables } from "./user-intent.js";

describe("user stated destinations", () => {
  it("extracts destination shaped values only", () => {
    const stated = extractStatedObservables("Email the summary to Alice@Corp.example, post in #eng-updates, then open https://Docs.Example.com/guide and pay GB29NWBK60161331926819. Thanks, bob.");
    expect(stated).toEqual(expect.arrayContaining([
      "email:alice@corp.example",
      "handle:#eng-updates",
      "url:https://docs.example.com/guide",
      "host:docs.example.com",
      "account:GB29NWBK60161331926819"
    ]));
    expect(stated.some((value) => value.includes("summary") || value.includes("thanks"))).toBe(false);
  });

  it("masks only the stated values and keeps the rest of the text", () => {
    const stated = new Set(extractStatedObservables("send it to alice@corp.example"));
    const result = maskStatedObservables("to alice@corp.example and cc mallory@evil.example", (value) => stated.has(value));
    expect(result.masked).toEqual(["email:alice@corp.example"]);
    expect(result.text).toContain("mallory@evil.example");
    expect(result.text).not.toContain("alice@corp.example");
  });

  it("does not let a stated host vouch for a different url on that host", () => {
    const stated = new Set(extractStatedObservables("look at docs.example.com"));
    const result = maskStatedObservables("https://docs.example.com/collect?d=copied", (value) => stated.has(value));
    expect(result.masked).toEqual([]);
  });

  it("canonicalizes hidden characters and case before comparing", () => {
    const stated = new Set(extractStatedObservables("ALICE@corp.example"));
    expect(maskStatedObservables("ali​ce@CORP.example", (value) => stated.has(value)).masked).toHaveLength(1);
  });

  it("stores statements with an expiry in both stores, keyed so values are not kept", async () => {
    const dir = await mkdtemp(join(tmpdir(), "palizade-intent-"));
    const sqlite = new SqliteTaintStore(join(dir, "taint.sqlite"), { keyPath: join(dir, "taint.key") });
    try {
      for (const store of [new InMemoryTaintStore(), sqlite]) {
        store.addUserStatements("s1", ["email:alice@corp.example"], 60_000);
        store.addUserStatements("s1", ["email:old@corp.example"], -1);
        expect(store.isUserStated("s1", "email:alice@corp.example")).toBe(true);
        expect(store.isUserStated("s1", "email:old@corp.example")).toBe(false);
        expect(store.isUserStated("s1", "email:other@corp.example")).toBe(false);
      }
      const reopened = new SqliteTaintStore(join(dir, "taint.sqlite"), { keyPath: join(dir, "taint.key") });
      expect(reopened.isUserStated("another-session", "email:alice@corp.example")).toBe(true);
      reopened.close();
    } finally {
      sqlite.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
});
