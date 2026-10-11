import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
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
