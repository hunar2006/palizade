import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse, resolve } from "node:path";

export const cli = resolve(import.meta.dirname, "../../packages/cli/dist/index.cjs");

export function run(command, args, options) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 45_000, ...options });
  if (result.error) throw result.error;
  return result;
}

export function powershell(script, args, cwd, env) {
  return run("powershell.exe", [
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", join(import.meta.dirname, script), ...args
  ], { cwd, env });
}

export async function createFixture() {
  if (process.platform !== "win32") throw new Error("This fixture requires Windows PowerShell.");
  const base = await mkdtemp(join(resolve(tmpdir()), "palizade-windows-"));
  const home = join(base, "home");
  await mkdir(home);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !/^(PALIZADE_|CLAUDE_|CODEX_HOME$|NODE_(?:OPTIONS|DEBUG|COMPILE_CACHE|DISABLE_COMPILE_CACHE)$|(?:HOME|HOMEPATH|HOMEDRIVE|USERPROFILE|APPDATA|LOCALAPPDATA|TEMP|TMP|TMPDIR)$|XDG_)/i.test(key)
  ));
  Object.assign(env, {
    HOME: home, USERPROFILE: home, HOMEDRIVE: parse(home).root.slice(0, 2), HOMEPATH: home.slice(2),
    APPDATA: home, LOCALAPPDATA: home, CODEX_HOME: home, CLAUDE_CONFIG_DIR: home,
    TEMP: base, TMP: base, TMPDIR: base, NODE_COMPILE_CACHE: join(base, "compile-cache"),
    PALIZADE_NO_DAEMON: "1"
  });

  return {
    base,
    home,
    env,
    setup(mode) {
      const result = powershell("setup.ps1", [mode], base, env);
      const cwd = /^Workspace: (.+)$/m.exec(result.stdout)?.[1].trim();
      if (result.status !== 0 || !cwd) throw new Error(result.stderr || result.stdout || "setup.ps1 failed");
      return cwd;
    },
    close: () => rm(base, { recursive: true, force: true, maxRetries: 3 })
  };
}
