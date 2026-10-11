import { execFileSync } from "node:child_process";
import { canonicalHost } from "@palizade/taint";
import type { ArgumentField } from "./arguments.js";
import { destinationsAllowed } from "./egress.js";
import type { PalizadeConfig } from "./config.js";

export function checkGitPush(tool: string, fields: ArgumentField[], cwd: string, allowlist: PalizadeConfig["egress"]["allowlist"]): { unapproved: boolean; destinations: string[] } {
  const commands = fields.filter((field) => field.role === "shell_command" && /\bgit\b[\s\S]{0,200}\bpush\b/iu.test(field.text));
  const native = /^(?:git[_-]?)?push$/iu.test(tool);
  if (!commands.length && !native) return { unapproved: false, destinations: [] };
  if (commands.length > 1) return { unapproved: true, destinations: [] };
  // shortcut: only simple literal git push remotes are resolved, require approval for dynamic/compound commands and extend parsing when needed.
  const command = commands[0]?.text;
  if (command && /[\n\r$`|;&]|--(?:repo|receive-pack)/u.test(command)) return { unapproved: true, destinations: [] };
  const remote = command ? /\bgit\s+push(?:\s+--[\w-]+|\s+-[a-z]+)*\s+["']?([^\s"'|;&]+)/iu.exec(command)?.[1] : fields.find((field) => /\.(remote|repository)$/iu.test(field.path))?.text;
  if (!remote) return { unapproved: true, destinations: [] };
  let urls = [remote];
  if (/^[a-z0-9_.-]+$/iu.test(remote)) {
    try { urls = execFileSync("git", ["remote", "get-url", "--push", "--all", remote], { cwd, encoding: "utf8", timeout: 1000, maxBuffer: 4096, windowsHide: true }).trim().split(/\r?\n/u); }
    catch { return { unapproved: true, destinations: [] }; }
  }
  const destinations = urls.map((url) => {
    try { return `host:${canonicalHost(new URL(url).hostname)}`; }
    catch {
      const ssh = /^(?:[^@\s]+@)?([^/:\s]+):[^\s]+$/u.exec(url);
      return ssh ? `host:${canonicalHost(ssh[1]!)}` : `repository_destination:${url}`;
    }
  });
  return { unapproved: !destinationsAllowed(destinations, allowlist), destinations };
}
