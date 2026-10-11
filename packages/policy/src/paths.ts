import { isAbsolute, matchesGlob } from "node:path";
import { homedir } from "node:os";

export function matchesPathGlob(path: string, pattern: string, insensitive = process.platform === "win32" || process.platform === "darwin"): boolean {
  let glob = pattern.replace(/\\/gu, "/").replace(/^~(?=\/|$)/u, homedir().replace(/\\/gu, "/"));
  if (!isAbsolute(glob) && !/^[a-z]:\//iu.test(glob)) glob = `**/${glob}`;
  const normalized = path.replace(/\\/gu, "/");
  // Node globstars skip dot directories; a matching-only sentinel lets protected paths cover hidden ancestors too.
  const view = (value: string) => (insensitive ? value.toLowerCase() : value).replace(/(^|\/)\.(?=[^/])/gu, "$1\0.");
  return matchesGlob(view(normalized), view(glob));
}
