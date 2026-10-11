import { isAbsolute, matchesGlob } from "node:path";
import { homedir } from "node:os";

export function matchesPathGlob(path: string, pattern: string, insensitive = process.platform === "win32" || process.platform === "darwin"): boolean {
  let glob = pattern.replace(/\\/gu, "/").replace(/^~(?=\/|$)/u, homedir().replace(/\\/gu, "/"));
  if (!isAbsolute(glob) && !/^[a-z]:\//iu.test(glob)) glob = `**/${glob}`;
  const normalized = path.replace(/\\/gu, "/");
  return matchesGlob(insensitive ? normalized.toLowerCase() : normalized, insensitive ? glob.toLowerCase() : glob);
}
