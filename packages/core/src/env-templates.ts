// `${NAME}` and `${NAME:-default}`, the syntax Claude Code uses. Cursor's `${env:NAME}` is
// rewritten to `${NAME}` when a client entry is imported.
const TEMPLATE = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/gu;

export interface ExpandedTemplate {
  value: string;
  missing: string[];
}

/** Fills `${NAME}` from env; an unset name with no default stays literal and is reported. */
export function expandEnvTemplates(value: string, env: NodeJS.ProcessEnv = process.env): ExpandedTemplate {
  const missing: string[] = [];
  const expanded = value.replace(TEMPLATE, (match, name: string, fallback: string | undefined) => {
    const found = env[name];
    if (found !== undefined && found !== "") return found;
    if (fallback !== undefined) return fallback;
    if (found === "") return "";
    missing.push(name);
    return match;
  });
  return { value: expanded, missing };
}

/** Converts Cursor's `${env:NAME}` placeholders to `${NAME}`. */
export function normalizeEnvPlaceholders(value: string): string {
  return value.replace(/\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}/gu, "${$1}");
}

export interface ExpandableServer {
  command?: string | undefined;
  args: string[];
  env: Record<string, string>;
}

/** Expands command, args and env values of a server definition; reports every unset name once. */
export function expandServerTemplates<T extends ExpandableServer>(server: T, env: NodeJS.ProcessEnv = process.env): { server: T; missing: string[] } {
  const missing = new Set<string>();
  const expand = (value: string): string => {
    const result = expandEnvTemplates(value, env);
    result.missing.forEach((name) => missing.add(name));
    return result.value;
  };
  return {
    server: {
      ...server,
      ...(server.command !== undefined ? { command: expand(server.command) } : {}),
      args: server.args.map(expand),
      env: Object.fromEntries(Object.entries(server.env).map(([key, value]) => [key, expand(value)]))
    },
    missing: [...missing].sort()
  };
}
