export type ArgumentRole =
  | "url"
  | "hostname"
  | "email_recipient"
  | "file_path"
  | "shell_command"
  | "repository_destination"
  | "http_header"
  | "http_query"
  | "body"
  | "unknown";

export interface ArgumentField {
  path: string;
  role: ArgumentRole;
  text: string;
}

const URL_RE = /\bhttps?:\/\/[^\s<>"')]+/giu;
const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu;

export function extractArgumentFields(value: unknown): ArgumentField[] {
  const fields: ArgumentField[] = [];
  visit(value, "$", fields);
  return fields;
}

export function argumentRolesSummary(fields: ArgumentField[]): string[] {
  return [...new Set(fields.map((field) => field.role))];
}

function visit(value: unknown, path: string, fields: ArgumentField[]): void {
  if (typeof value === "string") {
    const role = inferRole(path, value);
    fields.push({ path, role, text: value });
    for (const url of value.matchAll(URL_RE)) {
      fields.push({ path: `${path}<url:${url.index ?? 0}>`, role: "url", text: url[0] });
      try {
        fields.push({ path: `${path}<host:${url.index ?? 0}>`, role: "hostname", text: new URL(url[0]).hostname });
        if (new URL(url[0]).search) {
          fields.push({ path: `${path}<query:${url.index ?? 0}>`, role: "http_query", text: new URL(url[0]).search });
        }
      } catch {
        // Keep the raw URL field; URL parsing can fail for odd but still exfil-capable strings.
      }
    }
    for (const email of value.matchAll(EMAIL_RE)) {
      fields.push({ path: `${path}<email:${email.index ?? 0}>`, role: "email_recipient", text: email[0] });
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => visit(item, `${path}[${index}]`, fields));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      visit(child, `${path}.${key}`, fields);
    }
  }
}

function inferRole(path: string, value: string): ArgumentRole {
  const lowerPath = path.toLowerCase();
  if (/(^|\.)to$|recipient|email|cc|bcc/u.test(lowerPath)) return "email_recipient";
  if (/url|uri|endpoint|webhook/u.test(lowerPath) || /^https?:\/\//iu.test(value)) return "url";
  if (/host|hostname|domain/u.test(lowerPath)) return "hostname";
  if (/headers?\./u.test(lowerPath)) return "http_header";
  if (/query|params?/u.test(lowerPath)) return "http_query";
  if (/command|cmd|shell|script|exec/u.test(lowerPath)) return "shell_command";
  if (/path|file|filename|directory|dir/u.test(lowerPath)) return "file_path";
  if (/repo|repository|remote|origin/u.test(lowerPath)) return "repository_destination";
  if (/body|content|message|summary|text/u.test(lowerPath)) return "body";
  return "unknown";
}
