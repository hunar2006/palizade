import { closeSync, existsSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { parseYamlWithSchema } from "@palizade/policy";
import { canonicalEmail, canonicalHost } from "@palizade/taint";
import YAML from "yaml";
import { z } from "zod";
import type { ArgumentField } from "./arguments.js";
import type { PalizadeConfig } from "./config.js";

const learnedSchema = z.object({ hosts: z.array(z.string()).default([]), emails: z.array(z.string()).default([]), destinations: z.array(z.string()).default([]) }).strict();

export function destinationEntries(fields: ArgumentField[]): string[] {
  return [...new Set(fields.flatMap((field) => {
    if (field.role === "url") {
      try { return [`host:${canonicalHost(new URL(field.text).hostname)}`]; }
      catch { return [`invalid:${field.text}`]; }
    }
    if (field.role === "hostname") return [`host:${canonicalHost(field.text)}`];
    if (field.role === "email_recipient") return [`email:${canonicalEmail(field.text)}`];
    if (["repository_destination", "account_id", "channel_id"].includes(field.role)) return [`${field.role}:${field.text}`];
    return [];
  }))];
}

export class LearnedEgress {
  private lastGood: z.infer<typeof learnedSchema>;

  /** With `onInvalid`, a file that stops validating keeps the last valid version and reports the error; without it, an invalid file throws (fail closed). */
  constructor(readonly path: string, private readonly onInvalid?: (error: unknown) => void) { this.lastGood = this.read(); }

  allowlist(configured: PalizadeConfig["egress"]["allowlist"]): PalizadeConfig["egress"]["allowlist"] {
    const learned = this.current();
    return { hosts: [...configured.hosts, ...learned.hosts], emails: [...configured.emails, ...learned.emails], destinations: [...configured.destinations, ...learned.destinations] };
  }

  /** Re-reads the file now, so a bad edit is reported when it happens rather than on the next sink call. */
  validate(): void {
    this.current();
  }

  private current(): z.infer<typeof learnedSchema> {
    try {
      this.lastGood = this.read();
    } catch (error) {
      if (!this.onInvalid) throw error;
      this.onInvalid(error);
    }
    return this.lastGood;
  }

  remember(destinations: string[]): void {
    const lock = `${this.path}.lock`;
    const fd = openSync(lock, "wx", 0o600);
    const temporary = `${this.path}.${randomUUID()}.tmp`;
    try {
      const learned = this.read();
      for (const entry of destinations) {
        if (entry.startsWith("invalid:")) throw new Error("Invalid egress destination");
        const key = entry.startsWith("host:") ? "hosts" : entry.startsWith("email:") ? "emails" : "destinations";
        const value = key === "destinations" ? entry : entry.slice(entry.indexOf(":") + 1);
        if (!learned[key].includes(value)) learned[key].push(value);
      }
      writeFileSync(temporary, YAML.stringify(learned), { mode: 0o600 });
      renameSync(temporary, this.path);
    } finally {
      closeSync(fd);
      unlinkSync(lock);
      if (existsSync(temporary)) unlinkSync(temporary);
    }
  }

  private read(): z.infer<typeof learnedSchema> {
    if (!existsSync(this.path)) return learnedSchema.parse({});
    if (statSync(this.path).size > 1024 * 1024) throw new Error("Learned allowlist exceeds size limit");
    return parseYamlWithSchema(learnedSchema, readFileSync(this.path, "utf8"), this.path);
  }
}

export function destinationsAllowed(entries: string[], allowlist: PalizadeConfig["egress"]["allowlist"]): boolean {
  return entries.every((entry) => {
    if (entry.startsWith("host:")) {
      const host = entry.slice(5);
      return allowlist.hosts.some((value) => value === "*" || (value.startsWith("*.") ? host.endsWith(`.${canonicalHost(value.slice(2))}`) : canonicalHost(value) === host));
    }
    if (entry.startsWith("email:")) return allowlist.emails.some((configured) => {
      const value = configured.trim().toLowerCase();
      const email = entry.slice(6);
      if (value === "*") return true;
      const domainPattern = value.startsWith("*@") ? value.slice(2) : value.startsWith("@") ? value.slice(1) : undefined;
      if (domainPattern !== undefined) return email.slice(email.lastIndexOf("@") + 1) === canonicalHost(domainPattern);
      return canonicalEmail(value) === email;
    });
    return allowlist.destinations.includes(entry);
  });
}
