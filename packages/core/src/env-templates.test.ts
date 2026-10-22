import { describe, expect, it } from "vitest";
import { expandEnvTemplates, expandServerTemplates, normalizeEnvPlaceholders } from "./env-templates.js";
import { resolveHeaderTemplates, resolveUrlTemplate } from "./http.js";

describe("env templates", () => {
  const env = { TOKEN: "t0k", EMPTY: "" };

  it("expands set names, defaults, and reports unset names", () => {
    expect(expandEnvTemplates("a ${TOKEN} b", env)).toEqual({ value: "a t0k b", missing: [] });
    expect(expandEnvTemplates("${NOPE:-fallback}", env)).toEqual({ value: "fallback", missing: [] });
    expect(expandEnvTemplates("${EMPTY:-fallback}", env).value).toBe("fallback");
    expect(expandEnvTemplates("${EMPTY}", env)).toEqual({ value: "", missing: [] });
    expect(expandEnvTemplates("${NOPE}", env)).toEqual({ value: "${NOPE}", missing: ["NOPE"] });
  });

  it("converts Cursor placeholders", () => {
    expect(normalizeEnvPlaceholders("Bearer ${env:TOKEN}")).toBe("Bearer ${TOKEN}");
  });

  it("expands a server definition once per name", () => {
    const result = expandServerTemplates({ command: "${TOKEN}", args: ["${A}", "${A}"], env: { K: "${TOKEN}" } }, env);
    expect(result.server).toEqual({ command: "t0k", args: ["${A}", "${A}"], env: { K: "t0k" } });
    expect(result.missing).toEqual(["A"]);
  });

  it("drops headers with unset variables and rejects urls with them", () => {
    expect(resolveHeaderTemplates({ Authorization: "Bearer ${TOKEN}", X: "${NOPE}" }, env)).toEqual({ Authorization: "Bearer t0k" });
    expect(resolveUrlTemplate("https://h/${TOKEN}", env)).toBe("https://h/t0k");
    expect(() => resolveUrlTemplate("https://${NOPE}/mcp", env)).toThrow("NOPE");
  });
});
