import { describe, expect, it } from "vitest";
import { argumentRolesSummary, extractArgumentFields } from "./arguments.js";

describe("argument role extraction", () => {
  it("infers destinations, payloads, paths, and query values from tool arguments", () => {
    const fields = extractArgumentFields({
      to: "security@example.test",
      endpoint: "https://evil.example/upload?token=abc123",
      path: "C:/tmp/report.txt",
      body: "Quarterly report"
    });

    expect(argumentRolesSummary(fields)).toEqual(expect.arrayContaining([
      "email_recipient",
      "url",
      "hostname",
      "http_query",
      "file_path",
      "body"
    ]));
  });
});
