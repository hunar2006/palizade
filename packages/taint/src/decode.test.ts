import { expect, it } from "vitest";
import { expandCandidates } from "./decode.js";

it("expands nested printable encodings", () => {
  const text = "Quarterly untrusted report information";
  const encoded = Buffer.from(Buffer.from(text).toString("hex")).toString("base64url");
  expect(expandCandidates(encoded).map((view) => view.text)).toContain(text);
  expect(expandCandidates(`https://host.test/?q=${Buffer.from(text).toString("base64")}`).some((view) => view.text.includes(text))).toBe(true);
});
it("supports percent, entities, escapes, RFC2047 and punycode", () => {
  for (const [encoded, plain] of [["a%20b%ZZ", "a b%ZZ"], ["p&#x61;ypal.com", "paypal.com"], ["p\\u0061ypal.com", "paypal.com"], ["=?utf-8?b?cGF5cGFsLmNvbQ==?=", "paypal.com"], ["=?utf-8?q?hello=20world?=", "hello world"], ["xn--pypal-4ve.com", "pаypal.com"]]) {
    expect(expandCandidates(encoded!).map((view) => view.text)).toContain(plain);
  }
});
it("does not decode arbitrary binary and enforces the byte budget", () => {
  const image = Buffer.from([137, 80, 78, 71, 0, 0, 0, 0, 255, 255, 255, 255]).toString("base64");
  expect(expandCandidates(image)).toEqual([{ text: image, kind: "original" }]);
  expect(() => expandCandidates(Buffer.from("ordinary printable text").toString("base64"), { maxDepth: 2, maxBytes: 8 })).toThrow("limit");
});
