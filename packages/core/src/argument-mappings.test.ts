import { expect, it } from "vitest";
import { extractArgumentFields } from "./arguments.js";

it("maps common Slack and GitHub destinations", () => {
  expect(extractArgumentFields({ channel: "C123456789" }, "slack_post_message")[0]?.role).toBe("channel_id");
  expect(extractArgumentFields({ owner: "alice", repo: "app" }, "create_issue").map((field) => field.role)).toEqual(["account_id", "repository_destination"]);
  expect(extractArgumentFields({ content: "user authored prose" }, "write_file")[0]?.role).toBe("body");
});
it("lets per-tool JSON paths override inferred roles including array members", () => {
  expect(extractArgumentFields({ data: [{ destination: "1234" }] }, "custom", { "$.data[*].destination": "account_id" })[0]?.role).toBe("account_id");
  expect(extractArgumentFields({ to: "value" }, "send_email", { "$.to": "body" })[0]?.role).toBe("body");
});
