import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { helloAccessToken } from "./hello.js";

describe("hello access token", () => {
  it("uses the frame, then the Authorization header, never a query string", () => {
    assert.equal(helloAccessToken("frame-token", "header-token"), "frame-token");
    assert.equal(helloAccessToken("", "header-token"), "header-token");
    assert.equal(helloAccessToken(undefined, undefined), undefined);
    assert.equal(helloAccessToken({ query: "no" }, undefined), undefined);
  });
});
