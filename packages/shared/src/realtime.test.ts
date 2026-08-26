import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { canSeePresence, hiddenPresence, realtimeHello, realtimeUrl } from "./realtime.js";

describe("realtime url", () => {
  it("never puts a session secret in the socket URL", () => {
    assert.equal(realtimeUrl("https://api.ollo.example"), "https://api.ollo.example/v1/realtime");
    assert.equal(realtimeUrl("https://api.ollo.example/"), "https://api.ollo.example/v1/realtime");
    assert.equal(realtimeUrl("https://api.ollo.example").includes("token"), false);
    assert.equal(realtimeUrl("https://api.ollo.example").includes("?"), false);
    const hello = JSON.stringify(realtimeHello("secret-access"));
    assert.equal(hello.includes("/v1/realtime"), false);
    assert.equal(JSON.parse(hello).op, "hello");
    assert.equal(JSON.parse(hello).access_token, "secret-access");
  });
});

describe("presence visibility", () => {
  it("hides online state from strangers", () => {
    assert.equal(canSeePresence("u1", "u1", false), true);
    assert.equal(canSeePresence("u1", "u2", true), true);
    assert.equal(canSeePresence("u1", "u2", false), false);
    assert.deepEqual(hiddenPresence("u2"), { user_id: "u2", state: "offline", last_seen_day: null });
  });
});
