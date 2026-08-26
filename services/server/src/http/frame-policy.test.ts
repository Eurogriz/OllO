import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { framePolicyHeaders } from "./frame-policy.js";

describe("frame policy", () => {
  it("blocks every embedder in production", () => {
    const h = framePolicyHeaders(true);
    assert.equal(h["X-Frame-Options"], "DENY");
    assert.equal(h["Content-Security-Policy"], "frame-ancestors 'none'");
  });

  it("allows Arena and e2b preview iframes in development", () => {
    const h = framePolicyHeaders(false);
    assert.equal(Object.hasOwn(h, "X-Frame-Options"), false);
    const csp = h["Content-Security-Policy"] ?? "";
    assert.match(csp, /frame-ancestors/);
    assert.equal(csp.includes("'none'"), false);
    assert.match(csp, /https:\/\/\*\.e2b\.app/);
    assert.match(csp, /https:\/\/\*\.arena\.ai/);
  });
});
