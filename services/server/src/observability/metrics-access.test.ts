import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { metricsAccessAllowed } from "./metrics-access.js";

describe("metrics access", () => {
  it("is open in development when enabled", () => {
    assert.equal(
      metricsAccessAllowed({
        isProd: false,
        metricsEnabled: true,
        metricsToken: "",
        bearer: undefined,
      }),
      "ok",
    );
  });

  it("is closed in production without a scrape token", () => {
    assert.equal(
      metricsAccessAllowed({
        isProd: true,
        metricsEnabled: true,
        metricsToken: "",
        bearer: "guess",
      }),
      "disabled",
    );
  });

  it("requires the scrape token in production", () => {
    assert.equal(
      metricsAccessAllowed({
        isProd: true,
        metricsEnabled: true,
        metricsToken: "scrape-secret",
        bearer: undefined,
      }),
      "unauthorized",
    );
    assert.equal(
      metricsAccessAllowed({
        isProd: true,
        metricsEnabled: true,
        metricsToken: "scrape-secret",
        bearer: "wrong-secret",
      }),
      "unauthorized",
    );
    assert.equal(
      metricsAccessAllowed({
        isProd: true,
        metricsEnabled: true,
        metricsToken: "scrape-secret",
        bearer: "scrape-secret",
      }),
      "ok",
    );
  });

  it("stays off when metrics are disabled", () => {
    assert.equal(
      metricsAccessAllowed({
        isProd: false,
        metricsEnabled: false,
        metricsToken: "scrape-secret",
        bearer: "scrape-secret",
      }),
      "disabled",
    );
  });
});
