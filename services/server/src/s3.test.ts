import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { canonicalRequest, signingKey, stringToSign } from "./s3.js";

describe("S3 SigV4", () => {
  it("derives a 32-byte SigV4 signing key", () => {
    const key = signingKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1");
    assert.equal(key.length, 32);
  });

  it("builds a canonical request with sorted headers", () => {
    const canon = canonicalRequest({
      method: "PUT",
      path: "/bucket/a/b",
      query: "",
      headers: { Host: "s3.example", "X-Amz-Date": "20150830T123600Z", "x-amz-content-sha256": "abc" },
      payloadHash: "abc",
    });
    assert.match(canon, /^PUT\n\/bucket\/a\/b\n\n/);
    assert.match(canon, /host:s3.example/);
    assert.match(canon, /host;x-amz-content-sha256;x-amz-date/);
  });

  it("string-to-sign starts with the algorithm name", () => {
    const s = stringToSign("20150830T123600Z", "20150830", "eu-central-1", "canon");
    assert.equal(s.startsWith("AWS4-HMAC-SHA256\n"), true);
  });
});
