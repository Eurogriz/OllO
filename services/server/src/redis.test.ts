import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { memoryRedis, parseResp, resetRedisForTests, takeWindow } from "./redis.js";

describe("Redis RESP + window", () => {
  it("parses simple, integer, and bulk replies", () => {
    assert.equal(parseResp(Buffer.from("+PONG\r\n")).value, "PONG");
    assert.equal(parseResp(Buffer.from(":3\r\n")).value, 3);
    assert.equal(parseResp(Buffer.from("$5\r\nhello\r\n")).value, "hello");
    assert.equal(parseResp(Buffer.from("$-1\r\n")).value, null);
    assert.throws(() => parseResp(Buffer.from("-ERR nope\r\n")));
  });

  it("rate-limits in the in-memory fallback", async () => {
    resetRedisForTests(memoryRedis());
    assert.equal(await takeWindow("t:a", 2, 60), true);
    assert.equal(await takeWindow("t:a", 2, 60), true);
    assert.equal(await takeWindow("t:a", 2, 60), false);
    resetRedisForTests();
  });
});
