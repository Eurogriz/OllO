import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  encodeCommand,
  INCR_EXPIRE_LUA,
  memoryRedis,
  parseResp,
  redisEndpoint,
  RedisWindowStore,
  resetRedisForTests,
  takeWindow,
} from "./redis.js";

describe("Redis RESP + window", () => {
  it("parses simple, integer, and bulk replies", () => {
    assert.equal(parseResp(Buffer.from("+PONG\r\n")).value, "PONG");
    assert.equal(parseResp(Buffer.from(":3\r\n")).value, 3);
    assert.equal(parseResp(Buffer.from("$5\r\nhello\r\n")).value, "hello");
    assert.equal(parseResp(Buffer.from("$-1\r\n")).value, null);
    assert.throws(() => parseResp(Buffer.from("-ERR nope\r\n")));
  });

  it("encodes EVAL so INCR+EXPIRE is one round trip", () => {
    const buf = encodeCommand(["EVAL", INCR_EXPIRE_LUA, "1", "otp:x", "60"]);
    const text = buf.toString("utf8");
    assert.match(text, /^\*5\r\n/);
    assert.match(text, /EVAL/);
    assert.match(text, /INCR/);
    assert.match(text, /EXPIRE/);
    assert.equal(text.includes("INCR\r\n*2"), false);
  });

  it("treats rediss:// as TLS and keeps ACL username", () => {
    const ep = redisEndpoint("rediss://ollo:s3cret@cache.example:6380/0");
    assert.equal(ep.host, "cache.example");
    assert.equal(ep.port, 6380);
    assert.equal(ep.tls, true);
    assert.equal(ep.username, "ollo");
    assert.equal(ep.password, "s3cret");
    const plain = redisEndpoint("redis://:onlypass@127.0.0.1:6379");
    assert.equal(plain.tls, false);
    assert.equal(plain.username, null);
    assert.equal(plain.password, "onlypass");
    const forced = redisEndpoint("redis://cache.internal:6379", true);
    assert.equal(forced.tls, true);
  });

  it("rate-limits in the in-memory fallback", async () => {
    resetRedisForTests(memoryRedis());
    assert.equal(await takeWindow("t:a", 2, 60), true);
    assert.equal(await takeWindow("t:a", 2, 60), true);
    assert.equal(await takeWindow("t:a", 2, 60), false);
    resetRedisForTests();
  });

  it("shares Fastify window counters through the same Redis client", async () => {
    resetRedisForTests(memoryRedis());
    const store = new RedisWindowStore({ timeWindow: 60_000 });
    const first = await new Promise<{ current: number; ttl: number }>((resolve, reject) => {
      store.incr("ip:1", (err, res) => (err || !res ? reject(err) : resolve(res)), 60_000);
    });
    const second = await new Promise<{ current: number; ttl: number }>((resolve, reject) => {
      store.incr("ip:1", (err, res) => (err || !res ? reject(err) : resolve(res)), 60_000);
    });
    assert.equal(first.current, 1);
    assert.equal(second.current, 2);
    resetRedisForTests();
  });
});
