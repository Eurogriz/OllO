import http from "k6/http";
import { check, sleep, group } from "k6";

export const options = {
  scenarios: {
    health: {
      executor: "constant-vus",
      vus: 10,
      duration: "30s",
      exec: "health",
    },
    auth_burst: {
      executor: "ramping-arrival-rate",
      startRate: 5,
      timeUnit: "1s",
      preAllocatedVUs: 20,
      stages: [
        { target: 20, duration: "20s" },
        { target: 0, duration: "10s" },
      ],
      exec: "authBurst",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.05"],
    http_req_duration: ["p(99)<500"],
    checks: ["rate>0.95"],
  },
};

const BASE = __ENV.OLLO_BASE || "http://127.0.0.1:8080";

export function health() {
  const res = http.get(`${BASE}/healthz`);
  check(res, { "health 200": (r) => r.status === 200 });
  sleep(0.2);
}

export function authBurst() {
  group("challenge", () => {
    const res = http.post(`${BASE}/v1/auth/challenge`, "{}", {
      headers: { "content-type": "application/json" },
    });
    check(res, {
      "challenge 200 or 429": (r) => r.status === 200 || r.status === 429,
    });
  });
}

/**
 * Envelope flood is intentionally omitted from default. A real load run
 * must mint keys out-of-band and pass OLLO_ACCESS / OLLO_PEER. Never
 * generate keys inside k6.
 */
export function envelopes() {
  const token = __ENV.OLLO_ACCESS;
  const peer = __ENV.OLLO_PEER;
  if (!token || !peer) return;
  const res = http.get(`${BASE}/v1/keys/${peer}/devices`, {
    headers: { authorization: `Bearer ${token}` },
  });
  check(res, { "devices listed": (r) => r.status === 200 });
}
