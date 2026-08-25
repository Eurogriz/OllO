import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 10,
  duration: "30s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(99)<500"],
  },
};

const BASE = __ENV.OLLO_BASE || "http://127.0.0.1:8080";

export default function () {
  const health = http.get(`${BASE}/healthz`);
  check(health, { "health 200": (r) => r.status === 200 });
  sleep(0.2);
}
