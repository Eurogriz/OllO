import client from "prom-client";
import { config } from "../config.js";

export const registry = new client.Registry();

if (config.metricsEnabled) {
  client.collectDefaultMetrics({ register: registry });
}

export const httpRequests = new client.Counter({
  name: "ollo_http_requests_total",
  help: "HTTP requests",
  labelNames: ["route", "code", "method"],
  registers: [registry],
});

export const envelopesAccepted = new client.Counter({
  name: "ollo_envelopes_accepted_total",
  help: "Accepted envelopes",
  registers: [registry],
});

export const wsConnections = new client.Gauge({
  name: "ollo_ws_connections",
  help: "Open websocket connections",
  registers: [registry],
});
