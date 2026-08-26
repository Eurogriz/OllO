import { config } from "./config.js";
import { closeDb, getDb } from "./db/index.js";
import { buildApp } from "./app.js";
import { expireStale, startExpiryLoop } from "./jobs/expire.js";
import { log } from "./observability/logger.js";

const db = await getDb();
const app = await buildApp(db);
await expireStale(db);
const expiry = startExpiryLoop(db);

const shutdown = async (signal: string) => {
  log.info("shutdown", { signal });
  clearInterval(expiry);
  await app.close();
  await closeDb();
  process.exit(0);
};

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

await app.listen({ host: config.host, port: config.port });
log.info("ollo listening", { host: config.host, port: config.port, env: config.olloEnv });
