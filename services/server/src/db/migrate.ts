import { closeDb, getDb } from "./index.js";

const db = await getDb();
await closeDb();
console.log(JSON.stringify({ msg: "migrations complete", driver: process.env.DATABASE_DRIVER ?? "pglite" }));
void db;
