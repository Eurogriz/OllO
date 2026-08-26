import { defineConfig, type ProxyOptions } from "vite";
import react from "@vitejs/plugin-react";

// Arena / e2b serve the browser on https://{port}-{sandbox}.e2b.app.
// Vite `--host 0.0.0.0` would otherwise inject ws://0.0.0.0:5173 into the
// client, which the user's browser cannot reach — overlay: "server connection lost".
const previewSandbox = Boolean(process.env.E2B_SANDBOX_ID || process.env.E2B_SANDBOX);

const apiProxy: Record<string, ProxyOptions> = {
  "/v1": {
    target: "http://127.0.0.1:8080",
    changeOrigin: true,
    ws: true,
    timeout: 0,
    proxyTimeout: 0,
  },
  "/healthz": { target: "http://127.0.0.1:8080", changeOrigin: true },
  "/readyz": { target: "http://127.0.0.1:8080", changeOrigin: true },
};

const hmr = previewSandbox
  ? { protocol: "wss" as const, clientPort: 443 }
  : undefined;

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    hmr,
    proxy: apiProxy,
  },
  preview: {
    host: "0.0.0.0",
    port: 5173,
    allowedHosts: true,
    proxy: apiProxy,
  },
});
