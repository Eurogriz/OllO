import { safeEqualStr } from "../security/crypto-utils.js";

export type MetricsAccess = "ok" | "disabled" | "unauthorized";

export function metricsAccessAllowed(args: {
  isProd: boolean;
  metricsEnabled: boolean;
  metricsToken: string;
  bearer: string | undefined;
}): MetricsAccess {
  if (!args.metricsEnabled) return "disabled";
  if (!args.isProd) return "ok";
  if (!args.metricsToken) return "disabled";
  if (!args.bearer || !safeEqualStr(args.bearer, args.metricsToken)) return "unauthorized";
  return "ok";
}
