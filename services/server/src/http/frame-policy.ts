/**
 * Clickjacking headers.
 *
 * Production must deny every embedder. Development (and only development)
 * allows the Arena / e2b preview iframe — `X-Frame-Options: DENY` there
 * blanks the preview and looks like the sandbox dropped the connection.
 */
export function framePolicyHeaders(isProd: boolean): Record<string, string> {
  if (isProd) {
    return {
      "X-Frame-Options": "DENY",
      "Content-Security-Policy": "frame-ancestors 'none'",
    };
  }
  return {
    "Content-Security-Policy":
      "frame-ancestors 'self' https://*.e2b.app https://*.arena.ai https://arena.ai",
  };
}
