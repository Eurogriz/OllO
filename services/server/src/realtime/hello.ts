/** Prefer the hello frame. Never take a token from the URL. */
export function helloAccessToken(frameToken: unknown, headerBearer: string | undefined): string | undefined {
  if (typeof frameToken === "string" && frameToken.length > 0) return frameToken;
  if (headerBearer && headerBearer.length > 0) return headerBearer;
  return undefined;
}
