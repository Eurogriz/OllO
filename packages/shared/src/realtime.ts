/** Browser WebSocket cannot set Authorization. The token goes in hello, never the URL. */
export const REALTIME_PATH = "/v1/realtime";

export function realtimeUrl(origin: string): string {
  const base = origin.replace(/\/$/, "");
  return `${base}${REALTIME_PATH}`;
}

export function realtimeHello(
  accessToken: string,
  resume?: string,
): { op: "hello"; access_token: string; resume?: string } {
  const frame: { op: "hello"; access_token: string; resume?: string } = {
    op: "hello",
    access_token: accessToken,
  };
  if (resume) frame.resume = resume;
  return frame;
}

/** Presence of another user is only for a contact or the user themselves. */
export function canSeePresence(viewerUserId: string, targetUserId: string, isContact: boolean): boolean {
  if (!viewerUserId || !targetUserId) return false;
  return viewerUserId === targetUserId || isContact;
}

export function hiddenPresence(userId: string): { user_id: string; state: "offline"; last_seen_day: null } {
  return { user_id: userId, state: "offline", last_seen_day: null };
}
