import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { InnerMessage } from "@ollo/protocol";
import { t, type Lang } from "./i18n";
import { QrCard } from "./QrCard";
import {
  type Account,
  type ChatMessage,
  accountAddress,
  api,
  b64u,
  clearAccount,
  computeSafety,
  createBackupFile,
  confirmPendingMembership,
  createSignedGroup,
  distributeOwnSenderKey,
  downloadAndDecrypt,
  encryptFile,
  flushOutbox,
  ingestSenderKey,
  loadAccount,
  materialFromBackup,
  maybeRotateSignedPrekey,
  mergeBackupHistory,
  newDeviceMaterial,
  noteEnvelope,
  announceDeviceDrop,
  applyDeviceDropNotice,
  dropDeviceSessions,
  pruneSessionsForUser,
  rotateSenderKeysAfterDeviceDrop,
  realtimeHello,
  realtimeUrl,
  openEnvelope,
  parseUserUri,
  pendingMembershipNotice,
  registerWithIdentity,
  rejectPendingMembership,
  replenishPrekeys,
  resolveSenderEd25519,
  saveAccount,
  searchLocal,
  sendToGroup,
  sendToUser,
  syncGroupMembership,
  syncToOwnDevices,
  unlockVault,
  unwrapVaultPin,
  vaultLocked,
  wrapVaultWithPin,
} from "./client";

type Screen = "auth" | "app";
type Tab = "chats" | "contacts";
type Modal = null | "settings" | "safety" | "group" | "profile";

const EMOJI = ["👍", "❤️", "😂", "🔥", "👏", "🎉", "😮", "😢"];

export function App() {
  const [lang, setLang] = useState<Lang>((localStorage.getItem("ollo.lang") as Lang) || "ru");
  const [theme, setTheme] = useState(localStorage.getItem("ollo.theme") || "dark");
  const [acc, setAcc] = useState<Account | null>(null);
  const [screen, setScreen] = useState<Screen>("auth");
  const [ready, setReady] = useState(false);
  const [locked, setLocked] = useState(false);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("ollo.theme", theme);
  }, [theme]);
  useEffect(() => {
    localStorage.setItem("ollo.lang", lang);
  }, [lang]);

  useEffect(() => {
    if (vaultLocked()) {
      setLocked(true);
      setReady(true);
      return;
    }
    const existing = loadAccount();
    if (existing) {
      setAcc(existing);
      setScreen("app");
    }
    setReady(true);
  }, []);

  const persist = useCallback((next: Account) => {
    if (!next.outbox) next.outbox = [];
    if (!next.knownIdentities) next.knownIdentities = {};
    if (!next.senderKeys) next.senderKeys = {};
    if (!next.remoteSenderKeys) next.remoteSenderKeys = {};
    if (!next.heldSenderKeys) next.heldSenderKeys = {};
    if (!next.replay) next.replay = { ids: [] };
    if (!next.memberships) next.memberships = {};
    if (!next.pendingMemberships) next.pendingMemberships = {};
    if (!next.rejectedMemberships) next.rejectedMemberships = {};
    if (!next.droppedDevices) next.droppedDevices = [];
    if (!next.senderKeyShared) next.senderKeyShared = {};
    saveAccount(next);
    setAcc({ ...next, sessions: next.sessions, messages: { ...next.messages }, threads: [...next.threads] });
  }, []);

  if (!ready) return null;
  if (locked) {
    return (
      <Unlock
        lang={lang}
        onUnlock={() => {
          const existing = loadAccount();
          if (existing) {
            setAcc(existing);
            setScreen("app");
            setLocked(false);
          }
        }}
      />
    );
  }
  if (screen === "auth" || !acc) {
    return (
      <Auth
        lang={lang}
        setLang={setLang}
        onReady={(a) => {
          persist(a);
          setScreen("app");
        }}
      />
    );
  }
  return (
    <Shell
      acc={acc}
      persist={persist}
      lang={lang}
      setLang={setLang}
      theme={theme}
      setTheme={setTheme}
      onLogout={() => {
        clearAccount();
        setAcc(null);
        setScreen("auth");
      }}
    />
  );
}

function Unlock({ lang, onUnlock }: { lang: Lang; onUnlock: () => void }) {
  const [pin, setPin] = useState("");
  const [err, setErr] = useState("");
  return (
    <div className="auth">
      <div className="card">
        <div className="brand">
          <div className="logo">O</div> OllO
        </div>
        <h1>OllO</h1>
        <p>{t(lang, "vaultLocked")}</p>
        <div className="field">
          <label>{t(lang, "vaultPin")}</label>
          <input type="password" value={pin} onChange={(e) => setPin(e.target.value)} minLength={8} />
        </div>
        {err && <p style={{ color: "var(--danger)" }}>{err}</p>}
        <button
          className="primary"
          onClick={() => {
            if (!unlockVault(pin)) {
              setErr(t(lang, "failed"));
              return;
            }
            onUnlock();
          }}
        >
          {t(lang, "unlock")}
        </button>
      </div>
    </div>
  );
}

function Auth({
  lang,
  setLang,
  onReady,
}: {
  lang: Lang;
  setLang: (l: Lang) => void;
  onReady: (a: Account) => void;
}) {
  const [step, setStep] = useState<1 | 2>(1);
  const [lockPin, setLockPin] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [err, setErr] = useState("");
  const [restorePass, setRestorePass] = useState("");
  const [restoreRaw, setRestoreRaw] = useState("");
  const [address, setAddress] = useState("");
  const mat = useRef(newDeviceMaterial());

  async function createAccount() {
    setErr("");
    try {
      const res = await registerWithIdentity(
        mat.current,
        navigator.userAgent.slice(0, 40),
        lockPin.trim() || undefined,
      );
      const acc: Account = {
        userId: res.user.id,
        deviceId: res.device_id,
        username: res.user.username,
        displayName: "",
        about: "",
        access: res.access_token,
        refresh: res.refresh_token,
        device: { ...mat.current, userId: res.user.id, deviceId: res.device_id },
        sessions: {},
        messages: {},
        threads: [],
        contacts: [],
        pinned: {},
        drafts: {},
        firstSent: {},
        knownIdentities: {},
        outbox: [],
        senderKeys: {},
        remoteSenderKeys: {},
        heldSenderKeys: {},
        signedPrekeyAt: Date.now(),
        replay: { ids: [] },
        memberships: {},
        pendingMemberships: {},
        rejectedMemberships: {},
        droppedDevices: [],
        senderKeyShared: {},
      };
      if (restoreRaw) {
        try {
          mergeBackupHistory(acc, restoreRaw, restorePass);
        } catch {
          /* history optional */
        }
      }
      setAddress(accountAddress(acc));
      if (res.user.is_new || !res.user.username) {
        setStep(2);
        sessionStorage.setItem("ollo.tmp", JSON.stringify({ acc: serializeTmp(acc) }));
        (window as unknown as { __acc: Account }).__acc = acc;
      } else {
        onReady(acc);
      }
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function finishProfile() {
    const acc = (window as unknown as { __acc: Account }).__acc;
    if (!acc) return;
    try {
      const res = await api("/v1/me", acc.access, {
        method: "PUT",
        body: JSON.stringify({ username, display_name: displayName }),
      });
      acc.username = res.user.username;
      acc.displayName = res.user.display_name;
      onReady(acc);
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  return (
    <div className="auth">
      <div className="card">
        <div className="brand">
          <div className="logo">O</div> OllO
        </div>
        <h1>OllO</h1>
        <p>{t(lang, "tagline")}</p>
        {step === 1 && (
          <>
            <p className="hint">{t(lang, "addressHint")}</p>
            <div className="field">
              <label>{t(lang, "lock")}</label>
              <input
                type="password"
                value={lockPin}
                onChange={(e) => setLockPin(e.target.value)}
                autoComplete="off"
                placeholder="PIN"
              />
            </div>
            <button className="primary" onClick={() => void createAccount()}>
              {t(lang, "createAccount")}
            </button>
          </>
        )}
        {step === 2 && (
          <>
            <QrCard value={address} label={t(lang, "yourAddress")} />
            <button
              className="ghost"
              onClick={() => {
                void navigator.clipboard.writeText(address);
              }}
            >
              {t(lang, "copyAddress")}
            </button>
            <div className="field">
              <label>{t(lang, "displayName")}</label>
              <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            </div>
            <div className="field">
              <label>{t(lang, "username")}</label>
              <input value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())} placeholder="ivanov" />
            </div>
            <button className="primary" onClick={() => void finishProfile()}>
              {t(lang, "continue")}
            </button>
          </>
        )}
        {step === 1 && (
          <div className="field" style={{ marginTop: 12 }}>
            <label>{t(lang, "restore")}</label>
            <input
              type="password"
              value={restorePass}
              onChange={(e) => setRestorePass(e.target.value)}
              placeholder="passphrase"
            />
            <input
              type="file"
              accept="application/json,.ollo"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (!f) return;
                void f.text().then((txt) => {
                  try {
                    mat.current = materialFromBackup(txt, restorePass);
                    setRestoreRaw(txt);
                    sessionStorage.setItem("ollo.restore", txt);
                  } catch (er) {
                    setErr((er as Error).message);
                  }
                });
              }}
            />
          </div>
        )}
        {err && <p style={{ color: "var(--danger)" }}>{err}</p>}
        <div className="hint" style={{ marginTop: 16 }}>
          <button className="ghost" onClick={() => setLang(lang === "ru" ? "en" : "ru")}>
            {lang === "ru" ? "English" : "Русский"}
          </button>
        </div>
      </div>
    </div>
  );
}

function serializeTmp(a: Account) {
  return a.userId;
}

function Shell({
  acc,
  persist,
  lang,
  setLang,
  theme,
  setTheme,
  onLogout,
}: {
  acc: Account;
  persist: (a: Account) => void;
  lang: Lang;
  setLang: (l: Lang) => void;
  theme: string;
  setTheme: (t: string) => void;
  onLogout: () => void;
}) {
  const [tab, setTab] = useState<Tab>("chats");
  const [active, setActive] = useState<string | null>(acc.threads[0]?.id ?? null);
  const [query, setQuery] = useState("");
  const [modal, setModal] = useState<Modal>(null);
  const [safety, setSafety] = useState("");
  const [typing, setTyping] = useState(false);
  const [call, setCall] = useState<null | {
    media: "audio" | "video";
    remote?: string;
    incoming?: boolean;
    callId?: string;
  }>(null);
  const [ctx, setCtx] = useState<null | { x: number; y: number; msg: ChatMessage }>(null);
  const [replyTo, setReplyTo] = useState<ChatMessage | null>(null);
  const [text, setText] = useState(acc.drafts[active ?? ""] ?? "");
  const [presence, setPresence] = useState("");
  const [searchHits, setSearchHits] = useState<ChatMessage[] | null>(null);
  const [identityWarn, setIdentityWarn] = useState("");
  const [lockPin, setLockPin] = useState("");
  const [vaultPin, setVaultPin] = useState("");
  const [vaultPinErr, setVaultPinErr] = useState("");
  const [safetyQr, setSafetyQr] = useState("");
  const [backupPass, setBackupPass] = useState("");
  const [muted, setMuted] = useState(false);
  const [camOff, setCamOff] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const localVideo = useRef<HTMLVideoElement>(null);
  const remoteVideo = useRef<HTMLVideoElement>(null);

  const thread = acc.threads.find((th) => th.id === active) ?? null;
  const messages = active ? acc.messages[active] ?? [] : [];

  useEffect(() => {
    if (!thread?.peerUserId) {
      setPresence("");
      return;
    }
    let stop = false;
    const tick = async () => {
      try {
        const p = await api(`/v1/presence/${thread.peerUserId}`, acc.access, {}, acc);
        if (!stop) setPresence(p.state === "online" ? "online" : p.last_seen_day ?? "offline");
      } catch {
        /* ignore */
      }
    };
    void tick();
    const id = setInterval(() => void tick(), 15000);
    return () => {
      stop = true;
      clearInterval(id);
    };
  }, [thread?.peerUserId, acc.access]);

  useEffect(() => {
    if (!thread?.groupId) return;
    let stop = false;
    void syncGroupMembership(acc, thread.groupId)
      .then(() => {
        if (!stop) persist(acc);
      })
      .catch(() => undefined);
    return () => {
      stop = true;
    };
  }, [thread?.groupId, acc.access]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages.length, active]);

  useEffect(() => {
    let stopped = false;
    let ws: WebSocket | null = null;
    let ping: ReturnType<typeof setInterval> | undefined;
    const connect = () => {
      if (stopped) return;
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      ws = new WebSocket(realtimeUrl(`${proto}//${location.host}`));
      ws.onopen = () => {
        ws?.send(JSON.stringify(realtimeHello(acc.access)));
        void maybeRotateSignedPrekey(acc).then(() => persist(acc)).catch(() => undefined);
        void flushOutbox(acc).then(() => persist(acc));
        void replenishPrekeys(acc).catch(() => undefined);
      };
      ws.onmessage = (ev) => {
        const frame = JSON.parse(String(ev.data));
        if (frame.op === "envelope") {
          void handleIncoming(frame.envelope);
          ws?.send(JSON.stringify({ op: "ack", ids: [frame.envelope.id] }));
        }
      };
      ws.onclose = () => {
        if (!stopped) setTimeout(connect, 1500);
      };
    };
    connect();
    ping = setInterval(() => {
      if (ws?.readyState === 1) ws.send(JSON.stringify({ op: "ping" }));
    }, 25000);
    const drain = setInterval(() => void pullMailbox(), 8000);
    void pullMailbox();
    return () => {
      stopped = true;
      clearInterval(ping);
      clearInterval(drain);
      ws?.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [acc.access]);

  async function pullMailbox() {
    try {
      const res = await api("/v1/envelopes?limit=100", acc.access);
      const ids: string[] = [];
      for (const env of res.envelopes as Array<Record<string, string>>) {
        await handleIncoming(env);
        ids.push(env.id);
      }
      if (ids.length) {
        await api("/v1/envelopes/ack", acc.access, { method: "POST", body: JSON.stringify({ ids }) });
      }
    } catch {
      /* offline */
    }
  }

  async function handleIncoming(env: Record<string, string>) {
    try {
      if (noteEnvelope(acc, env.id) === "drop") {
        persist(acc);
        return;
      }
      const inner = openEnvelope(acc, env.sender_user_id, env.sender_device_id, env.ciphertext, env.group_id);
      if (inner.type === "sender_key_distribute") {
        const ed = await resolveSenderEd25519(acc, env.sender_user_id, env.sender_device_id);
        ingestSenderKey(acc, inner, env.sender_user_id, env.sender_device_id, ed);
        persist(acc);
        return;
      }
      if (inner.type === "device_drop" && inner.deviceDrop) {
        await applyDeviceDropNotice(
          acc,
          env.sender_user_id,
          env.sender_device_id,
          inner.deviceDrop.userId,
          inner.deviceDrop.deviceId,
        );
        persist(acc);
        return;
      }
      if (inner.type === "typing") {
        if (threadPeer(env) === active || env.group_id === active) setTyping(true);
        setTimeout(() => setTyping(false), 2000);
        persist(acc);
        return;
      }
      if (inner.type === "receipt_delivery" || inner.type === "receipt_read") {
        const tid = inner.threadId;
        const list = acc.messages[tid] ?? [];
        for (const m of list) {
          if (m.clientId === inner.receipt?.targetClientId) {
            m.status = inner.type === "receipt_read" ? "read" : "delivered";
          }
        }
        persist(acc);
        return;
      }
      if (inner.type === "call_signal") {
        await onCallSignal(env.sender_user_id, inner);
        persist(acc);
        return;
      }
      if (inner.type === "reaction" && inner.reaction) {
        const list = acc.messages[inner.threadId] ?? [];
        const target = list.find((m) => m.clientId === inner.reaction!.targetClientId);
        if (target) target.reaction = inner.reaction.remove ? undefined : inner.reaction.emoji;
        persist(acc);
        return;
      }
      if (inner.type === "edit" && inner.editOf) {
        const list = acc.messages[inner.threadId] ?? [];
        const target = list.find((m) => m.clientId === inner.editOf);
        if (target) {
          target.text = inner.text;
          target.edited = true;
        }
        persist(acc);
        return;
      }
      const tid = inner.threadId || threadPeer(env);
      ensureThread(tid, env.sender_user_id, env.group_id);
      const attachments: ChatMessage["attachments"] = [];
      if (inner.attachments?.length) {
        for (const a of inner.attachments) {
          try {
            const blob = await downloadAndDecrypt(acc, {
              objectId: a.objectId,
              key: a.key,
              nonce: a.nonce,
              digest: a.digest,
              mime: a.mime,
              filename: a.filename,
              grant: a.grant,
            });
            attachments.push({
              name: a.filename,
              mime: a.mime,
              url: URL.createObjectURL(blob),
              objectId: a.objectId,
              grant: a.grant,
            });
          } catch {
            attachments.push({ name: a.filename, mime: a.mime, objectId: a.objectId, grant: a.grant });
          }
        }
      }
      const msg: ChatMessage = {
        clientId: inner.clientId,
        threadId: tid,
        fromMe: env.sender_user_id === acc.userId,
        senderUserId: env.sender_user_id,
        text: inner.text,
        sentAt: inner.sentAt,
        status: "delivered",
        replyTo: inner.replyToClientId,
        expiresAt: inner.expiresAt,
        attachments: attachments.length ? attachments : undefined,
      };
      pushMsg(tid, msg);
      if (inner.type === "delete" && inner.editOf) {
        const list = acc.messages[tid] ?? [];
        const target = list.find((m) => m.clientId === inner.editOf);
        if (target) {
          target.deleted = true;
          target.text = "";
        }
      }
      persist(acc);
      if (env.kind === "message" && env.sender_user_id !== acc.userId) {
        void deliver(
          env.sender_user_id,
          {
            version: 1,
            type: "receipt_delivery",
            clientId: crypto.randomUUID(),
            sentAt: new Date().toISOString(),
            threadId: tid,
            receipt: { targetClientId: inner.clientId, at: new Date().toISOString() },
          },
          "receipt",
        );
      }
    } catch (e) {
      console.error("decrypt failed", e);
    }
  }

  function threadPeer(env: Record<string, string>) {
    return env.group_id || (env.sender_user_id === acc.userId ? env.recipient_user_id : env.sender_user_id);
  }

  function ensureThread(id: string, peer?: string, groupId?: string | null) {
    if (acc.threads.some((th) => th.id === id)) return;
    acc.threads.unshift({
      id,
      kind: groupId ? "group" : "direct",
      title: peer?.slice(0, 8) ?? "chat",
      peerUserId: groupId ? undefined : peer,
      groupId: groupId ?? undefined,
      last: "",
      unread: 0,
      disappearingSeconds: 0,
    });
  }

  function pushMsg(tid: string, msg: ChatMessage) {
    const list = acc.messages[tid] ?? [];
    if (list.some((m) => m.clientId === msg.clientId)) return;
    list.push(msg);
    acc.messages[tid] = list;
    const th = acc.threads.find((x) => x.id === tid);
    if (th) {
      th.last = msg.text ?? (msg.attachments ? "📎" : "");
      th.lastAt = msg.sentAt;
    }
  }

  async function deliver(
    peerUserId: string,
    inner: InnerMessage,
    kind: "message" | "receipt" | "typing" | "call" | "control" = "message",
    groupId?: string,
  ) {
    try {
      if (groupId) {
        await sendToGroup(acc, groupId, inner, kind);
      } else {
        await sendToUser(acc, peerUserId, inner, kind);
        if (peerUserId !== acc.userId) {
          await syncToOwnDevices(acc, inner, kind);
        }
      }
      persist(acc);
    } catch (e) {
      if ((e as Error).message === "identity_changed") {
        setIdentityWarn(peerUserId);
      }
      acc.outbox.push({
        id: crypto.randomUUID(),
        peerUserId,
        groupId,
        kind,
        inner,
        attempts: 0,
      });
      persist(acc);
      throw e;
    }
  }

  async function onCallSignal(from: string, inner: InnerMessage) {
    const sig = inner.call;
    if (!sig) return;
    if (sig.signalType === "offer") {
      setCall({ media: sig.media, incoming: true, remote: from, callId: sig.callId });
      (window as unknown as { __offer: string; __from: string; __sframe?: Uint8Array }).__offer = sig.sdp ?? "";
      (window as unknown as { __from: string }).__from = from;
      if (sig.sframeKey) (window as unknown as { __sframe: Uint8Array }).__sframe = sig.sframeKey;
      return;
    }
    const pc = pcRef.current;
    if (!pc) return;
    if (sig.signalType === "answer" && sig.sdp) {
      await pc.setRemoteDescription({ type: "answer", sdp: sig.sdp });
    }
    if (sig.signalType === "ice" && sig.ice) {
      try {
        await pc.addIceCandidate(sig.ice);
      } catch {
        /* ignore */
      }
    }
    if (sig.signalType === "hangup" || sig.signalType === "reject") {
      pc.close();
      pcRef.current = null;
      setCall(null);
    }
  }

  async function sendText() {
    if (!thread || !text.trim()) return;
    const ttl = thread.disappearingSeconds;
    const inner: InnerMessage = {
      version: 1,
      type: replyTo ? "reply" : "text",
      clientId: crypto.randomUUID(),
      sentAt: new Date().toISOString(),
      threadId: thread.id,
      text: text.trim(),
      replyToClientId: replyTo?.clientId,
      ttlSeconds: ttl || undefined,
      expiresAt: ttl ? new Date(Date.now() + ttl * 1000).toISOString() : undefined,
    };
    const local: ChatMessage = {
      clientId: inner.clientId,
      threadId: thread.id,
      fromMe: true,
      senderUserId: acc.userId,
      text: inner.text,
      sentAt: inner.sentAt,
      status: "pending",
      replyTo: inner.replyToClientId,
      expiresAt: inner.expiresAt,
    };
    pushMsg(thread.id, local);
    setText("");
    setReplyTo(null);
    acc.drafts[thread.id] = "";
    persist(acc);
    try {
      if (thread.kind === "direct" && thread.peerUserId) {
        await deliver(thread.peerUserId, inner);
      } else if (thread.groupId) {
        await deliver(acc.userId, inner, "message", thread.groupId);
      }
      local.status = "sent";
      persist(acc);
    } catch {
      local.status = "failed";
      persist(acc);
    }
  }

  async function searchUser() {
    if (!query.trim()) return;
    try {
      const q = query.trim();
      const body = parseUserUri(q) ? { address: q } : { username: q };
      const res = await api("/v1/users/search", acc.access, {
        method: "POST",
        body: JSON.stringify(body),
      }, acc);
      const u = res.users?.[0];
      if (!u) return;
      await api("/v1/contacts", acc.access, { method: "POST", body: JSON.stringify({ user_id: u.id }) });
      ensureThread(u.id, u.id);
      const th = acc.threads.find((x) => x.id === u.id);
      if (th) th.title = u.display_name || u.username || u.id.slice(0, 8);
      if (!acc.contacts.some((c) => c.id === u.id)) acc.contacts.push(u);
      persist(acc);
      setActive(u.id);
      setQuery("");
    } catch (e) {
      alert((e as Error).message);
    }
  }

  async function startSafety() {
    if (!thread?.peerUserId) return;
    const mat = await api(`/v1/safety/${thread.peerUserId}`, acc.access, {}, acc);
    const first = mat.devices?.[0];
    if (!first) return;
    const bytes = b64u(first.identity_x25519);
    const sn = computeSafety(acc, bytes);
    setSafety(sn.grouped);
    setSafetyQr(sn.qr);
    setModal("safety");
  }

  async function onAttach(file: File) {
    if (!thread?.peerUserId && !thread?.groupId) return;
    const enc = await encryptFile(file);
    const created = await api("/v1/attachments", acc.access, {
      method: "POST",
      body: JSON.stringify({ size: enc.ciphertext.length }),
    });
    await fetch(`/v1/attachments/${created.object_id}/data`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${acc.access}`, "Content-Type": "application/octet-stream" },
      body: new Blob([new Uint8Array(enc.ciphertext)]),
    });
    const grant = thread.groupId
      ? await api(`/v1/attachments/${created.object_id}/grants`, acc.access, {
          method: "POST",
          body: JSON.stringify({ group_id: thread.groupId }),
        }, acc)
      : thread.peerUserId
        ? await api(`/v1/attachments/${created.object_id}/grants`, acc.access, {
            method: "POST",
            body: JSON.stringify({ recipient_user_id: thread.peerUserId }),
          }, acc)
        : { grant: "" };
    const url = URL.createObjectURL(new Blob([new Uint8Array(enc.ciphertext)]));
    const inner: InnerMessage = {
      version: 1,
      type: file.type.startsWith("audio") ? "voice" : "attachment",
      clientId: crypto.randomUUID(),
      sentAt: new Date().toISOString(),
      threadId: thread.id,
      attachments: [
        {
          objectId: created.object_id,
          key: enc.key,
          nonce: enc.nonce,
          digest: enc.digest,
          size: enc.size,
          mime: enc.mime,
          filename: enc.filename,
          grant: grant.grant,
        },
      ],
    };
    const local: ChatMessage = {
      clientId: inner.clientId,
      threadId: thread.id,
      fromMe: true,
      senderUserId: acc.userId,
      sentAt: inner.sentAt,
      status: "sent",
      attachments: [{ name: file.name, mime: file.type, url: file.type.startsWith("image/") ? URL.createObjectURL(file) : url, objectId: created.object_id }],
    };
    pushMsg(thread.id, local);
    persist(acc);
    if (thread.peerUserId) await deliver(thread.peerUserId, inner);
    else if (thread.groupId) await deliver(acc.userId, inner, "message", thread.groupId);
  }

  async function recordVoice() {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const rec = new MediaRecorder(stream);
    const chunks: Blob[] = [];
    rec.ondataavailable = (e) => chunks.push(e.data);
    rec.onstop = () => {
      stream.getTracks().forEach((tr) => tr.stop());
      const blob = new Blob(chunks, { type: rec.mimeType || "audio/webm" });
      const file = new File([blob], "voice.webm", { type: blob.type });
      void onAttach(file);
    };
    rec.start();
    setTimeout(() => rec.state === "recording" && rec.stop(), 4000);
  }

  function attachPcHandlers(pc: RTCPeerConnection, peerUserId: string, callId: string, media: "audio" | "video") {
    pc.onicecandidate = (e) => {
      if (!e.candidate) return;
      void deliver(
        peerUserId,
        {
          version: 1,
          type: "call_signal",
          clientId: crypto.randomUUID(),
          sentAt: new Date().toISOString(),
          threadId: thread?.id ?? peerUserId,
          call: {
            callId,
            media,
            signalType: "ice",
            ice: {
              candidate: e.candidate.candidate,
              sdpMid: e.candidate.sdpMid ?? undefined,
              sdpMLineIndex: e.candidate.sdpMLineIndex ?? undefined,
            },
          },
        },
        "call",
        thread?.groupId,
      );
    };
    pc.ontrack = (ev) => {
      if (remoteVideo.current) remoteVideo.current.srcObject = ev.streams[0]!;
    };
  }

  async function startCall(media: "audio" | "video") {
    if (!thread?.peerUserId && !thread?.groupId) return;
    const created = await api(
      "/v1/calls",
      acc.access,
      {
        method: "POST",
        body: JSON.stringify({
          media,
          participant_user_ids: thread.peerUserId ? [thread.peerUserId] : [],
          group_id: thread.groupId,
        }),
      },
      acc,
    );
    const pc = new RTCPeerConnection({ iceServers: created.ice_servers });
    pcRef.current = pc;
    const local = await navigator.mediaDevices.getUserMedia({ audio: true, video: media === "video" });
    local.getTracks().forEach((tr) => pc.addTrack(tr, local));
    if (localVideo.current) localVideo.current.srcObject = local;
    const peer = thread.peerUserId ?? acc.userId;
    attachPcHandlers(pc, peer, created.call_id, media);
    const sframeKey = crypto.getRandomValues(new Uint8Array(32));
    (window as unknown as { __sframe: Uint8Array }).__sframe = sframeKey;
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await deliver(
      peer,
      {
        version: 1,
        type: "call_signal",
        clientId: crypto.randomUUID(),
        sentAt: new Date().toISOString(),
        threadId: thread.id,
        call: { callId: created.call_id, media, signalType: "offer", sdp: offer.sdp, sframeKey },
      },
      "call",
      thread.groupId,
    );
    setCall({ media, callId: created.call_id, remote: peer });
  }

  async function acceptIncoming() {
    if (!call?.remote) return;
    const offerSdp = (window as unknown as { __offer?: string }).__offer ?? "";
    const callId = call.callId ?? "";
    const joined = await api(`/v1/calls/${callId}/join`, acc.access, { method: "POST", body: "{}" }, acc);
    const pc = new RTCPeerConnection({ iceServers: joined.ice_servers });
    pcRef.current = pc;
    const local = await navigator.mediaDevices.getUserMedia({ audio: true, video: call.media === "video" });
    local.getTracks().forEach((tr) => pc.addTrack(tr, local));
    if (localVideo.current) localVideo.current.srcObject = local;
    attachPcHandlers(pc, call.remote, callId, call.media);
    if (offerSdp) await pc.setRemoteDescription({ type: "offer", sdp: offerSdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await deliver(
      call.remote,
      {
        version: 1,
        type: "call_signal",
        clientId: crypto.randomUUID(),
        sentAt: new Date().toISOString(),
        threadId: thread?.id ?? call.remote,
        call: { callId, media: call.media, signalType: "answer", sdp: answer.sdp },
      },
      "call",
      thread?.groupId,
    );
    setCall({ ...call, incoming: false });
  }

  async function hangupCall() {
    const remote = call?.remote ?? thread?.peerUserId;
    const callId = call?.callId;
    if (remote && callId) {
      void deliver(
        remote,
        {
          version: 1,
          type: "call_signal",
          clientId: crypto.randomUUID(),
          sentAt: new Date().toISOString(),
          threadId: thread?.id ?? remote,
          call: { callId, media: call?.media ?? "audio", signalType: "hangup" },
        },
        "call",
        thread?.groupId,
      );
      void api(`/v1/calls/${callId}/end`, acc.access, { method: "POST", body: "{}" }, acc);
    }
    pcRef.current?.getSenders().forEach((s) => s.track?.stop());
    pcRef.current?.close();
    pcRef.current = null;
    setCall(null);
    setMuted(false);
    setCamOff(false);
  }

  function toggleMute() {
    const next = !muted;
    setMuted(next);
    pcRef.current?.getSenders().forEach((s) => {
      if (s.track?.kind === "audio") s.track.enabled = !next;
    });
  }

  function toggleCamera() {
    const next = !camOff;
    setCamOff(next);
    pcRef.current?.getSenders().forEach((s) => {
      if (s.track?.kind === "video") s.track.enabled = !next;
    });
  }

  async function shareScreen() {
    const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
    const track = stream.getVideoTracks()[0];
    if (!track || !pcRef.current) return;
    const sender = pcRef.current.getSenders().find((s) => s.track?.kind === "video");
    if (sender) await sender.replaceTrack(track);
    track.onended = () => {
      const cam = (localVideo.current?.srcObject as MediaStream | null)?.getVideoTracks()[0];
      if (cam && sender) void sender.replaceTrack(cam);
    };
  }

  async function confirmGroupMembership(groupId: string) {
    const result = confirmPendingMembership(acc, groupId);
    if (!result) return;
    if (result.added.length) {
      await distributeOwnSenderKey(acc, groupId, result.applied.epoch, result.added);
    }
    persist(acc);
  }

  async function createGroup(name: string, ids: string[]) {
    const created = await createSignedGroup(acc, ids);
    acc.threads.unshift({
      id: created.id,
      kind: "group",
      title: name || "Group",
      groupId: created.id,
      last: "",
      unread: 0,
      disappearingSeconds: 0,
    });
    await distributeOwnSenderKey(acc, created.id, created.epoch, created.memberIds);
    persist(acc);
    setActive(created.id);
    setModal(null);
  }

  const visibleThreads = useMemo(
    () => acc.threads.filter((th) => !th.archived && (tab === "chats" || th.kind === "direct")),
    [acc.threads, tab],
  );

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="logo">O</div>
          OllO
          <span className="hint" style={{ fontWeight: 500 }}>
            {acc.username ? `@${acc.username}` : acc.userId.slice(0, 8)}
          </span>
        </div>
        <div className="top-actions">
          <button className="ghost" onClick={() => setModal("group")}>
            {t(lang, "group")}
          </button>
          <button className="ghost" onClick={() => setModal("settings")}>
            {t(lang, "settings")}
          </button>
        </div>
      </header>
      <div className="shell">
        <aside className="sidebar">
          <div className="side-head">
            <input
              className="search"
              placeholder={t(lang, "search")}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                if (e.target.value.startsWith("/")) setSearchHits(searchLocal(acc, e.target.value.slice(1)));
                else setSearchHits(null);
              }}
              onKeyDown={(e) => e.key === "Enter" && !query.startsWith("/") && void searchUser()}
            />
            <div className="tabs">
              <button className={`tab ${tab === "chats" ? "active" : ""}`} onClick={() => setTab("chats")}>
                {t(lang, "chats")}
              </button>
              <button className={`tab ${tab === "contacts" ? "active" : ""}`} onClick={() => setTab("contacts")}>
                {t(lang, "contacts")}
              </button>
            </div>
          </div>
          <div className="chat-list">
            {searchHits && (
              <div className="hint" style={{ padding: "8px 14px" }}>
                {searchHits.map((m) => (
                  <div
                    key={m.clientId}
                    className="chat-item"
                    onClick={() => {
                      setActive(m.threadId);
                      setSearchHits(null);
                      setQuery("");
                    }}
                  >
                    <div className="meta">
                      <div className="title">{m.text}</div>
                      <div className="preview">{new Date(m.sentAt).toLocaleString()}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {tab === "contacts"
              ? acc.contacts.map((c) => (
                  <div
                    key={c.id}
                    className="chat-item"
                    onClick={() => {
                      ensureThread(c.id, c.id);
                      const th = acc.threads.find((x) => x.id === c.id);
                      if (th) th.title = c.display_name || c.username || c.id.slice(0, 8);
                      persist(acc);
                      setActive(c.id);
                    }}
                  >
                    <div className="avatar">{(c.display_name || c.username || "?").slice(0, 1).toUpperCase()}</div>
                    <div className="meta">
                      <div className="title">{c.display_name || c.username}</div>
                      <div className="preview">@{c.username}</div>
                    </div>
                  </div>
                ))
              : visibleThreads.map((th) => (
                  <div
                    key={th.id}
                    className={`chat-item ${active === th.id ? "active" : ""}`}
                    onClick={() => {
                      setActive(th.id);
                      setText(acc.drafts[th.id] ?? "");
                    }}
                  >
                    <div className={`avatar ${th.kind === "group" ? "g" : ""}`}>
                      {th.title.slice(0, 1).toUpperCase()}
                    </div>
                    <div className="meta">
                      <div className="title">{th.title}</div>
                      <div className="preview">{th.last}</div>
                    </div>
                    <div className="when">{th.lastAt ? new Date(th.lastAt).toLocaleTimeString().slice(0, 5) : ""}</div>
                  </div>
                ))}
          </div>
        </aside>
        <section className="main">
          {!thread ? (
            <div className="empty">
              <div className="logo" style={{ width: 56, height: 56, borderRadius: 18, fontSize: 24 }}>
                O
              </div>
              <h2>{t(lang, "emptyTitle")}</h2>
              <p>{t(lang, "emptyBody")}</p>
            </div>
          ) : (
            <>
              <div className="chat-head">
                <div>
                  <div className="title">{thread.title}</div>
                  <div className="hint">
                    {presence === "online" ? t(lang, "online") : presence || t(lang, "noPlaintext")}
                  </div>
                </div>
                <div className="top-actions">
                  <button className="ghost" onClick={() => void startCall("audio")}>
                    {t(lang, "call")}
                  </button>
                  <button className="ghost" onClick={() => void startCall("video")}>
                    {t(lang, "video")}
                  </button>
                  <button className="ghost" onClick={() => void startSafety()}>
                    {t(lang, "safety")}
                  </button>
                  <button
                    className="ghost"
                    onClick={() => {
                      thread.disappearingSeconds = thread.disappearingSeconds ? 0 : 30;
                      persist(acc);
                    }}
                  >
                    {t(lang, "disappearing")}
                    {thread.disappearingSeconds ? ` ${thread.disappearingSeconds}s` : ""}
                  </button>
                  {thread.peerUserId && (
                    <button
                      className="ghost"
                      onClick={() => {
                        void api("/v1/blocks", acc.access, {
                          method: "POST",
                          body: JSON.stringify({ user_id: thread.peerUserId }),
                        }, acc).then(() => {
                          thread.archived = true;
                          persist(acc);
                          setActive(null);
                        });
                      }}
                    >
                      {t(lang, "block")}
                    </button>
                  )}
                  <button
                    className="ghost"
                    onClick={() => {
                      const next = !thread.muted;
                      void api("/v1/threads/mute", acc.access, {
                        method: "POST",
                        body: JSON.stringify({ thread_id: thread.id, until: next ? null : null }),
                      }, acc).then(() => {
                        thread.muted = next;
                        persist(acc);
                      });
                    }}
                  >
                    {t(lang, "muteChat")}
                  </button>
                  <button
                    className="ghost"
                    onClick={() => {
                      const next = !thread.archived;
                      void api("/v1/threads/archive", acc.access, {
                        method: "POST",
                        body: JSON.stringify({ thread_id: thread.id, archived: next }),
                      }, acc).then(() => {
                        thread.archived = next;
                        persist(acc);
                        if (next) setActive(null);
                      });
                    }}
                  >
                    {t(lang, "archiveThread")}
                  </button>
                  {thread.peerUserId && (
                    <button
                      className="ghost"
                      onClick={() => {
                        void api("/v1/reports", acc.access, {
                          method: "POST",
                          body: JSON.stringify({ user_id: thread.peerUserId, reason: "other" }),
                        }, acc);
                      }}
                    >
                      {t(lang, "report")}
                    </button>
                  )}
                </div>
              </div>
              {thread.groupId && acc.pendingMemberships?.[thread.groupId] && (
                <div className="hint" style={{ padding: "8px 16px", color: "var(--danger)" }}>
                  {t(lang, "membershipConfirm")}{" "}
                  {(() => {
                    const view = pendingMembershipNotice(acc, thread.groupId!);
                    if (!view) return null;
                    const extra = view.added.map((id) => id.slice(0, 8)).join(", ");
                    return (
                      <>
                        {extra ? <span>({extra})</span> : null}
                        {view.signerNotice === "own-other-device" ? (
                          <div>{t(lang, "membershipOtherDevice")}</div>
                        ) : null}
                      </>
                    );
                  })()}{" "}
                  <button className="primary" onClick={() => void confirmGroupMembership(thread.groupId!)}>
                    {t(lang, "accept")}
                  </button>{" "}
                  <button
                    className="ghost"
                    onClick={() => {
                      const hostile = rejectPendingMembership(acc, thread.groupId!);
                      persist(acc);
                      if (hostile) void rotateSenderKeysAfterDeviceDrop(acc).finally(() => persist(acc));
                    }}
                  >
                    {t(lang, "decline")}
                  </button>
                </div>
              )}
              <div className="messages">
                {messages
                  .filter((m) => !m.expiresAt || new Date(m.expiresAt).getTime() > Date.now())
                  .map((m) => (
                    <div
                      key={m.clientId}
                      className={`row ${m.fromMe ? "me" : "them"}`}
                      onContextMenu={(e) => {
                        e.preventDefault();
                        setCtx({ x: e.clientX, y: e.clientY, msg: m });
                      }}
                    >
                      <div className="bubble">
                        {m.replyTo && (
                          <div className="reply-chip">
                            {messages.find((x) => x.clientId === m.replyTo)?.text ?? "…"}
                          </div>
                        )}
                        {m.attachments?.map((a) =>
                          a.mime.startsWith("image/") && a.url ? (
                            <img key={a.objectId} className="attach" src={a.url} alt="" />
                          ) : a.mime.startsWith("audio/") && a.url ? (
                            <audio key={a.objectId} controls src={a.url} />
                          ) : (
                            <div key={a.objectId} className="file-chip">
                              📄 {a.name}
                            </div>
                          ),
                        )}
                        {m.deleted ? <i className="hint">{t(lang, "del")}</i> : <div className="msg-text">{m.text}</div>}
                        <div className="msg-meta">
                          {m.edited && "✎ "}
                          {new Date(m.sentAt).toLocaleTimeString().slice(0, 5)}
                          {m.fromMe && (
                            <span className={`ticks ${m.status === "read" ? "read" : ""}`}>
                              {m.status === "pending" ? "…" : m.status === "failed" ? "!" : m.status === "read" ? "✓✓" : "✓"}
                            </span>
                          )}
                        </div>
                        {m.reaction && (
                          <div className="reactions">
                            <span className="rx">{m.reaction}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                <div ref={bottomRef} />
              </div>
              {typing && <div className="typing">● ● ●</div>}
              {replyTo && (
                <div className="hint" style={{ padding: "0 16px" }}>
                  ↪ {replyTo.text}{" "}
                  <button className="ghost" onClick={() => setReplyTo(null)}>
                    ×
                  </button>
                </div>
              )}
              <div className="composer">
                <button className="icon-btn" onClick={() => fileRef.current?.click()}>
                  📎
                </button>
                <button className="icon-btn" onClick={() => void recordVoice()}>
                  🎙
                </button>
                <input
                  ref={fileRef}
                  className="hidden"
                  type="file"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) void onAttach(f);
                    e.target.value = "";
                  }}
                />
                <textarea
                  rows={1}
                  placeholder={t(lang, "message")}
                  value={text}
                  onChange={(e) => {
                    setText(e.target.value);
                    if (active) acc.drafts[active] = e.target.value;
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      void sendText();
                    }
                  }}
                />
                <button className="primary" onClick={() => void sendText()}>
                  {t(lang, "send")}
                </button>
              </div>
            </>
          )}
        </section>
      </div>

      {ctx && (
        <div className="ctx" style={{ left: ctx.x, top: ctx.y }} onMouseLeave={() => setCtx(null)}>
          <button onClick={() => { setReplyTo(ctx.msg); setCtx(null); }}>{t(lang, "reply")}</button>
          {EMOJI.map((e) => (
            <button
              key={e}
              onClick={() => {
                ctx.msg.reaction = e;
                persist(acc);
                setCtx(null);
                if (thread?.groupId) {
                  void deliver(acc.userId, {
                    version: 1,
                    type: "reaction",
                    clientId: crypto.randomUUID(),
                    sentAt: new Date().toISOString(),
                    threadId: ctx.msg.threadId,
                    reaction: { targetClientId: ctx.msg.clientId, emoji: e },
                  }, "control", thread.groupId);
                } else if (thread?.peerUserId) {
                  void deliver(thread.peerUserId, {
                    version: 1,
                    type: "reaction",
                    clientId: crypto.randomUUID(),
                    sentAt: new Date().toISOString(),
                    threadId: ctx.msg.threadId,
                    reaction: { targetClientId: ctx.msg.clientId, emoji: e },
                  }, "control");
                }
              }}
            >
              {e}
            </button>
          ))}
          <button
            onClick={() => {
              ctx.msg.deleted = true;
              ctx.msg.text = "";
              persist(acc);
              setCtx(null);
              if (thread?.groupId) {
                void deliver(acc.userId, {
                  version: 1,
                  type: "delete",
                  clientId: crypto.randomUUID(),
                  sentAt: new Date().toISOString(),
                  threadId: ctx.msg.threadId,
                  editOf: ctx.msg.clientId,
                  deleteFor: "everyone",
                }, "control", thread.groupId);
              } else if (thread?.peerUserId) {
                void deliver(thread.peerUserId, {
                  version: 1,
                  type: "delete",
                  clientId: crypto.randomUUID(),
                  sentAt: new Date().toISOString(),
                  threadId: ctx.msg.threadId,
                  editOf: ctx.msg.clientId,
                  deleteFor: "everyone",
                }, "control");
              }
            }}
          >
            {t(lang, "del")}
          </button>
        </div>
      )}

      {modal === "settings" && (
        <div className="modal-back" onClick={() => setModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>{t(lang, "settings")}</h3>
            <QrCard value={accountAddress(acc)} label={t(lang, "yourAddress")} />
            <div className="list-row">
              <button
                className="ghost"
                onClick={() => {
                  void navigator.clipboard.writeText(accountAddress(acc));
                }}
              >
                {t(lang, "copyAddress")}
              </button>
            </div>
            <div className="list-row">
              <span>{t(lang, "theme")}</span>
              <button className="ghost" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
                {theme}
              </button>
            </div>
            <div className="list-row">
              <span>{t(lang, "lang")}</span>
              <button className="ghost" onClick={() => setLang(lang === "ru" ? "en" : "ru")}>
                {lang}
              </button>
            </div>
            <Devices acc={acc} lang={lang} />
            <div className="list-row">
              <span>{t(lang, "vaultPin")}</span>
              <input
                type="password"
                value={vaultPin}
                onChange={(e) => setVaultPin(e.target.value)}
                placeholder="min 8"
                style={{ width: 90 }}
              />
              <button
                className="ghost"
                onClick={() => {
                  setVaultPinErr("");
                  try {
                    wrapVaultWithPin(vaultPin);
                    setVaultPin("");
                  } catch (e) {
                    setVaultPinErr((e as Error).message);
                  }
                }}
              >
                {t(lang, "setVaultPin")}
              </button>
              <button
                className="ghost"
                onClick={() => {
                  unwrapVaultPin();
                  setVaultPin("");
                }}
              >
                {t(lang, "clearVaultPin")}
              </button>
            </div>
            {vaultPinErr && <p style={{ color: "var(--danger)" }}>{vaultPinErr}</p>}
            <div className="list-row">
              <span>{t(lang, "lock")}</span>
              <input
                value={lockPin}
                onChange={(e) => setLockPin(e.target.value)}
                placeholder="PIN"
                style={{ width: 90 }}
              />
              <button
                className="ghost"
                onClick={() => {
                  void api(
                    "/v1/auth/registration-lock",
                    acc.access,
                    { method: "POST", body: JSON.stringify({ pin: lockPin || null }) },
                    acc,
                  );
                  setLockPin("");
                }}
              >
                OK
              </button>
            </div>
            <div className="list-row">
              <span>{t(lang, "about")}</span>
              <span>@{acc.username}</span>
            </div>
            <div className="list-row">
              <button
                className="danger"
                onClick={() => {
                  void api("/v1/auth/logout", acc.access, { method: "POST" });
                  onLogout();
                }}
              >
                {t(lang, "logout")}
              </button>
              <button
                className="danger"
                onClick={() => {
                  if (!confirm(t(lang, "deleteAccount"))) return;
                  void api("/v1/me/delete", acc.access, { method: "POST", body: "{}" }, acc).finally(() => {
                    onLogout();
                  });
                }}
              >
                {t(lang, "deleteAccount")}
              </button>
            </div>
          </div>
        </div>
      )}

      {modal === "safety" && (
        <div className="modal-back" onClick={() => setModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>{t(lang, "safety")}</h3>
            <p>{t(lang, "verifySafety")}</p>
            <div className="safety">{safety}</div>
            <div className="hint" style={{ marginTop: 10, wordBreak: "break-all" }}>
              {safetyQr}
            </div>
          </div>
        </div>
      )}

      {identityWarn && (
        <div className="modal-back" onClick={() => setIdentityWarn("")}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>{t(lang, "safety")}</h3>
            <p>{t(lang, "verifySafety")}</p>
            <p style={{ color: "var(--danger)" }}>Identity key changed for this contact. Re-verify the safety number.</p>
            <button className="primary" onClick={() => setIdentityWarn("")}>
              OK
            </button>
          </div>
        </div>
      )}

      {modal === "group" && (
        <GroupModal
          lang={lang}
          contacts={acc.contacts}
          onClose={() => setModal(null)}
          onCreate={(name, ids) => void createGroup(name, ids)}
        />
      )}

      {call && (
        <div className="call-overlay">
          <div className="title">{call.incoming ? t(lang, "incoming") : t(lang, call.media === "video" ? "video" : "call")}</div>
          <video ref={localVideo} autoPlay muted playsInline />
          <video ref={remoteVideo} autoPlay playsInline />
          <div className="call-actions">
            {call.incoming && (
              <button className="primary" onClick={() => void acceptIncoming()}>
                {t(lang, "accept")}
              </button>
            )}
            <button className="ghost" onClick={() => toggleMute()}>
              {t(lang, "mute")}
              {muted ? " off" : ""}
            </button>
            <button className="ghost" onClick={() => toggleCamera()}>
              {t(lang, "camera")}
              {camOff ? " off" : ""}
            </button>
            <button className="ghost" onClick={() => void shareScreen()}>
              {t(lang, "screenshare")}
            </button>
            <button className="danger" onClick={() => void hangupCall()}>
              {t(lang, "hangup")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Devices({ acc, lang }: { acc: Account; lang: Lang }) {
  const [rows, setRows] = useState<Array<Record<string, string | boolean>>>([]);
  const [rosterHash, setRosterHash] = useState("");
  const [rosterWarn, setRosterWarn] = useState(false);
  useEffect(() => {
    void api("/v1/devices", acc.access).then((r) => {
      const devices = (r.devices ?? []) as Array<Record<string, string | boolean>>;
      setRows(devices);
      pruneSessionsForUser(
        acc,
        acc.userId,
        devices.map((d) => String(d.id)),
      );
      const next = String(r.roster_hash ?? "");
      setRosterHash(next);
      if (acc.ownRosterHash && next && next !== acc.ownRosterHash) {
        setRosterWarn(true);
      } else if (next) {
        acc.ownRosterHash = next;
      }
      saveAccount(acc);
    });
  }, [acc.access]);
  return (
    <div>
      <h4>{t(lang, "devices")}</h4>
      {rosterHash && <div className="hint" style={{ wordBreak: "break-all" }}>{rosterHash}</div>}
      {rosterWarn && (
        <p style={{ color: "var(--danger)" }}>
          {lang === "ru" ? "Список устройств изменился. Проверьте лишние сессии." : "Device list changed. Review extra sessions."}
        </p>
      )}
      {rows.map((d) => (
        <div className="list-row" key={String(d.id)}>
          <div>
            {String(d.name)} {d.this_device ? `(${t(lang, "thisDevice")})` : ""}
          </div>
          {!d.this_device && (
            <button
              className="ghost"
              onClick={() => {
                void api(`/v1/devices/${d.id}`, acc.access, { method: "DELETE" }).then(() => {
                  dropDeviceSessions(acc, acc.userId, String(d.id));
                  saveAccount(acc);
                  setRows(rows.filter((x) => x.id !== d.id));
                  void rotateSenderKeysAfterDeviceDrop(acc)
                    .then(() => announceDeviceDrop(acc, acc.userId, String(d.id)))
                    .finally(() => saveAccount(acc));
                });
              }}
            >
              {t(lang, "revoke")}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

function GroupModal({
  lang,
  contacts,
  onClose,
  onCreate,
}: {
  lang: Lang;
  contacts: Account["contacts"];
  onClose: () => void;
  onCreate: (name: string, ids: string[]) => void;
}) {
  const [name, setName] = useState("");
  const [ids, setIds] = useState<string[]>([]);
  return (
    <div className="modal-back" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>{t(lang, "createGroup")}</h3>
        <div className="field">
          <label>{t(lang, "displayName")}</label>
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        {contacts.map((c) => (
          <label key={c.id} className="list-row">
            <span>{c.display_name || c.username}</span>
            <input
              type="checkbox"
              checked={ids.includes(c.id)}
              onChange={(e) => setIds(e.target.checked ? [...ids, c.id] : ids.filter((x) => x !== c.id))}
            />
          </label>
        ))}
        <button className="primary" onClick={() => onCreate(name, ids)}>
          {t(lang, "continue")}
        </button>
      </div>
    </div>
  );
}
