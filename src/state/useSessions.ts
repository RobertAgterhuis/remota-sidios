import { useCallback, useRef, useState } from "react";
import { ApiError, type Protocol, request, treeApi } from "../lib/api";

/** What the server answers when a session may start (SidiOS contracts/remota-api.md). */
export interface SessionStart {
  sessionId: string;
  /** Path with the single-use ticket, valid for 60 seconds. */
  websocket: string;
  protocol: Protocol;
  /** RDP only: a throwaway login for this one session, never the target's credential. */
  rdpSessionLogin?: { username: string; password: string };
  /** RDP only: whether the administrator allows the clipboard. */
  clipboard?: boolean;
}

/** An RDP certificate the user must decide on before the session can start. */
export interface CertificateDecision {
  kind: "unknown" | "changed";
  fingerprint: string;
}

export interface SessionTab {
  id: string;
  connId: string;
  title: string;
  protocol: Protocol;
  start?: SessionStart;
  /** Incremented on reconnect to remount the renderer with a new ticket. */
  epoch: number;
  dead?: boolean;
  error?: string;
  /** The connection has no credential: ask for one for this session. */
  needsPassword?: boolean;
  certificate?: CertificateDecision;
  /** A one-time password kept while the user decides on a certificate. */
  pendingSecret?: OneTimeSecret;
}

export interface OpenOpts {
  connId: string;
  title: string;
  protocol: Protocol;
}

export interface OneTimeSecret {
  password: string;
  save: boolean;
}

/** Asks the server for a session: it resolves inheritance and policy and issues the ticket. */
export async function startSession(
  connId: string,
  secret?: OneTimeSecret,
): Promise<SessionStart> {
  return request<SessionStart>("POST", "/api/sessions", {
    connectionId: connId,
    ...(secret
      ? { oneTimeSecret: secret.password, saveSecret: secret.save }
      : {}),
  });
}

/** The WebSocket URL for a start answer, on this page's own origin. */
export function socketUrl(start: SessionStart): string {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}${start.websocket}`;
}

export function certificateDecision(
  e: unknown,
): CertificateDecision | undefined {
  if (!(e instanceof ApiError) || !e.fingerprint) return undefined;
  if (e.code === "certificate_unknown")
    return { kind: "unknown", fingerprint: e.fingerprint };
  if (e.code === "certificate_changed")
    return { kind: "changed", fingerprint: e.fingerprint };
  return undefined;
}

export function useSessions() {
  const [tabs, setTabs] = useState<SessionTab[]>([]);
  const tabsRef = useRef<SessionTab[]>([]);
  tabsRef.current = tabs;

  const update = (id: string, patch: Partial<SessionTab>) =>
    setTabs((list) =>
      list.map((tab) => (tab.id === id ? { ...tab, ...patch } : tab)),
    );

  const begin = useCallback(
    async (id: string, connId: string, secret?: OneTimeSecret) => {
      try {
        const start = await startSession(connId, secret);
        setTabs((list) =>
          list.map((tab) =>
            tab.id === id
              ? {
                  ...tab,
                  start,
                  error: undefined,
                  dead: false,
                  needsPassword: false,
                  certificate: undefined,
                  pendingSecret: undefined,
                  epoch: tab.epoch + 1,
                }
              : tab,
          ),
        );
      } catch (e) {
        const needsPassword =
          e instanceof ApiError && e.code === "no_credential";
        const certificate = certificateDecision(e);
        update(id, {
          start: undefined,
          needsPassword,
          certificate,
          // A secret the user asked to save is already saved; only a one-time secret is kept.
          pendingSecret:
            certificate && secret && !secret.save ? secret : undefined,
          error:
            needsPassword || certificate
              ? undefined
              : e instanceof Error
                ? e.message
                : String(e),
        });
      }
    },
    [],
  );

  const openSession = useCallback(
    async (opts: OpenOpts): Promise<string> => {
      const id = crypto.randomUUID();
      setTabs((list) => [
        ...list,
        {
          id,
          connId: opts.connId,
          title: opts.title,
          protocol: opts.protocol,
          epoch: 0,
        },
      ]);
      await begin(id, opts.connId);
      return id;
    },
    [begin],
  );

  const closeSession = useCallback((id: string) => {
    setTabs((list) => list.filter((tab) => tab.id !== id));
  }, []);

  /** Every reconnect asks for a new ticket; nothing is reopened without one. */
  const reconnect = useCallback(
    async (id: string, secret?: OneTimeSecret) => {
      const tab = tabsRef.current.find((t) => t.id === id);
      if (tab) await begin(id, tab.connId, secret);
    },
    [begin],
  );

  /** Trusts a first-seen certificate the user compared, then starts the session again. */
  const trustCertificate = useCallback(
    async (id: string) => {
      const tab = tabsRef.current.find((t) => t.id === id);
      if (!tab?.certificate || tab.certificate.kind !== "unknown") return;
      try {
        await treeApi.trustCertificate(tab.connId, tab.certificate.fingerprint);
        await begin(id, tab.connId, tab.pendingSecret);
      } catch (e) {
        const certificate = certificateDecision(e);
        update(id, {
          certificate,
          error: certificate
            ? undefined
            : e instanceof Error
              ? e.message
              : String(e),
        });
      }
    },
    [begin],
  );

  /** After the user confirmed a changed certificate with the server's owner. */
  const forgetCertificate = useCallback(
    async (id: string) => {
      const tab = tabsRef.current.find((t) => t.id === id);
      if (!tab) return;
      try {
        await treeApi.forgetHostKey(tab.connId);
        await begin(id, tab.connId, tab.pendingSecret);
      } catch (e) {
        update(id, {
          certificate: undefined,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    },
    [begin],
  );

  const markDead = useCallback((id: string) => update(id, { dead: true }), []);

  const duplicate = useCallback(
    async (id: string): Promise<string | null> => {
      const tab = tabsRef.current.find((t) => t.id === id);
      if (!tab) return null;
      return openSession({
        connId: tab.connId,
        title: `${tab.title} (2)`,
        protocol: tab.protocol,
      });
    },
    [openSession],
  );

  return {
    tabs,
    openSession,
    closeSession,
    reconnect,
    duplicate,
    markDead,
    trustCertificate,
    forgetCertificate,
  };
}
