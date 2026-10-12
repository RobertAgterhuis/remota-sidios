import { useCallback, useRef, useState } from "react";
import { ApiError, type Protocol, request } from "../lib/api";

/** What the server answers when a session may start (SidiOS contracts/remota-api.md). */
export interface SessionStart {
  sessionId: string;
  /** Path with the single-use ticket, valid for 60 seconds. */
  websocket: string;
  protocol: Protocol;
  /** RDP only: a throwaway login for this one session, never the target's credential. */
  rdpSessionLogin?: { username: string; password: string };
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
    ...(secret ? { oneTimeSecret: secret.password, saveSecret: secret.save } : {}),
  });
}

/** The WebSocket URL for a start answer, on this page's own origin. */
export function socketUrl(start: SessionStart): string {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}${start.websocket}`;
}

export function useSessions() {
  const [tabs, setTabs] = useState<SessionTab[]>([]);
  const tabsRef = useRef<SessionTab[]>([]);
  tabsRef.current = tabs;

  const update = (id: string, patch: Partial<SessionTab>) =>
    setTabs((list) => list.map((tab) => (tab.id === id ? { ...tab, ...patch } : tab)));

  const begin = useCallback(async (id: string, connId: string, secret?: OneTimeSecret) => {
    try {
      const start = await startSession(connId, secret);
      setTabs((list) =>
        list.map((tab) =>
          tab.id === id
            ? { ...tab, start, error: undefined, dead: false, needsPassword: false, epoch: tab.epoch + 1 }
            : tab,
        ),
      );
    } catch (e) {
      const needsPassword = e instanceof ApiError && e.code === "no_credential";
      update(id, {
        start: undefined,
        needsPassword,
        error: needsPassword ? undefined : e instanceof Error ? e.message : String(e),
      });
    }
  }, []);

  const openSession = useCallback(
    async (opts: OpenOpts): Promise<string> => {
      const id = crypto.randomUUID();
      setTabs((list) => [
        ...list,
        { id, connId: opts.connId, title: opts.title, protocol: opts.protocol, epoch: 0 },
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

  const markDead = useCallback((id: string) => update(id, { dead: true }), []);

  const duplicate = useCallback(
    async (id: string): Promise<string | null> => {
      const tab = tabsRef.current.find((t) => t.id === id);
      if (!tab) return null;
      return openSession({ connId: tab.connId, title: `${tab.title} (2)`, protocol: tab.protocol });
    },
    [openSession],
  );

  return { tabs, openSession, closeSession, reconnect, duplicate, markDead };
}
