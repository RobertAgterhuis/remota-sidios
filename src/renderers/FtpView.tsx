import { useCallback, useEffect, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import { describe } from "../lib/api";
import { colors, ghostBtn, input, primaryBtn } from "../components/styles";

/** Largest upload the server accepts (SidiOS FR-019). */
export const MAX_UPLOAD = 1024 ** 3;

type Props = {
  /** The session WebSocket with its single-use ticket. */
  wsUrl: string;
  sessionId: string;
  /** FTPS; plain FTP sends the password unencrypted to the server. */
  secure: boolean;
  onClosed?: () => void;
};

export interface Entry {
  name: string;
  kind: "dir" | "file" | "link";
  size: number;
  modified?: number;
}

type Answer = {
  ok: boolean;
  code?: string;
  message?: string;
  path?: string;
  entries?: Entry[];
};

export function joinPath(folder: string, name: string): string {
  return folder.endsWith("/") ? `${folder}${name}` : `${folder}/${name}`;
}

export function parentPath(path: string): string {
  const trimmed = path.replace(/\/+$/u, "");
  const cut = trimmed.lastIndexOf("/");
  return cut <= 0 ? "/" : trimmed.slice(0, cut);
}

/** Each step from the root to `path`, for the breadcrumbs. */
export function crumbs(path: string): { name: string; path: string }[] {
  const parts = path.split("/").filter(Boolean);
  return [
    { name: "/", path: "/" },
    ...parts.map((name, i) => ({ name, path: `/${parts.slice(0, i + 1).join("/")}` })),
  ];
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

function transferUrl(sessionId: string, action: "download" | "upload", path: string): string {
  return `/api/ftp/${encodeURIComponent(sessionId)}/${action}?path=${encodeURIComponent(path)}`;
}

function problem(answer: Answer): string {
  if (answer.code === "server_error" && answer.message) return `The server answered: ${answer.message}`;
  return describe(answer.code ?? "failed");
}

/** An FTP or FTPS file browser. The server signs in; this page never sees the password. */
export function FtpView({ wsUrl, sessionId, secure, onClosed }: Props) {
  const socket = useRef<WebSocket | null>(null);
  const pending = useRef(new Map<number, (answer: Answer) => void>());
  const nextId = useRef(0);
  const [ready, setReady] = useState(false);
  const [ended, setEnded] = useState<string | null>(null);
  const [path, setPath] = useState("/");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [editing, setEditing] = useState<{ mode: "mkdir" | "rename"; value: string } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const rows = useRef(new Map<string, HTMLTableRowElement>());

  const call = useCallback((command: Record<string, unknown>): Promise<Answer> => {
    const ws = socket.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return Promise.resolve({ ok: false, code: "connection_closed" });
    }
    nextId.current += 1;
    const id = nextId.current;
    return new Promise((resolve) => {
      pending.current.set(id, resolve);
      ws.send(JSON.stringify({ ...command, id }));
    });
  }, []);

  const open = useCallback(
    async (target: string) => {
      setBusy(true);
      const answer = await call({ op: "list", path: target });
      setBusy(false);
      if (!answer.ok) {
        setNotice({ ok: false, text: problem(answer) });
        return;
      }
      setPath(answer.path ?? target);
      setEntries(answer.entries ?? []);
      setSelected(null);
    },
    [call],
  );

  useEffect(() => {
    const ws = new WebSocket(wsUrl);
    const waiting = pending.current;
    socket.current = ws;
    setReady(false);
    setEnded(null);
    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string") return;
      let message: { type?: string; id?: number; start?: string } & Answer;
      try {
        message = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (message.type === "ready") {
        setReady(true);
        void open(message.start || "/");
      } else if (message.type === "result" && typeof message.id === "number") {
        waiting.get(message.id)?.(message);
        waiting.delete(message.id);
      }
    };
    ws.onclose = (ev) => {
      for (const resolve of waiting.values()) resolve({ ok: false, code: "connection_closed" });
      waiting.clear();
      setEnded(ev.reason || "ended");
      onClosed?.();
    };
    return () => {
      ws.onclose = null;
      ws.close();
      socket.current = null;
    };
    // `open` and `onClosed` must not reopen the session; only a new ticket (URL) does.
  }, [wsUrl]);

  const refresh = () => open(path);
  const current = entries.find((e) => e.name === selected) ?? null;

  const download = (entry: Entry) => {
    const link = document.createElement("a");
    link.href = transferUrl(sessionId, "download", joinPath(path, entry.name));
    link.download = entry.name;
    link.rel = "noopener";
    document.body.append(link);
    link.click();
    link.remove();
  };

  const activate = (entry: Entry) => {
    if (entry.kind === "file") download(entry);
    else void open(joinPath(path, entry.name));
  };

  const upload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setBusy(true);
    try {
      for (const file of Array.from(files)) {
        if (file.size > MAX_UPLOAD) {
          setNotice({ ok: false, text: `${file.name} is larger than 1 GB.` });
          continue;
        }
        const response = await fetch(transferUrl(sessionId, "upload", joinPath(path, file.name)), {
          method: "PUT",
          body: file,
          credentials: "same-origin",
        });
        if (!response.ok) {
          const payload = (await response.json().catch(() => ({}))) as Answer;
          const text =
            response.status === 413 ? `${file.name} is larger than 1 GB.` : problem({ ...payload, ok: false });
          setNotice({ ok: false, text });
          continue;
        }
        setNotice({ ok: true, text: `Uploaded ${file.name}` });
      }
    } finally {
      setBusy(false);
      if (fileInput.current) fileInput.current.value = "";
    }
    await refresh();
  };

  const remove = async (entry: Entry) => {
    const what = entry.kind === "dir" ? "folder" : "file";
    if (!window.confirm(`Delete the ${what} ${entry.name}? This cannot be undone.`)) return;
    const answer = await call({ op: "delete", path: joinPath(path, entry.name), folder: entry.kind === "dir" });
    setNotice(answer.ok ? { ok: true, text: `Deleted ${entry.name}` } : { ok: false, text: problem(answer) });
    if (answer.ok) await refresh();
  };

  const submitEdit = async () => {
    if (!editing) return;
    const value = editing.value.trim();
    if (!value || value.includes("/")) {
      setNotice({ ok: false, text: "Enter a name without a slash." });
      return;
    }
    const answer =
      editing.mode === "mkdir"
        ? await call({ op: "mkdir", path: joinPath(path, value) })
        : await call({ op: "rename", from: joinPath(path, selected ?? ""), to: joinPath(path, value) });
    if (!answer.ok) {
      setNotice({ ok: false, text: problem(answer) });
      return;
    }
    setEditing(null);
    setNotice(null);
    await refresh();
    if (editing.mode === "rename") setSelected(value);
  };

  const onRowKey = (ev: KeyboardEvent<HTMLTableRowElement>, entry: Entry, index: number) => {
    const move = (to: number) => {
      const next = entries[Math.max(0, Math.min(entries.length - 1, to))];
      if (!next) return;
      setSelected(next.name);
      rows.current.get(next.name)?.focus();
    };
    switch (ev.key) {
      case "ArrowDown":
        move(index + 1);
        break;
      case "ArrowUp":
        move(index - 1);
        break;
      case "Home":
        move(0);
        break;
      case "End":
        move(entries.length - 1);
        break;
      case "Enter":
        activate(entry);
        break;
      case "Backspace":
        void open(parentPath(path));
        break;
      case "Delete":
        void remove(entry);
        break;
      case "F2":
        setSelected(entry.name);
        setEditing({ mode: "rename", value: entry.name });
        break;
      default:
        return;
    }
    ev.preventDefault();
  };

  if (ended && !ready) {
    return (
      <div role="alert" style={{ padding: 20, color: colors.danger, fontSize: 13 }}>
        The file session could not start: {ended}.
      </div>
    );
  }

  const disabled = !ready || busy || ended !== null;
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", padding: 12, gap: 10, boxSizing: "border-box" }}>
      {!secure && (
        <div role="note" style={{ fontSize: 12, color: colors.danger }}>
          Plain FTP: the password and files travel to the server unencrypted. Use FTPS when the server offers it.
        </div>
      )}
      {ended && (
        <div role="status" style={{ fontSize: 12, color: colors.dim }}>
          The session ended ({ended}). Reconnect from the tab to continue.
        </div>
      )}

      <nav aria-label="Folder path" style={{ display: "flex", flexWrap: "wrap", gap: 2, fontSize: 13 }}>
        {crumbs(path).map((crumb, i) => (
          <span key={crumb.path}>
            {i > 1 && <span style={{ color: colors.dim }}>/</span>}
            <button
              type="button"
              disabled={disabled}
              aria-current={crumb.path === path ? "location" : undefined}
              onClick={() => void open(crumb.path)}
              style={{ ...ghostBtn, border: "none", padding: "2px 4px", color: colors.text }}
            >
              {crumb.name}
            </button>
          </span>
        ))}
      </nav>

      <div role="toolbar" aria-label="File actions" style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        <button type="button" style={ghostBtn} disabled={disabled || path === "/"} onClick={() => void open(parentPath(path))}>
          Up
        </button>
        <button type="button" style={ghostBtn} disabled={disabled} onClick={() => void refresh()}>
          Refresh
        </button>
        <button type="button" style={ghostBtn} disabled={disabled} onClick={() => fileInput.current?.click()}>
          Upload…
        </button>
        <input
          ref={fileInput}
          type="file"
          multiple
          hidden
          aria-label="Files to upload"
          onChange={(e) => void upload(e.target.files)}
        />
        <button type="button" style={ghostBtn} disabled={disabled} onClick={() => setEditing({ mode: "mkdir", value: "" })}>
          New folder
        </button>
        <button
          type="button"
          style={ghostBtn}
          disabled={disabled || !current || current.kind !== "file"}
          onClick={() => current && download(current)}
        >
          Download
        </button>
        <button
          type="button"
          style={ghostBtn}
          disabled={disabled || !current}
          onClick={() => current && setEditing({ mode: "rename", value: current.name })}
        >
          Rename
        </button>
        <button type="button" style={ghostBtn} disabled={disabled || !current} onClick={() => current && void remove(current)}>
          Delete
        </button>
      </div>

      {editing && (
        <form
          aria-label={editing.mode === "mkdir" ? "New folder" : `Rename ${selected ?? ""}`}
          onSubmit={(e) => {
            e.preventDefault();
            void submitEdit();
          }}
          style={{ display: "flex", gap: 6, maxWidth: 420 }}
        >
          <input
            aria-label={editing.mode === "mkdir" ? "Folder name" : "New name"}
            style={input}
            autoFocus
            maxLength={255}
            value={editing.value}
            onChange={(e) => setEditing({ ...editing, value: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Escape") setEditing(null);
            }}
          />
          <button type="submit" style={primaryBtn} disabled={disabled}>
            {editing.mode === "mkdir" ? "Create" : "Rename"}
          </button>
          <button type="button" style={ghostBtn} onClick={() => setEditing(null)}>
            Cancel
          </button>
        </form>
      )}

      {notice && (
        <div role={notice.ok ? "status" : "alert"} style={{ fontSize: 12, color: notice.ok ? colors.success : colors.danger }}>
          {notice.text}
        </div>
      )}

      <div style={{ flex: 1, overflow: "auto", border: `1px solid ${colors.border}`, borderRadius: "var(--radius-sm)" }}>
        <table aria-label={`Files in ${path}`} aria-busy={busy || !ready} style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: "left", color: colors.dim }}>
              <th style={{ padding: "6px 8px" }}>Name</th>
              <th style={{ padding: "6px 8px", width: 90 }}>Size</th>
              <th style={{ padding: "6px 8px", width: 170 }}>Modified</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, index) => (
              <tr
                key={entry.name}
                ref={(row) => {
                  if (row) rows.current.set(entry.name, row);
                  else rows.current.delete(entry.name);
                }}
                tabIndex={selected === entry.name || (selected === null && index === 0) ? 0 : -1}
                aria-selected={selected === entry.name}
                onClick={() => setSelected(entry.name)}
                onFocus={() => setSelected(entry.name)}
                onDoubleClick={() => activate(entry)}
                onKeyDown={(ev) => onRowKey(ev, entry, index)}
                style={{
                  cursor: "pointer",
                  background: selected === entry.name ? colors.selected : undefined,
                  outlineOffset: -2,
                }}
              >
                <td style={{ padding: "4px 8px" }}>
                  <span
                    role="img"
                    aria-label={entry.kind === "dir" ? "Folder" : entry.kind === "link" ? "Link" : "File"}
                    style={{ color: colors.dim, marginRight: 6 }}
                  >
                    {entry.kind === "dir" ? "▸" : entry.kind === "link" ? "↪" : "•"}
                  </span>
                  {entry.name}
                </td>
                <td style={{ padding: "4px 8px", color: colors.dim }}>{entry.kind === "file" ? formatSize(entry.size) : ""}</td>
                <td style={{ padding: "4px 8px", color: colors.dim }}>
                  {entry.modified ? new Date(entry.modified).toLocaleString() : ""}
                </td>
              </tr>
            ))}
            {ready && entries.length === 0 && (
              <tr>
                <td colSpan={3} style={{ padding: 12, color: colors.dim }}>
                  This folder is empty.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p style={{ margin: 0, fontSize: 11, color: colors.dim }}>
        Enter opens a folder or downloads a file · Backspace goes up · F2 renames · Delete deletes
      </p>
    </div>
  );
}
