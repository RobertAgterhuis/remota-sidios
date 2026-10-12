import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { clipRead, clipWrite } from "../lib/clipboard";
import { colors, ghostBtn, primaryBtn } from "../components/styles";

/** A control message from the server (text frame); terminal output is always binary. */
export type ControlMessage =
  | { type: "trust"; host: string; port: number; fingerprint: string }
  | { type: "error"; message: string };

export function parseControl(text: string): ControlMessage | null {
  try {
    const value = JSON.parse(text) as { type?: unknown };
    return value.type === "trust" || value.type === "error" ? (value as ControlMessage) : null;
  } catch {
    return null;
  }
}

/** SSH terminal: the server runs the SSH session; this page only draws it (xterm.js). */
export function SshView({ wsUrl, onClosed }: { wsUrl: string; onClosed?: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const socket = useRef<WebSocket | null>(null);
  const [trust, setTrust] = useState<Extract<ControlMessage, { type: "trust" }> | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const styles = getComputedStyle(document.documentElement);
    const term = new Terminal({
      fontSize: 13,
      fontFamily: styles.getPropertyValue("--font-mono").trim() || "monospace",
      cursorBlink: true,
      theme: {
        background: styles.getPropertyValue("--color-background").trim(),
        foreground: styles.getPropertyValue("--color-text").trim(),
      },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    fit.fit();

    // The PTY starts at the real size, so full-screen programs fit from the first frame.
    const ws = new WebSocket(`${wsUrl}&cols=${term.cols}&rows=${term.rows}`);
    socket.current = ws;
    ws.binaryType = "arraybuffer";
    const enc = new TextEncoder();

    // Ctrl+Shift+C copies the selection; Ctrl+Shift+V pastes.
    term.attachCustomKeyEventHandler((e) => {
      if (e.type === "keydown" && e.ctrlKey && e.shiftKey) {
        if (e.code === "KeyC") {
          const sel = term.getSelection();
          if (sel) clipWrite(sel);
          return false;
        }
        if (e.code === "KeyV") {
          clipRead().then((t) => {
            if (t && ws.readyState === WebSocket.OPEN) ws.send(enc.encode(t));
          });
          return false;
        }
      }
      return true;
    });

    const sendResize = () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string") {
        term.write(new Uint8Array(ev.data));
        return;
      }
      const control = parseControl(ev.data);
      if (control?.type === "trust") setTrust(control);
      if (control?.type === "error") term.write(`\r\n\x1b[31m${control.message}\x1b[0m\r\n`);
    };
    ws.onopen = () => sendResize();
    ws.onclose = (ev) => {
      setTrust(null);
      const reason = ev.reason ? `: ${ev.reason}` : "";
      term.write(`\r\n\x1b[90m[session ended${reason}]\x1b[0m\r\n`);
      onClosed?.();
    };

    const onData = term.onData((d) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d));
    });

    const refit = () => {
      fit.fit();
      sendResize();
    };
    const ro = new ResizeObserver(() => refit());
    ro.observe(el);

    return () => {
      ro.disconnect();
      onData.dispose();
      ws.close();
      term.dispose();
      socket.current = null;
    };
  }, [wsUrl]);

  const answer = (accept: boolean) => {
    socket.current?.send(JSON.stringify({ type: "trust", accept }));
    setTrust(null);
  };

  return (
    <div style={{ position: "relative", width: "100%", height: "100%" }}>
      <div
        ref={ref}
        style={{ width: "100%", height: "100%", background: colors.bg, padding: 4, boxSizing: "border-box" }}
      />
      {trust && (
        <div
          role="alertdialog"
          aria-labelledby="trust-title"
          style={{
            position: "absolute",
            inset: "20% 10% auto",
            background: colors.raised,
            border: `1px solid ${colors.border}`,
            borderRadius: "var(--radius-md)",
            padding: 16,
            display: "grid",
            gap: 10,
          }}
        >
          <strong id="trust-title">First connection to {trust.host}</strong>
          <span style={{ fontSize: 13 }}>
            Check that this host key fingerprint is the server's before you trust it:
          </span>
          <code style={{ fontFamily: "var(--font-mono)", fontSize: 12, wordBreak: "break-all" }}>
            {trust.fingerprint}
          </code>
          <div style={{ display: "flex", gap: 8 }}>
            <button type="button" style={primaryBtn} autoFocus onClick={() => answer(true)}>
              Trust and connect
            </button>
            <button type="button" style={ghostBtn} onClick={() => answer(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
