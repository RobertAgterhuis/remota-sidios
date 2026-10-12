import { useEffect, useId, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import type { Node, Protocol } from "../lib/api";
import type { Inherited } from "../lib/inherit";
import {
  GatewaySection,
  type GwForm,
  emptyGw,
  gwFromModel,
  gwToModel,
} from "./GatewaySection";
import {
  SecretField,
  type SecretForm,
  emptySecret,
  secretFromModel,
  secretToModel,
} from "./SecretField";
import { colors, input, label, primaryBtn } from "./styles";

const PROTOCOLS: Protocol[] = ["ssh", "rdp"];
const DEFAULT_PORT: Record<Protocol, number> = { ssh: 22, rdp: 3389 };

type Props = {
  node: Node | null;
  /** What the folders above provide, to show where empty fields come from. */
  inherited: Inherited;
  onSave: (node: Node) => Promise<void>;
  onConnect?: (id: string) => void;
};

export function ConnectionEditor({ node, inherited, onSave, onConnect }: Props) {
  const editingId = node?.type === "connection" ? node.id : null;
  const [name, setName] = useState("");
  const [protocol, setProtocol] = useState<Protocol>("ssh");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("");
  const [username, setUsername] = useState("");
  const [domain, setDomain] = useState("");
  const [secret, setSecret] = useState<SecretForm>(emptySecret);
  const [gw, setGw] = useState<GwForm>(emptyGw);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    const e = node?.type === "connection" ? node : null;
    setName(e?.name ?? "");
    setProtocol(e?.conn.protocol ?? "ssh");
    setHost(e?.conn.host ?? "");
    setPort(e?.conn.port ? String(e.conn.port) : "");
    setUsername(e?.conn.credentials.username ?? "");
    setDomain(e?.conn.credentials.domain ?? "");
    setSecret(secretFromModel(e?.conn.credentials));
    setGw(gwFromModel(e?.conn.gateway));
    setMessage(null);
  }, [node]);

  async function submit(ev: { preventDefault: () => void }) {
    ev.preventDefault();
    if (!name.trim() || !host.trim()) return;
    setBusy(true);
    try {
      await onSave({
        type: "connection",
        id: editingId ?? crypto.randomUUID(),
        name: name.trim(),
        conn: {
          protocol,
          host: host.trim(),
          port: port ? Number(port) : undefined,
          credentials: {
            username: username || undefined,
            domain: domain || undefined,
            ...secretToModel(secret),
          },
          gateway: gwToModel(gw),
        },
      });
      setMessage({ ok: true, text: "Saved" });
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }

  const isRdp = protocol === "rdp";
  const inheritedGw = inherited.gateway
    ? `${inherited.gateway.value.host} (from ${inherited.gateway.from})`
    : undefined;

  return (
    <form
      onSubmit={submit}
      aria-label={editingId ? "Edit connection" : "New connection"}
      style={{ display: "flex", flexDirection: "column", gap: 12, padding: 16, maxWidth: 420 }}
    >
      <h2 style={{ margin: 0, fontSize: 15, color: colors.text }}>
        {editingId ? "Edit connection" : "New connection"}
      </h2>

      <Field label="Name">
        {(id) => (
          <input id={id} style={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. web-prod" maxLength={120} />
        )}
      </Field>

      <div style={{ display: "flex", gap: 10 }}>
        <Field label="Protocol" style={{ flex: 1 }}>
          {(id) => (
            <select id={id} style={{ ...input, cursor: "pointer" }} value={protocol} onChange={(e) => setProtocol(e.target.value as Protocol)}>
              {PROTOCOLS.map((p) => (
                <option key={p} value={p}>
                  {p.toUpperCase()}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label="Port" style={{ width: 110 }}>
          {(id) => (
            <input id={id} style={input} inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ""))} placeholder={String(DEFAULT_PORT[protocol])} />
          )}
        </Field>
      </div>

      <Field label="Host">
        {(id) => (
          <input id={id} style={input} value={host} onChange={(e) => setHost(e.target.value)} placeholder="e.g. 192.168.1.10" />
        )}
      </Field>

      <fieldset style={{ border: "none", borderTop: `1px solid ${colors.border}`, padding: "12px 0 0", margin: 0 }}>
        <legend style={{ ...label, padding: 0, marginBottom: 8 }}>
          Credentials (empty = inherit from folder)
        </legend>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <input
            aria-label="Username"
            style={input}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder={inherited.username ? `${inherited.username.value} (from ${inherited.username.from})` : "username"}
          />
          <SecretField
            prefix="Connection"
            allowKey={!isRdp}
            value={secret}
            onChange={setSecret}
            inheritedFrom={inherited.secret?.from}
          />
          {isRdp && (
            <input
              aria-label="Domain"
              style={input}
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder={inherited.domain ? `${inherited.domain.value} (from ${inherited.domain.from})` : "domain (RDP)"}
            />
          )}
        </div>
      </fieldset>

      {!isRdp && <GatewaySection value={gw} onChange={setGw} inheritedFrom={inheritedGw} />}

      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <button type="submit" disabled={busy || !name.trim() || !host.trim()} style={{ ...primaryBtn, opacity: busy || !name.trim() || !host.trim() ? 0.6 : 1 }}>
          {busy ? "Saving…" : "Save"}
        </button>
        {editingId && onConnect && (
          <button type="button" onClick={() => onConnect(editingId)} style={{ ...primaryBtn, background: colors.raised }} title="Open session (same as double-click in the tree)">
            Connect ▸
          </button>
        )}
        {message && (
          <span role="status" style={{ color: message.ok ? colors.success : colors.danger, fontSize: 12 }}>
            {message.text}
          </span>
        )}
      </div>
    </form>
  );
}

function Field({
  label: text,
  children,
  style,
}: {
  label: string;
  children: (id: string) => ReactNode;
  style?: CSSProperties;
}) {
  const id = useId();
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4, ...style }}>
      <label htmlFor={id} style={label}>
        {text}
      </label>
      {children(id)}
    </div>
  );
}
