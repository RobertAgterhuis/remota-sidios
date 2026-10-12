import { type ReactNode, useEffect, useState } from "react";
import type { Node } from "../lib/api";
import type { Inherited } from "../lib/inherit";
import { colors, input, label, primaryBtn } from "./styles";
import { GatewaySection, type GwForm, emptyGw, gwFromModel, gwToModel } from "./GatewaySection";
import {
  SecretField,
  type SecretForm,
  emptySecret,
  secretFromModel,
  secretToModel,
} from "./SecretField";

const ICONS = [
  // pastas / storage
  "📁", "📂", "🗂️", "🗄️", "🗃️", "📦", "💾",
  // hosts / OS
  "🖥️", "💻", "⌨️", "🐧", "🪟", "🍎",
  // containers / cloud native / git
  "🐳", "☸️", "🐙", "🦊",
  // bases de dados / linguagens
  "🐘", "🐬", "🐍", "☕",
  // cloud / rede
  "☁️", "🌩️", "🌐", "🌍", "🕸️", "📡", "🛰️",
  // devops / ferramentas / automação
  "⚙️", "🛠️", "🧰", "🔧", "🏗️", "🤖",
  // segurança
  "🔒", "🔐", "🔑", "🛡️", "🔥", "🚨",
  // observabilidade / ambientes / destaque
  "📊", "📈", "🧪", "🎯", "⚡", "🚀",
  "🏠", "🏢", "⭐", "🔴", "🟢", "🔵",
];

export function FolderEditor({
  node,
  inherited,
  onSave,
}: {
  node: Node | null;
  inherited: Inherited;
  onSave: (n: Node) => Promise<void>;
}) {
  const editingId = node?.type === "folder" ? node.id : null;
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [domain, setDomain] = useState("");
  const [secret, setSecret] = useState<SecretForm>(emptySecret);
  const [gw, setGw] = useState<GwForm>(emptyGw);
  const [icon, setIcon] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    const f = node?.type === "folder" ? node : null;
    setName(f?.name ?? "");
    setUsername(f?.defaults.username ?? "");
    setDomain(f?.defaults.domain ?? "");
    setSecret(secretFromModel(f?.defaults));
    setGw(gwFromModel(f?.gateway));
    setIcon(f?.icon ?? "");
    setMessage(null);
  }, [node]);

  async function submit(ev: { preventDefault: () => void }) {
    ev.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    try {
      // The server keeps an existing folder's contents; only its own settings are sent.
      await onSave({
        type: "folder",
        id: editingId ?? crypto.randomUUID(),
        name: name.trim(),
        defaults: {
          username: username || undefined,
          domain: domain || undefined,
          ...secretToModel(secret),
        },
        gateway: gwToModel(gw),
        icon: icon || undefined,
        children: [],
      });
      setMessage({ ok: true, text: "Saved" });
    } catch (e) {
      setMessage({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }

  const inheritedGw = inherited.gateway
    ? `${inherited.gateway.value.host} (from ${inherited.gateway.from})`
    : undefined;

  return (
    <form
      onSubmit={submit}
      aria-label={editingId ? "Edit folder" : "New folder"}
      style={{ display: "flex", flexDirection: "column", gap: 12, padding: 16, maxWidth: 420 }}
    >
      <h2 style={{ margin: 0, fontSize: 15, color: colors.text }}>{editingId ? "Edit folder" : "New folder"}</h2>
      <Field label="Name">
        <input aria-label="Name" style={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Production" maxLength={120} />
      </Field>
      <Field label="Icon">
        <div role="radiogroup" aria-label="Icon" style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {ICONS.map((ic) => (
            <button
              key={ic}
              type="button"
              role="radio"
              aria-checked={icon === ic}
              onClick={() => setIcon(ic === icon ? "" : ic)}
              style={{
                fontSize: 18,
                lineHeight: 1,
                padding: "4px 7px",
                borderRadius: "var(--radius-sm)",
                cursor: "pointer",
                background: icon === ic ? colors.selected : "transparent",
                border: `1px solid ${icon === ic ? colors.accent : colors.border}`,
              }}
            >
              {ic}
            </button>
          ))}
        </div>
      </Field>
      <fieldset style={{ border: "none", borderTop: `1px solid ${colors.border}`, padding: "12px 0 0", margin: 0 }}>
        <legend style={{ ...label, padding: 0, marginBottom: 8 }}>Defaults inherited by children</legend>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <input
            aria-label="Username"
            style={input}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder={inherited.username ? `${inherited.username.value} (from ${inherited.username.from})` : "username"}
          />
          <SecretField prefix="Folder" allowKey value={secret} onChange={setSecret} inheritedFrom={inherited.secret?.from} />
          <input
            aria-label="Domain"
            style={input}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder={inherited.domain ? `${inherited.domain.value} (from ${inherited.domain.from})` : "domain"}
          />
        </div>
      </fieldset>
      <GatewaySection
        value={gw}
        onChange={setGw}
        inheritedFrom={inheritedGw}
        hint="All connections inside this folder go out through this jump host (unless they define their own)."
      />

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <button type="submit" disabled={busy || !name.trim()} style={{ ...primaryBtn, opacity: busy || !name.trim() ? 0.6 : 1 }}>
          {busy ? "Saving…" : "Save"}
        </button>
        {message && (
          <span role="status" style={{ color: message.ok ? colors.success : colors.danger, fontSize: 12 }}>
            {message.text}
          </span>
        )}
      </div>
    </form>
  );
}

function Field({ label: text, children }: { label: string; children: ReactNode }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      <span style={label}>{text}</span>
      {children}
    </div>
  );
}
