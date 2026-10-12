import type { Gateway } from "../lib/api";
import {
  SecretField,
  type SecretForm,
  emptySecret,
  secretFromModel,
  secretToModel,
} from "./SecretField";
import { colors, input, label } from "./styles";

export type GwForm = {
  host: string;
  port: string;
  username: string;
  secret: SecretForm;
};
export const emptyGw: GwForm = {
  host: "",
  port: "",
  username: "",
  secret: emptySecret,
};

export function gwFromModel(g?: Gateway): GwForm {
  return {
    host: g?.host ?? "",
    port: g?.port ? String(g.port) : "",
    username: g?.username ?? "",
    secret: secretFromModel(g),
  };
}

export function gwToModel(f: GwForm): Gateway | undefined {
  if (!f.host.trim()) return undefined;
  return {
    host: f.host.trim(),
    port: f.port ? Number(f.port) : undefined,
    username: f.username || undefined,
    ...secretToModel(f.secret),
  };
}

export function GatewaySection({
  value,
  onChange,
  hint,
  inheritedFrom,
}: {
  value: GwForm;
  onChange: (v: GwForm) => void;
  hint?: string;
  /** "host (from folder)" when a folder above provides the jump host. */
  inheritedFrom?: string;
}) {
  const set = (patch: Partial<GwForm>) => onChange({ ...value, ...patch });
  return (
    <fieldset
      style={{
        border: "none",
        borderTop: `1px solid ${colors.border}`,
        padding: "12px 0 0",
        margin: 0,
      }}
    >
      <legend style={{ ...label, padding: 0, marginBottom: 6 }}>
        Jump host (SSH)
      </legend>
      <div style={{ color: colors.dim, fontSize: 11, marginBottom: 8 }}>
        {hint ??
          "Reach the target through this host (empty = direct). Inherited by connections in the folder."}
        {inheritedFrom && !value.host && ` Now inherited: ${inheritedFrom}.`}
      </div>
      <div style={{ display: "flex", gap: 10 }}>
        <input
          aria-label="Jump host"
          style={input}
          value={value.host}
          onChange={(e) => set({ host: e.target.value })}
          placeholder="jump host (e.g. 192.168.1.242)"
        />
        <input
          aria-label="Jump host port"
          style={{ ...input, width: 90 }}
          inputMode="numeric"
          value={value.port}
          onChange={(e) => set({ port: e.target.value.replace(/[^0-9]/g, "") })}
          placeholder="22"
        />
      </div>
      {value.host.trim() && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 10,
            marginTop: 10,
          }}
        >
          <input
            aria-label="Jump host username"
            style={input}
            value={value.username}
            onChange={(e) => set({ username: e.target.value })}
            placeholder="jump username"
          />
          <SecretField
            prefix="Jump host"
            allowKey
            value={value.secret}
            onChange={(secret) => set({ secret })}
          />
        </div>
      )}
    </fieldset>
  );
}
