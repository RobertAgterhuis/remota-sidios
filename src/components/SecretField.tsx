import { useId } from "react";
import type { SecretFields } from "../lib/api";
import { colors, ghostBtn, input, label } from "./styles";

/**
 * Editing state of a write-only secret. A saved secret is never shown or sent back: the field
 * starts empty, and only a newly typed password or key, or an explicit removal, changes it.
 */
export type SecretForm = {
  credentialId?: string;
  password: string;
  privateKey: string;
  passphrase: string;
  remove: boolean;
};

export const emptySecret: SecretForm = {
  password: "",
  privateKey: "",
  passphrase: "",
  remove: false,
};

export function secretFromModel(model?: SecretFields): SecretForm {
  return { ...emptySecret, credentialId: model?.credential_id };
}

/** The secret part of a node to save: a new secret, the kept credential, or nothing. */
export function secretToModel(form: SecretForm): SecretFields {
  if (form.privateKey.trim()) {
    return {
      private_key: form.privateKey,
      passphrase: form.passphrase || undefined,
    };
  }
  if (form.password) return { password: form.password };
  if (form.remove || !form.credentialId) return {};
  return { credential_id: form.credentialId };
}

type Props = {
  value: SecretForm;
  onChange: (value: SecretForm) => void;
  /** Offer an SSH private key besides a password. */
  allowKey: boolean;
  /** Where an inherited secret comes from, shown when this node has none. */
  inheritedFrom?: string;
  prefix: string;
};

export function SecretField({
  value,
  onChange,
  allowKey,
  inheritedFrom,
  prefix,
}: Props) {
  const id = useId();
  const saved = value.credentialId !== undefined && !value.remove;
  const set = (patch: Partial<SecretForm>) => onChange({ ...value, ...patch });
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <label htmlFor={`${id}-password`} className="visually-hidden">
        {prefix} password
      </label>
      <input
        id={`${id}-password`}
        style={input}
        type="password"
        autoComplete="new-password"
        value={value.password}
        onChange={(e) => set({ password: e.target.value })}
        placeholder={
          saved
            ? "Password saved in SidiOS — type to replace"
            : inheritedFrom
              ? `Inherited from ${inheritedFrom}`
              : "password"
        }
      />
      {allowKey && (
        <>
          <label htmlFor={`${id}-key`} style={label}>
            {prefix} SSH private key (optional)
          </label>
          <textarea
            id={`${id}-key`}
            style={{ ...input, fontFamily: "var(--font-mono)", minHeight: 64 }}
            spellCheck={false}
            value={value.privateKey}
            onChange={(e) => set({ privateKey: e.target.value })}
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          />
          {value.privateKey.trim() && (
            <input
              aria-label={`${prefix} key passphrase`}
              style={input}
              type="password"
              autoComplete="new-password"
              value={value.passphrase}
              onChange={(e) => set({ passphrase: e.target.value })}
              placeholder="key passphrase (if any)"
            />
          )}
        </>
      )}
      {value.credentialId !== undefined && (
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ color: saved ? colors.success : colors.dim, fontSize: 12 }}>
            {saved ? "A secret is saved." : "The saved secret will be removed."}
          </span>
          <button
            type="button"
            style={ghostBtn}
            onClick={() => set({ remove: !value.remove })}
          >
            {value.remove ? "Keep it" : "Remove saved secret"}
          </button>
        </div>
      )}
    </div>
  );
}
