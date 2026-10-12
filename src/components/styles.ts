import type { CSSProperties } from "react";

// Every color is a SidiOS design token (app.css); components never hardcode values.
export const colors = {
  bg: "var(--color-background)",
  panel: "var(--color-surface)",
  raised: "var(--color-surface-raised)",
  border: "var(--color-border)",
  text: "var(--color-text)",
  dim: "var(--color-text-muted)",
  accent: "var(--color-accent)",
  danger: "var(--color-danger)",
  success: "var(--color-success)",
  selected: "var(--color-selected)",
  ssh: "var(--color-ssh)",
  rdp: "var(--color-rdp)",
};

export const input: CSSProperties = {
  background: colors.bg,
  color: colors.text,
  border: `1px solid ${colors.border}`,
  borderRadius: "var(--radius-sm)",
  padding: "8px 10px",
  fontSize: 13,
  width: "100%",
  boxSizing: "border-box",
};

export const primaryBtn: CSSProperties = {
  background: colors.accent,
  color: colors.text,
  border: "none",
  borderRadius: "var(--radius-sm)",
  padding: "8px 12px",
  fontSize: 13,
  cursor: "pointer",
};

export const ghostBtn: CSSProperties = {
  background: "transparent",
  color: colors.dim,
  border: `1px solid ${colors.border}`,
  borderRadius: "var(--radius-sm)",
  padding: "6px 10px",
  fontSize: 12,
  cursor: "pointer",
};

export const label: CSSProperties = {
  fontSize: 11,
  color: colors.dim,
  textTransform: "uppercase",
  letterSpacing: 0.4,
};
