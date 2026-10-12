import { type CSSProperties, useEffect, useId, useRef, useState } from "react";
import { type About, aboutApi } from "../lib/api";
import { colors, primaryBtn } from "./styles";

/** Help → About: the running build's fork commit and a link to its exact source (AGPL-3.0). */
export function AboutDialog(props: { onClose: () => void }) {
  const titleId = useId();
  const [about, setAbout] = useState<About | null>(null);
  const [failed, setFailed] = useState(false);
  const close = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    close.current?.focus();
    aboutApi.get().then(setAbout, () => setFailed(true));
  }, []);

  return (
    <div style={backdrop}>
      <div
        aria-labelledby={titleId}
        aria-modal="true"
        onKeyDown={(event) => {
          if (event.key === "Escape") props.onClose();
        }}
        role="dialog"
        style={dialog}
      >
        <h2 id={titleId} style={{ fontSize: 16, margin: 0 }}>
          About Remota
        </h2>
        {about ? (
          <dl
            style={{
              margin: 0,
              display: "grid",
              gridTemplateColumns: "auto 1fr",
              gap: "6px 12px",
              fontSize: 13,
            }}
          >
            <dt style={term}>Version</dt>
            <dd style={value}>
              {about.name} {about.version}
            </dd>
            <dt style={term}>Source commit</dt>
            <dd style={{ ...value, fontFamily: "var(--font-mono, monospace)" }}>
              {about.commit ?? "not recorded in this build"}
            </dd>
            <dt style={term}>License</dt>
            <dd style={value}>
              GNU Affero General Public License v3.0 ({about.license})
            </dd>
          </dl>
        ) : failed ? (
          <p role="alert" style={{ margin: 0, fontSize: 13 }}>
            The build information could not be loaded.
          </p>
        ) : (
          <p style={{ margin: 0, fontSize: 13 }}>Loading…</p>
        )}
        <p style={{ margin: 0, fontSize: 13, color: colors.dim }}>
          Remota is free software: you can get the source of the version you are
          using and change it under the AGPL-3.0.{" "}
          <a
            href={
              about?.source ??
              "https://github.com/RobertAgterhuis/remota-sidios"
            }
            rel="noopener noreferrer"
            style={{ color: colors.accent }}
            target="_blank"
          >
            Get the source code
          </a>
        </p>
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button
            onClick={props.onClose}
            ref={close}
            style={primaryBtn}
            type="button"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

const backdrop: CSSProperties = {
  position: "fixed",
  inset: 0,
  background: "color-mix(in srgb, var(--color-background) 70%, transparent)",
  display: "grid",
  placeItems: "center",
  zIndex: 50,
};

const dialog: CSSProperties = {
  background: colors.panel,
  border: `1px solid ${colors.border}`,
  borderRadius: "var(--radius-md, 8px)",
  padding: 20,
  width: "min(480px, calc(100vw - 32px))",
  display: "grid",
  gap: 16,
  color: colors.text,
};

const term: CSSProperties = { color: colors.dim };
const value: CSSProperties = { margin: 0, overflowWrap: "anywhere" };
