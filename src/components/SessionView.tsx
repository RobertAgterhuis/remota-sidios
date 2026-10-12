import { useState } from "react";
import { socketUrl, type OneTimeSecret, type SessionTab } from "../state/useSessions";
import { SshView } from "../renderers/SshView";
import { RdpView } from "../renderers/RdpView";
import { colors, ghostBtn, input, primaryBtn } from "./styles";

export function SessionView({
  tab,
  onDead,
  onRetry,
}: {
  tab: SessionTab;
  onDead?: () => void;
  onRetry: (secret?: OneTimeSecret) => void;
}) {
  if (tab.needsPassword) return <PasswordPrompt title={tab.title} onSubmit={onRetry} />;
  if (tab.error) {
    return (
      <div role="alert" style={{ padding: 20, display: "grid", gap: 12, justifyItems: "start" }}>
        <span style={{ color: colors.danger, fontSize: 13 }}>{tab.error}</span>
        <button type="button" style={ghostBtn} onClick={() => onRetry()}>
          Try again
        </button>
      </div>
    );
  }
  if (!tab.start) {
    return (
      <div role="status" style={{ padding: 20, color: colors.dim, fontSize: 13 }}>
        Connecting…
      </div>
    );
  }
  if (tab.protocol === "ssh") {
    return <SshView key={tab.epoch} wsUrl={socketUrl(tab.start)} onClosed={onDead} />;
  }
  return (
    <RdpView
      key={tab.epoch}
      proxyUrl={socketUrl(tab.start)}
      login={tab.start.rdpSessionLogin}
      onClosed={onDead}
    />
  );
}

/** Asked when a connection and its folders have no credential: used for this session only. */
function PasswordPrompt({
  title,
  onSubmit,
}: {
  title: string;
  onSubmit: (secret: OneTimeSecret) => void;
}) {
  const [password, setPassword] = useState("");
  const [save, setSave] = useState(false);
  return (
    <form
      aria-label={`Password for ${title}`}
      onSubmit={(e) => {
        e.preventDefault();
        if (password) onSubmit({ password, save });
      }}
      style={{ padding: 20, display: "grid", gap: 10, maxWidth: 360 }}
    >
      <span style={{ fontSize: 13 }}>
        {title} has no saved password. Enter one to connect.
      </span>
      <input
        aria-label="Password"
        style={input}
        type="password"
        autoComplete="current-password"
        autoFocus
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}>
        <input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} />
        Save it in SidiOS for this connection
      </label>
      <button type="submit" style={primaryBtn} disabled={!password}>
        Connect
      </button>
    </form>
  );
}
