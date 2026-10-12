import { useState } from "react";
import {
  type CertificateDecision,
  socketUrl,
  type OneTimeSecret,
  type SessionTab,
} from "../state/useSessions";
import { SshView } from "../renderers/SshView";
import { RdpView } from "../renderers/RdpView";
import { FtpView } from "../renderers/FtpView";
import { colors, ghostBtn, input, primaryBtn } from "./styles";

export function SessionView({
  tab,
  onDead,
  onRetry,
  onTrustCertificate,
  onForgetCertificate,
}: {
  tab: SessionTab;
  onDead?: () => void;
  onRetry: (secret?: OneTimeSecret) => void;
  onTrustCertificate: () => void;
  onForgetCertificate: () => void;
}) {
  if (tab.needsPassword)
    return <PasswordPrompt title={tab.title} onSubmit={onRetry} />;
  if (tab.certificate) {
    return (
      <CertificatePrompt
        title={tab.title}
        decision={tab.certificate}
        onTrust={onTrustCertificate}
        onForget={onForgetCertificate}
      />
    );
  }
  if (tab.error) {
    return (
      <div
        role="alert"
        style={{ padding: 20, display: "grid", gap: 12, justifyItems: "start" }}
      >
        <span style={{ color: colors.danger, fontSize: 13 }}>{tab.error}</span>
        <button type="button" style={ghostBtn} onClick={() => onRetry()}>
          Try again
        </button>
      </div>
    );
  }
  if (!tab.start) {
    return (
      <div
        role="status"
        style={{ padding: 20, color: colors.dim, fontSize: 13 }}
      >
        Connecting…
      </div>
    );
  }
  if (tab.protocol === "ssh") {
    return (
      <SshView key={tab.epoch} wsUrl={socketUrl(tab.start)} onClosed={onDead} />
    );
  }
  if (tab.protocol === "ftp" || tab.protocol === "ftps") {
    return (
      <FtpView
        key={tab.epoch}
        wsUrl={socketUrl(tab.start)}
        sessionId={tab.start.sessionId}
        secure={tab.start.secure === true}
        onClosed={onDead}
      />
    );
  }
  return (
    <RdpView
      key={tab.epoch}
      proxyUrl={socketUrl(tab.start)}
      login={tab.start.rdpSessionLogin}
      clipboard={tab.start.clipboard === true}
      onClosed={onDead}
    />
  );
}

/**
 * An RDP or FTPS server's certificate, decided like an SSH host key: a first-seen one is trusted after
 * the user compares its fingerprint; a changed one is never accepted in one step.
 */
function CertificatePrompt({
  title,
  decision,
  onTrust,
  onForget,
}: {
  title: string;
  decision: CertificateDecision;
  onTrust: () => void;
  onForget: () => void;
}) {
  const changed = decision.kind === "changed";
  return (
    <div
      role="alertdialog"
      aria-labelledby="certificate-title"
      aria-describedby="certificate-text"
      style={{ padding: 20, display: "grid", gap: 12, maxWidth: 520 }}
    >
      <strong id="certificate-title" style={{ fontSize: 14 }}>
        {changed ? `${title}: the certificate changed` : `Trust ${title}?`}
      </strong>
      <span
        id="certificate-text"
        style={{ fontSize: 13, color: changed ? colors.danger : colors.text }}
      >
        {changed
          ? "The server presents a different certificate than the one you trusted. This can mean someone is intercepting the connection. Ask the server's owner to confirm the new fingerprint before you forget the old certificate."
          : "Compare this fingerprint with the one the server's owner gave you before connecting."}
      </span>
      <code style={{ fontSize: 12, overflowWrap: "anywhere" }}>
        {decision.fingerprint}
      </code>
      <div style={{ display: "flex", gap: 8 }}>
        {changed ? (
          <button type="button" style={ghostBtn} onClick={onForget}>
            Forget the old certificate
          </button>
        ) : (
          <button type="button" style={primaryBtn} onClick={onTrust}>
            Trust and connect
          </button>
        )}
      </div>
    </div>
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
      <label
        style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}
      >
        <input
          type="checkbox"
          checked={save}
          onChange={(e) => setSave(e.target.checked)}
        />
        Save it in SidiOS for this connection
      </label>
      <button type="submit" style={primaryBtn} disabled={!password}>
        Connect
      </button>
    </form>
  );
}
