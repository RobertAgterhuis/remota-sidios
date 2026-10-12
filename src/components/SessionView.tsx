import type { SessionTab } from "../state/useSessions";
import { SshView } from "../renderers/SshView";
import { RdpView } from "../renderers/RdpView";
import { colors } from "./styles";

export function SessionView({
  tab,
  onDead,
}: {
  tab: SessionTab;
  onDead?: () => void;
}) {
  if (tab.error) {
    return (
      <div style={{ padding: 20 }}>
        <span
          style={{
            color: colors.danger,
            fontFamily: "monospace",
            fontSize: 12,
          }}
        >
          Failed to open session: {tab.error}
        </span>
      </div>
    );
  }

  if (tab.protocol === "ssh") {
    return <SshView key={tab.epoch} wsUrl={tab.wsUrl} onClosed={onDead} />;
  }

  if (tab.protocol === "rdp") {
    // RDP (beta): the gateway runs an RDCleanPath proxy; ironrdp-web does CredSSP/NLA.
    return (
      <RdpView
        key={tab.epoch}
        proxyUrl={tab.wsUrl}
        destination={tab.target}
        username={tab.username ?? ""}
        password={tab.password ?? ""}
        domain={tab.domain}
        onClosed={onDead}
      />
    );
  }

  return null;
}
