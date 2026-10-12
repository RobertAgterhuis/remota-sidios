import {
  type CSSProperties,
  type FormEvent,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import {
  ApiError,
  describe,
  type ImportReport,
  type ImportResult,
  transferApi,
} from "../lib/api";
import { colors, ghostBtn, input, label, primaryBtn } from "./styles";

export type ImportKind = "mremoteng" | "remota";

const reasons: Record<string, string> = {
  cipher_not_supported: "password not imported: cipher not supported",
  invalid_host: "host name is not valid",
  password_unreadable: "password could not be decrypted",
  protocol_not_supported: "protocol not supported",
  rdp_gateway_not_supported: "RD Gateway setting not imported",
  ssh_tunnel_not_supported: "SSH tunnel setting not imported",
};

export function describeSkip(reason: string, detail?: string): string {
  const text = reasons[reason] ?? "not imported";
  return detail ? `${text} (${detail})` : text;
}

/** Choose a file (and, for mRemoteNG, its master password), import it, and show the report. */
export function ImportDialog(props: {
  kind: ImportKind;
  onClose: () => void;
  onImported: (result: ImportResult) => void;
}) {
  const titleId = useId();
  const errorId = useId();
  const [file, setFile] = useState<File | null>(null);
  const [master, setMaster] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<ImportReport | null>(null);
  const first = useRef<HTMLInputElement>(null);
  const mremoteng = props.kind === "mremoteng";

  useEffect(() => first.current?.focus(), []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (file === null) return setError("Choose a file first.");
    setBusy(true);
    try {
      const result = mremoteng
        ? await transferApi.importMremoteng(file, master)
        : await transferApi.importRemota(file);
      setMaster("");
      setError("");
      setReport(result.report);
      props.onImported(result);
    } catch (caught) {
      setError(
        caught instanceof ApiError ? caught.message : describe("failed"),
      );
    } finally {
      setBusy(false);
    }
  }

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
          {mremoteng ? "Import from mRemoteNG" : "Import Remota JSON"}
        </h2>
        {report === null ? (
          <form
            onSubmit={(event) => void submit(event)}
            style={{ display: "grid", gap: 12 }}
          >
            <label style={{ display: "grid", gap: 4 }}>
              <span style={label}>
                {mremoteng ? "confCons.xml file" : "Remota JSON file"}
              </span>
              <input
                accept={
                  mremoteng
                    ? ".xml,text/xml,application/xml"
                    : ".json,application/json"
                }
                aria-describedby={error ? errorId : undefined}
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                ref={first}
                type="file"
              />
            </label>
            {mremoteng && (
              <label style={{ display: "grid", gap: 4 }}>
                <span style={label}>Master password</span>
                <input
                  aria-describedby={error ? errorId : undefined}
                  autoComplete="off"
                  onChange={(event) => setMaster(event.target.value)}
                  style={input}
                  type="password"
                  value={master}
                />
                <span style={{ fontSize: 12, color: colors.dim }}>
                  Leave empty if the file has no master password. Passwords are
                  decrypted on the server and stored in the SidiOS vault; delete
                  the source file afterwards.
                </span>
              </label>
            )}
            {!mremoteng && (
              <p style={{ fontSize: 12, color: colors.dim, margin: 0 }}>
                A Remota export contains no passwords; enter them again after
                importing.
              </p>
            )}
            {error && (
              <p
                id={errorId}
                role="alert"
                style={{ color: colors.danger, margin: 0, fontSize: 13 }}
              >
                {error}
              </p>
            )}
            <div
              style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}
            >
              <button onClick={props.onClose} style={ghostBtn} type="button">
                Cancel
              </button>
              <button disabled={busy} style={primaryBtn} type="submit">
                {busy ? "Importing…" : "Import"}
              </button>
            </div>
          </form>
        ) : (
          <ReportView onClose={props.onClose} report={report} />
        )}
      </div>
    </div>
  );
}

function ReportView(props: { report: ImportReport; onClose: () => void }) {
  const { report } = props;
  return (
    <div style={{ display: "grid", gap: 12 }}>
      <p role="status" style={{ margin: 0, fontSize: 13 }}>
        Imported {report.connections}{" "}
        {report.connections === 1 ? "connection" : "connections"} in{" "}
        {report.folders} {report.folders === 1 ? "folder" : "folders"}, with{" "}
        {report.passwords} {report.passwords === 1 ? "password" : "passwords"}.
      </p>
      {report.skipped.length > 0 && (
        <table
          aria-label="Not imported"
          style={{ fontSize: 13, borderCollapse: "collapse" }}
        >
          <thead>
            <tr>
              <th scope="col" style={cell}>
                Item
              </th>
              <th scope="col" style={cell}>
                Reason
              </th>
            </tr>
          </thead>
          <tbody>
            {report.skipped.map((skip, index) => (
              <tr key={`${skip.name}-${index}`}>
                <th scope="row" style={cell}>
                  {skip.name}
                </th>
                <td style={cell}>{describeSkip(skip.reason, skip.detail)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ display: "flex", justifyContent: "flex-end" }}>
        <button onClick={props.onClose} style={primaryBtn} type="button">
          Close
        </button>
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
  maxHeight: "calc(100vh - 32px)",
  overflow: "auto",
  display: "grid",
  gap: 16,
  color: colors.text,
};

const cell: CSSProperties = {
  textAlign: "left",
  padding: "4px 8px",
  borderBottom: `1px solid ${colors.border}`,
  fontWeight: "normal",
};
