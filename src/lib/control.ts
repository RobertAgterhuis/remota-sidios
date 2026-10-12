/** A control message from the server (text frame); terminal output is always binary. */
// SSH session WebSocket: binary frames are terminal data; text frames are these JSON messages.
export type ControlMessage =
  | { type: "trust"; host: string; port: number; fingerprint: string }
  | { type: "error"; message: string };

export function parseControl(text: string): ControlMessage | null {
  try {
    const value = JSON.parse(text) as { type?: unknown };
    return value.type === "trust" || value.type === "error" ? (value as ControlMessage) : null;
  } catch {
    return null;
  }
}
