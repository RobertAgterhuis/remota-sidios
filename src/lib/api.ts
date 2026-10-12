// Types mirroring the server's tree (remota-server/src/model.rs) and the HTTP API that replaces
// upstream's Tauri commands. SidiOS's gateway identifies the user on every request, so there is no
// sign-in or vault password here. Secrets are write-only: the editors may send `password`,
// `private_key`, and `passphrase`; the server seals them and answers only `credential_id`.
export type Protocol = "ssh" | "rdp";

export interface SecretFields {
  /** A sealed credential on the server; never its value. */
  credential_id?: string;
  /** Write-only: a new password to seal. */
  password?: string;
  /** Write-only: a new SSH private key (PEM or OpenSSH) to seal. */
  private_key?: string;
  /** Write-only: the private key's passphrase. */
  passphrase?: string;
}

export interface Credentials extends SecretFields {
  username?: string;
  domain?: string;
}

/** Jump host (SSH ProxyJump): the session is tunneled through this host. */
export interface Gateway extends SecretFields {
  host: string;
  port?: number;
  username?: string;
}

export interface Connection {
  protocol: Protocol;
  host: string;
  port?: number;
  credentials: Credentials;
  gateway?: Gateway;
}

// Internally tagged enum (#[serde(tag = "type")]) on the server.
export type Node =
  | {
      type: "folder";
      id: string;
      name: string;
      defaults: Credentials;
      gateway?: Gateway;
      icon?: string;
      children: Node[];
    }
  | { type: "connection"; id: string; name: string; conn: Connection };

/** A trashed node and the folder it came from. */
export interface TrashEntry {
  node: Node;
  parent_id?: string;
}

export interface Document {
  nodes: Node[];
  trash: TrashEntry[];
}

/** A refused request, with the server's code (for example `parent_not_found`). */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(describe(code));
  }
}

const messages: Record<string, string> = {
  forbidden: "You are not allowed to do that.",
  id_mismatch: "That item could not be saved.",
  invalid_host: "Enter a host name or address without spaces or a path.",
  invalid_id: "That item could not be saved.",
  invalid_jump_host: "Enter a jump host name or address without spaces or a path.",
  invalid_name: "Enter a name of at most 120 characters.",
  invalid_secret: "That password or key is empty or too large.",
  node_in_trash: "That item is in the Trash. Restore it first.",
  not_found: "It is no longer there.",
  parent_not_found: "That folder is no longer there.",
  too_deep: "Folders can be nested at most 10 levels deep.",
  too_many_nodes: "The tree is full (5,000 items).",
  unauthorized: "Your SidiOS session has ended. Reopen Remota.",
  unknown_credential: "That saved password is no longer available. Enter it again.",
  vault_unavailable: "SidiOS could not store the secret right now. Try again.",
};

export function describe(code: string): string {
  return messages[code] ?? "Something went wrong. Try again.";
}

export async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const response = await fetch(path, {
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    headers:
      body === undefined ? undefined : { "content-type": "application/json" },
    method,
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as {
      code?: unknown;
    };
    throw new ApiError(
      response.status,
      typeof payload.code === "string" ? payload.code : "failed",
    );
  }
  return (await response.json()) as T;
}

const segment = (id: string) => encodeURIComponent(id);

export const treeApi = {
  listTree: () => request<Document>("GET", "/api/tree"),
  saveNode: (parentId: string | null, node: Node) =>
    request<Document>("PUT", `/api/nodes/${segment(node.id)}`, {
      node,
      parentId,
    }),
  deleteNode: (id: string) =>
    request<Document>("DELETE", `/api/nodes/${segment(id)}`),
  restoreNode: (id: string) =>
    request<Document>("POST", `/api/trash/${segment(id)}/restore`),
  deleteForever: (id: string) =>
    request<Document>("DELETE", `/api/trash/${segment(id)}`),
  emptyTrash: () => request<Document>("DELETE", "/api/trash"),
};
