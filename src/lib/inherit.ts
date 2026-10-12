import type { Credentials, Document, Gateway, Node } from "./api";

export type Source = { value: string; from: string };

/** What a connection or folder inherits, and from which folder, for the editors. */
export type Inherited = {
  username?: Source;
  domain?: Source;
  secret?: Source;
  gateway?: { value: Gateway; from: string };
};

/** The folders from the top level down to the parent of `id`, or null if `id` is not found. */
export function ancestors(doc: Document, id: string): Node[] | null {
  function walk(nodes: Node[], chain: Node[]): Node[] | null {
    for (const node of nodes) {
      if (node.id === id) return chain;
      if (node.type === "folder") {
        const found = walk(node.children, [...chain, node]);
        if (found) return found;
      }
    }
    return null;
  }
  return walk(doc.nodes, []);
}

/** The folders `parentId` and above, for a node that does not exist yet. */
export function chainFor(doc: Document, parentId: string | null): Node[] {
  if (parentId === null) return [];
  const above = ancestors(doc, parentId) ?? [];
  const parent = findFolder(doc.nodes, parentId);
  return parent ? [...above, parent] : above;
}

function findFolder(nodes: Node[], id: string): Node | null {
  for (const node of nodes) {
    if (node.type !== "folder") continue;
    if (node.id === id) return node;
    const found = findFolder(node.children, id);
    if (found) return found;
  }
  return null;
}

/** The nearest folder (deepest first) that sets each inheritable value. */
export function inheritedValues(chain: Node[]): Inherited {
  const result: Inherited = {};
  for (const folder of [...chain].reverse()) {
    if (folder.type !== "folder") continue;
    const d: Credentials = folder.defaults;
    result.username ??= d.username ? { value: d.username, from: folder.name } : undefined;
    result.domain ??= d.domain ? { value: d.domain, from: folder.name } : undefined;
    result.secret ??= d.credential_id ? { value: "saved", from: folder.name } : undefined;
    result.gateway ??= folder.gateway ? { value: folder.gateway, from: folder.name } : undefined;
  }
  return result;
}
