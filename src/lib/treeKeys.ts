import type { Node } from "./api";

/** A row the tree currently shows, in display order. */
export type Row = { node: Node; depth: number; parentId: string | null };

export function visibleRows(nodes: Node[], collapsed: Set<string>): Row[] {
  const rows: Row[] = [];
  const walk = (list: Node[], depth: number, parentId: string | null) => {
    for (const node of list) {
      rows.push({ node, depth, parentId });
      if (node.type === "folder" && !collapsed.has(node.id)) {
        walk(node.children, depth + 1, node.id);
      }
    }
  };
  walk(nodes, 0, null);
  return rows;
}

export type TreeAction =
  | { kind: "focus"; id: string }
  | { kind: "expand"; id: string }
  | { kind: "collapse"; id: string }
  | { kind: "open"; id: string }
  | { kind: "delete"; id: string }
  | { kind: "cut"; id: string }
  | { kind: "paste"; into: string | null }
  | { kind: "cancel" }
  | { kind: "menu"; id: string }
  | null;

type KeyInput = {
  key: string;
  ctrlKey?: boolean;
  metaKey?: boolean;
  shiftKey?: boolean;
};

/**
 * The tree's keyboard model (WAI-ARIA tree pattern plus cut and paste to move): arrows move and
 * open or close folders, Home and End jump, Enter opens, Delete trashes, Ctrl+X then Ctrl+V moves
 * the cut item into the focused folder (or the focused item's folder), Escape cancels.
 */
export function treeKeyAction(
  event: KeyInput,
  rows: Row[],
  focusId: string | null,
  collapsed: Set<string>,
): TreeAction {
  const index = rows.findIndex((row) => row.node.id === focusId);
  const row = rows[index];
  const command = event.ctrlKey || event.metaKey;
  if (!row) return rows[0] && isNavigation(event.key) ? focus(rows[0]) : null;
  if (command && event.key.toLowerCase() === "x") return { kind: "cut", id: row.node.id };
  if (command && event.key.toLowerCase() === "v") {
    return { kind: "paste", into: row.node.type === "folder" ? row.node.id : row.parentId };
  }
  switch (event.key) {
    case "ArrowDown":
      return rows[index + 1] ? focus(rows[index + 1]) : null;
    case "ArrowUp":
      return rows[index - 1] ? focus(rows[index - 1]) : null;
    case "Home":
      return focus(rows[0]);
    case "End":
      return focus(rows[rows.length - 1]);
    case "ArrowRight":
      return right(row, rows[index + 1], collapsed);
    case "ArrowLeft":
      return left(row, collapsed);
    case "Enter":
      return { kind: "open", id: row.node.id };
    case "Delete":
      return { kind: "delete", id: row.node.id };
    case "Escape":
      return { kind: "cancel" };
    case "ContextMenu":
      return { kind: "menu", id: row.node.id };
    case "F10":
      return event.shiftKey ? { kind: "menu", id: row.node.id } : null;
    default:
      return null;
  }
}

const focus = (row: Row): TreeAction => ({ kind: "focus", id: row.node.id });

function isNavigation(key: string): boolean {
  return ["ArrowDown", "ArrowUp", "Home", "End"].includes(key);
}

function right(row: Row, next: Row | undefined, collapsed: Set<string>): TreeAction {
  if (row.node.type !== "folder") return null;
  if (collapsed.has(row.node.id)) return { kind: "expand", id: row.node.id };
  return next && next.parentId === row.node.id ? focus(next) : null;
}

function left(row: Row, collapsed: Set<string>): TreeAction {
  const open = row.node.type === "folder" && !collapsed.has(row.node.id);
  if (open && row.node.type === "folder" && row.node.children.length > 0) {
    return { kind: "collapse", id: row.node.id };
  }
  return row.parentId ? { kind: "focus", id: row.parentId } : null;
}
