import {
  type CSSProperties,
  type KeyboardEvent,
  type MouseEvent,
  useEffect,
  useRef,
  useState,
} from "react";
import type { Connection, Credentials, Document, Node } from "../lib/api";
import { ContextMenu, type CtxItem } from "./ContextMenu";
import { colors } from "./styles";
import { treeKeyAction, visibleRows } from "../lib/treeKeys";

/** Todos os ids de pasta na árvore (para expand/collapse all). */
function allFolderIds(nodes: Node[]): string[] {
  const out: string[] = [];
  const walk = (ns: Node[]) => {
    for (const n of ns) {
      if (n.type === "folder") {
        out.push(n.id);
        walk(n.children);
      }
    }
  };
  walk(nodes);
  return out;
}

const protoColor: Record<string, string> = {
  ssh: colors.ssh,
  rdp: colors.rdp,
};

/** Username efetivo de uma conexão dada a cadeia de defaults das pastas-pai. */
function effectiveUser(
  chain: Credentials[],
  conn: Connection,
): { value?: string; inherited: boolean } {
  if (conn.credentials.username)
    return { value: conn.credentials.username, inherited: false };
  for (let i = chain.length - 1; i >= 0; i--) {
    if (chain[i].username) return { value: chain[i].username, inherited: true };
  }
  return { inherited: false };
}

type Dnd = {
  dragId: string | null;
  dropTarget: string | null; // id da pasta, ou "root"
  onStart: (id: string) => void;
  onOver: (target: string) => void;
  onLeave: () => void;
  onDrop: (parentId: string | null) => void;
};

type Props = {
  doc: Document;
  selectedId: string | null;
  onSelect: (node: Node) => void;
  onOpen: (node: Node) => void; // duplo-clique: volta à aba já aberta (ou abre)
  onOpenNew: (node: Node) => void; // força uma nova aba
  onDelete: (id: string) => void;
  onNewConnection: (parentId: string | null) => void;
  onNewFolder: (parentId: string | null) => void;
  onMove: (nodeId: string, targetParentId: string | null) => void;
};

export function ConnectionTree({
  doc,
  selectedId,
  onSelect,
  onOpen,
  onOpenNew,
  onDelete,
  onNewConnection,
  onNewFolder,
  onMove,
}: Props) {
  const [menu, setMenu] = useState<{
    x: number;
    y: number;
    items: CtxItem[];
  } | null>(null);
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  const [dragId, setDragId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [focusId, setFocusId] = useState<string | null>(selectedId);
  const [cutId, setCutId] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const treeRef = useRef<HTMLDivElement>(null);
  const rows = visibleRows(doc.nodes, collapsed);
  const tabStop =
    rows.find((row) => row.node.id === focusId)?.node.id ??
    rows.find((row) => row.node.id === selectedId)?.node.id ??
    rows[0]?.node.id ??
    null;

  useEffect(() => {
    if (selectedId) setFocusId(selectedId);
  }, [selectedId]);

  function focusRow(id: string) {
    setFocusId(id);
    const row = rows.find((r) => r.node.id === id);
    if (row) onSelect(row.node);
    requestAnimationFrame(() =>
      treeRef.current
        ?.querySelector<HTMLElement>(`[data-node-id="${CSS.escape(id)}"]`)
        ?.focus(),
    );
  }

  function onKeyDown(e: KeyboardEvent) {
    if ((e.target as HTMLElement).closest("button")) return;
    const action = treeKeyAction(e, rows, tabStop, collapsed);
    if (!action) return;
    e.preventDefault();
    const nodeOf = (id: string) => rows.find((r) => r.node.id === id)?.node;
    switch (action.kind) {
      case "focus":
        return focusRow(action.id);
      case "expand":
      case "collapse":
        return toggle(action.id);
      case "open": {
        const node = nodeOf(action.id);
        if (node?.type === "connection") onOpen(node);
        else if (node) toggle(node.id);
        return;
      }
      case "delete":
        return onDelete(action.id);
      case "cut":
        setCutId(action.id);
        setAnnouncement(`${nodeOf(action.id)?.name ?? "Item"} cut. Press Ctrl+V on a folder to move it.`);
        return;
      case "paste":
        if (cutId) {
          onMove(cutId, action.into);
          setAnnouncement("Moved.");
        }
        setCutId(null);
        return;
      case "cancel":
        setCutId(null);
        return;
      case "menu": {
        const element = treeRef.current?.querySelector<HTMLElement>(
          `[data-node-id="${CSS.escape(action.id)}"]`,
        );
        const rect = element?.getBoundingClientRect();
        const node = nodeOf(action.id);
        if (node && rect) setMenu({ x: rect.left + 24, y: rect.bottom, items: itemsFor(node) });
        return;
      }
    }
  }

  const dnd: Dnd = {
    dragId,
    dropTarget,
    onStart: (id) => setDragId(id),
    onOver: (target) => setDropTarget(target),
    onLeave: () => setDropTarget(null),
    onDrop: (parentId) => {
      if (dragId) onMove(dragId, parentId);
      setDragId(null);
      setDropTarget(null);
    },
  };

  function toggle(id: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const collapseAll = () => setCollapsed(new Set(allFolderIds(doc.nodes)));
  const expandAll = () => setCollapsed(new Set());
  const hasFolders = doc.nodes.some((n) => n.type === "folder");

  function itemsFor(node: Node | null): CtxItem[] {
    if (!node) {
      return [
        { label: "New connection", onClick: () => onNewConnection(null) },
        { label: "New folder", onClick: () => onNewFolder(null) },
      ];
    }
    if (node.type === "folder") {
      return [
        {
          label: "New connection here",
          onClick: () => onNewConnection(node.id),
        },
        { label: "New folder here", onClick: () => onNewFolder(node.id) },
        "sep",
        { label: "Edit", onClick: () => onSelect(node) },
        { label: "Delete", onClick: () => onDelete(node.id) },
      ];
    }
    return [
      { label: "Open", onClick: () => onOpen(node) },
      { label: "Open in new tab", onClick: () => onOpenNew(node) },
      { label: "Edit", onClick: () => onSelect(node) },
      "sep",
      { label: "Delete", onClick: () => onDelete(node.id) },
    ];
  }

  function openMenu(e: MouseEvent, node: Node | null) {
    e.preventDefault();
    e.stopPropagation();
    setMenu({ x: e.clientX, y: e.clientY, items: itemsFor(node) });
  }

  return (
    <div
      ref={treeRef}
      role="tree"
      aria-label="Connections"
      onKeyDown={onKeyDown}
      onContextMenu={(e) => openMenu(e, null)}
      onDragOver={(e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        setDropTarget("root");
      }}
      onDrop={(e) => {
        e.preventDefault();
        dnd.onDrop(null);
      }}
      style={{
        padding: 6,
        minHeight: "100%",
        outline: dropTarget === "root" ? `2px dashed ${colors.accent}` : undefined,
        outlineOffset: -2,
      }}
    >
      {hasFolders && (
        <div
          style={{
            display: "flex",
            gap: 6,
            justifyContent: "flex-end",
            padding: "0 2px 6px",
          }}
        >
          <button
            type="button"
            style={miniBtn}
            onClick={expandAll}
            title="Expand all folders"
          >
            Expand all
          </button>
          <button
            type="button"
            style={miniBtn}
            onClick={collapseAll}
            title="Collapse all folders"
          >
            Collapse all
          </button>
        </div>
      )}
      {doc.nodes.length === 0 ? (
        <div style={{ padding: 12, color: colors.dim, fontSize: 13 }}>
          Empty. Use File, New connection, or right-click here.
        </div>
      ) : (
        doc.nodes.map((n) => (
          <TreeNode
            key={n.id}
            node={n}
            depth={0}
            chain={[]}
            selectedId={selectedId}
            tabStop={tabStop}
            cutId={cutId}
            onFocusRow={setFocusId}
            collapsed={collapsed}
            onToggle={toggle}
            onSelect={onSelect}
            onOpen={onOpen}
            onDelete={onDelete}
            onContext={openMenu}
            dnd={dnd}
          />
        ))
      )}
      <div role="status" aria-live="polite" className="visually-hidden">
        {announcement}
      </div>
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          items={menu.items}
          onClose={() => setMenu(null)}
        />
      )}
    </div>
  );
}

function TreeNode({
  node,
  depth,
  chain,
  selectedId,
  tabStop,
  cutId,
  onFocusRow,
  collapsed,
  onToggle,
  onSelect,
  onOpen,
  onDelete,
  onContext,
  dnd,
}: {
  node: Node;
  depth: number;
  chain: Credentials[];
  selectedId: string | null;
  tabStop: string | null;
  cutId: string | null;
  onFocusRow: (id: string) => void;
  collapsed: Set<string>;
  onToggle: (id: string) => void;
  onSelect: (node: Node) => void;
  onOpen: (node: Node) => void;
  onDelete: (id: string) => void;
  onContext: (e: MouseEvent, node: Node) => void;
  dnd: Dnd;
}) {
  const pad = 8 + depth * 14;
  const itemProps = {
    role: "treeitem",
    "aria-level": depth + 1,
    "aria-selected": node.id === selectedId,
    "data-node-id": node.id,
    tabIndex: node.id === tabStop ? 0 : -1,
    onFocus: () => onFocusRow(node.id),
  } as const;
  const cut = node.id === cutId ? { opacity: 0.55 } : {};

  if (node.type === "folder") {
    const isCollapsed = collapsed.has(node.id);
    const hasChildren = node.children.length > 0;
    return (
      <div>
        <div
          {...itemProps}
          aria-expanded={hasChildren ? !isCollapsed : undefined}
          className="tree-row"
          draggable
          onDragStart={(e) => {
            e.stopPropagation();
            e.dataTransfer.setData("text/plain", node.id);
            e.dataTransfer.effectAllowed = "move";
            dnd.onStart(node.id);
          }}
          onDragOver={(e) => {
            e.preventDefault();
            e.stopPropagation();
            e.dataTransfer.dropEffect = "move";
            dnd.onOver(node.id);
          }}
          onDragLeave={() => dnd.onLeave()}
          onDrop={(e) => {
            e.preventDefault();
            e.stopPropagation();
            dnd.onDrop(node.id);
          }}
          onClick={() => onSelect(node)}
          onDoubleClick={() => onToggle(node.id)}
          onContextMenu={(e) => onContext(e, node)}
          style={{
            ...rowStyle(node.id === selectedId),
            paddingLeft: pad,
            cursor: "pointer",
            color: colors.dim,
            ...cut,
            ...(dnd.dropTarget === node.id
              ? { background: colors.selected, outline: `1px solid ${colors.accent}` }
              : {}),
          }}
        >
          <span
            style={{
              display: "flex",
              alignItems: "center",
              gap: 4,
              minWidth: 0,
            }}
          >
            <span
              onClick={(e) => {
                e.stopPropagation();
                if (hasChildren) onToggle(node.id);
              }}
              style={{
                width: 12,
                textAlign: "center",
                fontSize: 10,
                cursor: hasChildren ? "pointer" : "default",
              }}
            >
              {hasChildren ? (isCollapsed ? "▸" : "▾") : ""}
            </span>
            <span
              style={{
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {node.icon ?? "📁"} {node.name}
            </span>
          </span>
          <DeleteBtn
            onClick={(e) => {
              e.stopPropagation();
              onDelete(node.id);
            }}
          />
        </div>
        {!isCollapsed &&
          node.children.map((c) => (
            <TreeNode
              key={c.id}
              node={c}
              depth={depth + 1}
              chain={[...chain, node.defaults]}
              selectedId={selectedId}
              tabStop={tabStop}
              cutId={cutId}
              onFocusRow={onFocusRow}
              collapsed={collapsed}
              onToggle={onToggle}
              onSelect={onSelect}
              onOpen={onOpen}
              onDelete={onDelete}
              onContext={onContext}
              dnd={dnd}
            />
          ))}
      </div>
    );
  }

  const eu = effectiveUser(chain, node.conn);
  const selected = node.id === selectedId;
  return (
    <div
      {...itemProps}
      className="tree-row"
      draggable
      onDragStart={(e) => {
        e.stopPropagation();
        e.dataTransfer.setData("text/plain", node.id);
        e.dataTransfer.effectAllowed = "move";
        dnd.onStart(node.id);
      }}
      onClick={() => onSelect(node)}
      onDoubleClick={() => onOpen(node)}
      onContextMenu={(e) => onContext(e, node)}
      title="Double-click or Enter to open · drag or Ctrl+X, Ctrl+V to move · right-click or Shift+F10 for options"
      style={{ ...rowStyle(selected), ...cut, paddingLeft: pad, cursor: "pointer" }}
    >
      <span
        style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}
      >
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            color: protoColor[node.conn.protocol] ?? colors.dim,
            textTransform: "uppercase",
            width: 42,
          }}
        >
          {node.conn.protocol}
        </span>
        <span
          style={{
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {node.name}
          <span style={{ color: colors.dim }}> — {node.conn.host}</span>
          {eu.value && (
            <span
              style={{
                color: eu.inherited ? colors.dim : colors.text,
                fontStyle: eu.inherited ? "italic" : "normal",
              }}
            >
              {" "}
              ({eu.value}
              {eu.inherited ? " ↳inherited" : ""})
            </span>
          )}
        </span>
      </span>
      <DeleteBtn
        onClick={(e) => {
          e.stopPropagation();
          onDelete(node.id);
        }}
      />
    </div>
  );
}

function rowStyle(selected: boolean) {
  return {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 8,
    padding: "6px 8px",
    borderRadius: 6,
    fontSize: 13,
    color: colors.text,
    // Sem background quando não-selecionado, para o `.tree-row:hover` do CSS funcionar.
    ...(selected ? { background: colors.selected } : {}),
  } as const;
}

const miniBtn: CSSProperties = {
  background: "transparent",
  color: colors.dim,
  border: `1px solid ${colors.border}`,
  borderRadius: 5,
  padding: "2px 7px",
  fontSize: 11,
  cursor: "pointer",
};

function DeleteBtn({ onClick }: { onClick: (e: MouseEvent) => void }) {
  return (
    <button
      type="button"
      tabIndex={-1}
      aria-label="Move to Trash"
      onClick={onClick}
      title="Move to Trash (Delete)"
      style={{
        background: "transparent",
        border: "none",
        color: colors.dim,
        cursor: "pointer",
        fontSize: 14,
        lineHeight: 1,
      }}
    >
      ×
    </button>
  );
}
