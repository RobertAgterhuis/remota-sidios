import { type CSSProperties, type ReactNode, useState } from "react";
import { useTree } from "./state/useTree";
import { useSessions } from "./state/useSessions";
import { ConnectionTree } from "./components/ConnectionTree";
import { ConnectionEditor } from "./components/ConnectionEditor";
import { FolderEditor } from "./components/FolderEditor";
import { TabBar } from "./components/TabBar";
import { SessionView } from "./components/SessionView";
import { TrashPanel } from "./components/TrashPanel";
import { MenuBar, type Menu } from "./components/MenuBar";
import {
  findConnWithChain,
  findNode,
  findParentId,
  isInSubtree,
  nodeExists,
} from "./lib/tree";
import { ancestors, chainFor, inheritedValues } from "./lib/inherit";
import type { Node } from "./lib/api";
import { colors } from "./components/styles";
import { downloadFile } from "./lib/browserFiles";
import { ImportDialog, type ImportKind } from "./components/ImportDialog";
import { AboutDialog } from "./components/AboutDialog";

type Editing = {
  kind: "connection" | "folder";
  node: Node | null;
  parentId: string | null;
};

export default function App() {
  const v = useTree();
  const s = useSessions();
  const [editing, setEditing] = useState<Editing>({
    kind: "connection",
    node: null,
    parentId: null,
  });
  const [active, setActive] = useState<string>("editor");
  const [notice, setNotice] = useState<string | null>(null);
  const [importing, setImporting] = useState<ImportKind | null>(null);
  const [showAbout, setShowAbout] = useState(false);

  if (v.status === "loading") return <Center>Loading your connections…</Center>;
  if (v.status === "error")
    return (
      <Center>
        <div role="alert" style={{ display: "grid", gap: 12, justifyItems: "center" }}>
          <span>{v.error ?? "Your connections could not be loaded."}</span>
          <button style={toolBtn} onClick={() => void v.refresh()}>
            Try again
          </button>
        </div>
      </Center>
    );

  const selected = editing.node;
  // novo nó vai dentro da pasta selecionada (se houver), senão na raiz.
  const targetParent = selected?.type === "folder" ? selected.id : null;

  function selectNode(n: Node) {
    setEditing({
      kind: n.type === "folder" ? "folder" : "connection",
      node: n,
      parentId: findParentId(v.tree, n.id),
    });
    setActive("editor");
  }
  function newConnectionAt(parentId: string | null) {
    setEditing({ kind: "connection", node: null, parentId });
    setActive("editor");
  }
  function newFolderAt(parentId: string | null) {
    setEditing({ kind: "folder", node: null, parentId });
    setActive("editor");
  }
  const newConnection = () => newConnectionAt(targetParent);
  const newFolder = () => newFolderAt(targetParent);
  // Where empty fields of the edited node would come from.
  const inherited = inheritedValues(
    editing.node
      ? (ancestors(v.tree, editing.node.id) ?? chainFor(v.tree, editing.parentId))
      : chainFor(v.tree, editing.parentId),
  );

  async function guarded(action: () => Promise<void>) {
    try {
      await action();
    } catch (e) {
      setNotice(e instanceof Error ? e.message : String(e));
    }
  }

  async function saveNode(n: Node) {
    // mantém o nó no lugar: existente → pai atual; novo → pai-alvo da criação.
    const parentId = nodeExists(v.tree, n.id)
      ? findParentId(v.tree, n.id)
      : editing.parentId;
    await v.save(parentId, n);
    setEditing({
      kind: n.type === "folder" ? "folder" : "connection",
      node: n,
      parentId,
    });
  }

  async function openConn(id: string, forceNew = false) {
    // Duplo-clique: se já há uma aba aberta desta conexão, volta a ela (não abre outra).
    if (!forceNew) {
      const existing = s.tabs.find((t) => t.connId === id);
      if (existing) {
        setActive(existing.id);
        return;
      }
    }
    // The server resolves inheritance, checks the policy, and issues a single-use ticket.
    const found = findConnWithChain(v.tree, id);
    if (!found) return;
    const newId = await s.openSession({
      connId: id,
      title: found.node.name,
      protocol: found.node.conn.protocol,
    });
    setActive(newId);
  }
  function closeTab(id: string) {
    s.closeSession(id);
    setActive((cur) => (cur === id ? "editor" : cur));
  }

  // Arrastar um nó para dentro de uma pasta (ou raiz). O backend (upsert) trata do mover.
  async function moveNode(nodeId: string, targetParentId: string | null) {
    if (nodeId === targetParentId) return;
    const node = findNode(v.tree, nodeId);
    if (!node) return;
    if (findParentId(v.tree, nodeId) === targetParentId) return; // já está lá
    if (
      node.type === "folder" &&
      targetParentId &&
      isInSubtree(node, targetParentId)
    )
      return; // evita ciclo
    await guarded(() => v.save(targetParentId, node));
  }

  async function exportConnections() {
    try {
      await downloadFile("/api/export", "remota-export.json");
      setNotice("Connections exported, without passwords.");
    } catch {
      setNotice("Export failed. Try again.");
    }
  }

  async function deleteNode(id: string) {
    const node = findNode(v.tree, id);
    const name = node?.name ?? "este item";
    const isFolder = node?.type === "folder";
    const msg = isFolder
      ? `Move the folder "${name}" and its contents to the Trash?`
      : `Move the connection "${name}" to the Trash?`;
    const ok = window.confirm(msg);
    if (!ok) return;
    await guarded(() => v.remove(id)); // soft delete: to the Trash, restorable
    if (selected?.id === id)
      setEditing({ kind: "connection", node: null, parentId: null });
  }

  async function deleteForever(id: string) {
    const ok = window.confirm(
      "Delete this item permanently? This cannot be undone.",
    );
    if (ok) await guarded(() => v.deleteForever(id));
  }
  async function emptyTrash() {
    const ok = window.confirm(
      "Permanently delete everything in the Trash? This cannot be undone.",
    );
    if (ok) await guarded(() => v.emptyTrash());
  }

  const menus: Menu[] = [
    {
      title: "File",
      items: [
        { label: "New connection", onClick: newConnection },
        { label: "New folder", onClick: newFolder },
        "sep",
        {
          label: "Import from mRemoteNG (confCons.xml)…",
          onClick: () => setImporting("mremoteng"),
        },
        {
          label: "Import connections (Remota JSON)…",
          onClick: () => setImporting("remota"),
        },
        { label: "Export connections (JSON)…", onClick: exportConnections },
      ],
    },
    {
      title: "Help",
      items: [
        {
          label: "About Remota",
          onClick: () => setShowAbout(true),
        },
      ],
    },
  ];

  return (
    <div style={shell}>
      <MenuBar menus={menus} />
      {showAbout && <AboutDialog onClose={() => setShowAbout(false)} />}
      {importing && (
        <ImportDialog
          kind={importing}
          onClose={() => setImporting(null)}
          onImported={() => void v.refresh()}
        />
      )}
      <div aria-hidden style={{ height: 2, background: colors.accent }} />

      <div style={toolbar}>
        <strong style={{ fontSize: 14, letterSpacing: 0.3 }}>Remota</strong>
        <div
          style={{
            width: 1,
            height: 18,
            background: colors.border,
            margin: "0 6px",
          }}
        />
        <button style={toolBtn} onClick={newConnection}>
          + Connection
        </button>
        <button style={toolBtn} onClick={newFolder}>
          + Folder
        </button>
      </div>

      {notice && (
        <div style={banner} role="status">
          <span style={{ fontSize: 13 }}>{notice}</span>
          <button
            aria-label="Dismiss"
            onClick={() => setNotice(null)}
            style={{ ...toolBtn, marginLeft: "auto" }}
          >
            ×
          </button>
        </div>
      )}

      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        <aside style={sidebar}>
          <div style={sidebarHead}>Connections</div>
          <div style={{ flex: 1, overflow: "auto", minHeight: 0 }}>
            <ConnectionTree
              doc={v.tree}
              selectedId={selected?.id ?? null}
              onSelect={selectNode}
              onOpen={(n) => {
                if (n.type === "connection") openConn(n.id);
              }}
              onOpenNew={(n) => {
                if (n.type === "connection") openConn(n.id, true);
              }}
              onDelete={deleteNode}
              onNewConnection={newConnectionAt}
              onNewFolder={newFolderAt}
              onMove={moveNode}
            />
          </div>
          <TrashPanel
            trash={v.tree.trash ?? []}
            onRestore={(id) => guarded(() => v.restore(id))}
            onDeleteForever={deleteForever}
            onEmpty={emptyTrash}
          />
        </aside>

        <main
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            minWidth: 0,
          }}
        >
          <TabBar
            tabs={s.tabs}
            activeId={active}
            onActivate={setActive}
            onClose={closeTab}
            onReconnect={s.reconnect}
            onDuplicate={async (id) => {
              const nid = await s.duplicate(id);
              if (nid) setActive(nid);
            }}
          />
          <div style={{ flex: 1, position: "relative", minHeight: 0 }}>
            <div
              style={{
                ...pane,
                overflow: "auto",
                display: active === "editor" ? "block" : "none",
              }}
            >
              {editing.kind === "folder" ? (
                <FolderEditor node={editing.node} inherited={inherited} onSave={saveNode} />
              ) : (
                <ConnectionEditor
                  node={editing.node}
                  inherited={inherited}
                  onSave={saveNode}
                  onConnect={openConn}
                />
              )}
            </div>
            {s.tabs.map((t) => (
              <div
                key={t.id}
                style={{ ...pane, display: active === t.id ? "block" : "none" }}
              >
                <SessionView
                  tab={t}
                  onDead={() => s.markDead(t.id)}
                  onRetry={(secret) => void s.reconnect(t.id, secret)}
                  onTrustCertificate={() => void s.trustCertificate(t.id)}
                  onForgetCertificate={() => void s.forgetCertificate(t.id)}
                />
              </div>
            ))}
          </div>
        </main>
      </div>

      <footer style={statusbar}>
        <span style={{ color: colors.success }}>● Signed in through SidiOS</span>
        <Sep />
        <span>
          {s.tabs.length}{" "}
          {s.tabs.length === 1 ? "open session" : "open sessions"}
        </span>
      </footer>
    </div>
  );
}

function Sep() {
  return <span style={{ color: colors.border }}>│</span>;
}

function Center({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        height: "100vh",
        display: "grid",
        placeItems: "center",
        background: colors.bg,
        color: colors.dim,
      }}
    >
      {children}
    </div>
  );
}

const shell: CSSProperties = {
  height: "100vh",
  display: "flex",
  flexDirection: "column",
  background: colors.bg,
  color: colors.text,
};
const toolbar: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 6,
  padding: "6px 10px",
  borderBottom: `1px solid ${colors.border}`,
  background: colors.panel,
};
const toolBtn: CSSProperties = {
  background: "transparent",
  color: colors.dim,
  border: `1px solid ${colors.border}`,
  borderRadius: "var(--radius-sm)",
  padding: "4px 10px",
  fontSize: 12,
  cursor: "pointer",
};
const banner: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  padding: "8px 12px",
  background: colors.raised,
  borderBottom: `1px solid ${colors.border}`,
  color: colors.text,
};
const sidebar: CSSProperties = {
  width: 320,
  borderRight: `1px solid ${colors.border}`,
  overflow: "hidden",
  display: "flex",
  flexDirection: "column",
};
const sidebarHead: CSSProperties = {
  padding: "8px 12px",
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: 0.6,
  color: colors.dim,
  borderBottom: `1px solid ${colors.border}`,
};
const pane: CSSProperties = { position: "absolute", inset: 0 };
const statusbar: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  padding: "4px 12px",
  borderTop: `1px solid ${colors.border}`,
  background: colors.panel,
  color: colors.dim,
  fontSize: 12,
};
