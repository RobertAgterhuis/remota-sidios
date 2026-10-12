import { useCallback, useEffect, useState } from "react";
import { type Document, type Node, treeApi } from "../lib/api";

export type TreeStatus = "loading" | "ready" | "error";

/**
 * The signed-in user's connection tree, kept on the server. Every change answers the whole tree
 * afterwards, so the view always shows what the server stored.
 */
export function useTree() {
  const [status, setStatus] = useState<TreeStatus>("loading");
  const [tree, setTree] = useState<Document>({ nodes: [], trash: [] });
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setTree(await treeApi.listTree());
      setError(null);
      setStatus("ready");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStatus((current) => (current === "ready" ? current : "error"));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const apply = useCallback(async (change: () => Promise<Document>) => {
    try {
      setTree(await change());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      throw e;
    }
  }, []);

  const save = useCallback(
    (parentId: string | null, node: Node) =>
      apply(() => treeApi.saveNode(parentId, node)),
    [apply],
  );
  const remove = useCallback(
    (id: string) => apply(() => treeApi.deleteNode(id)),
    [apply],
  );
  const restore = useCallback(
    (id: string) => apply(() => treeApi.restoreNode(id)),
    [apply],
  );
  const deleteForever = useCallback(
    (id: string) => apply(() => treeApi.deleteForever(id)),
    [apply],
  );
  const emptyTrash = useCallback(
    () => apply(() => treeApi.emptyTrash()),
    [apply],
  );

  return {
    status,
    tree,
    error,
    refresh,
    save,
    remove,
    restore,
    deleteForever,
    emptyTrash,
  };
}
