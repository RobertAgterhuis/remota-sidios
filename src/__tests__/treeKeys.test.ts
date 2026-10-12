import { describe, expect, it } from "vitest";
import type { Node } from "../lib/api";
import { treeKeyAction, visibleRows } from "../lib/treeKeys";

const conn = (id: string): Node => ({
  type: "connection",
  id,
  name: id,
  conn: { protocol: "ssh", host: "h", credentials: {} },
});
const folder = (id: string, children: Node[]): Node => ({
  type: "folder",
  id,
  name: id,
  defaults: {},
  children,
});

const nodes = [folder("lab", [conn("web"), folder("deep", [conn("db")])]), conn("solo")];
const open = new Set<string>();
const rows = visibleRows(nodes, open);
const key = (k: string, extra = {}) => ({ key: k, ...extra });

describe("tree keyboard model", () => {
  it("lists visible rows in order and hides collapsed folders' contents", () => {
    expect(rows.map((r) => r.node.id)).toEqual(["lab", "web", "deep", "db", "solo"]);
    expect(visibleRows(nodes, new Set(["lab"])).map((r) => r.node.id)).toEqual(["lab", "solo"]);
    expect(rows.find((r) => r.node.id === "db")).toMatchObject({ depth: 2, parentId: "deep" });
  });

  it("moves with the arrows, Home, and End", () => {
    expect(treeKeyAction(key("ArrowDown"), rows, "lab", open)).toEqual({ kind: "focus", id: "web" });
    expect(treeKeyAction(key("ArrowUp"), rows, "web", open)).toEqual({ kind: "focus", id: "lab" });
    expect(treeKeyAction(key("ArrowUp"), rows, "lab", open)).toBeNull();
    expect(treeKeyAction(key("End"), rows, "lab", open)).toEqual({ kind: "focus", id: "solo" });
    expect(treeKeyAction(key("Home"), rows, "solo", open)).toEqual({ kind: "focus", id: "lab" });
  });

  it("starts at the first row when nothing has focus", () => {
    expect(treeKeyAction(key("ArrowDown"), rows, null, open)).toEqual({ kind: "focus", id: "lab" });
    expect(treeKeyAction(key("Enter"), rows, null, open)).toBeNull();
  });

  it("opens and closes folders with Right and Left, then moves in and out", () => {
    const closed = new Set(["deep"]);
    const closedRows = visibleRows(nodes, closed);
    expect(treeKeyAction(key("ArrowRight"), closedRows, "deep", closed)).toEqual({ kind: "expand", id: "deep" });
    expect(treeKeyAction(key("ArrowRight"), rows, "deep", open)).toEqual({ kind: "focus", id: "db" });
    expect(treeKeyAction(key("ArrowLeft"), rows, "deep", open)).toEqual({ kind: "collapse", id: "deep" });
    expect(treeKeyAction(key("ArrowLeft"), rows, "db", open)).toEqual({ kind: "focus", id: "deep" });
    expect(treeKeyAction(key("ArrowRight"), rows, "web", open)).toBeNull();
  });

  it("opens, trashes, and offers the context menu", () => {
    expect(treeKeyAction(key("Enter"), rows, "web", open)).toEqual({ kind: "open", id: "web" });
    expect(treeKeyAction(key("Delete"), rows, "web", open)).toEqual({ kind: "delete", id: "web" });
    expect(treeKeyAction(key("F10", { shiftKey: true }), rows, "web", open)).toEqual({ kind: "menu", id: "web" });
    expect(treeKeyAction(key("ContextMenu"), rows, "web", open)).toEqual({ kind: "menu", id: "web" });
  });

  it("moves by cut and paste into the focused folder or the focused item's folder", () => {
    expect(treeKeyAction(key("x", { ctrlKey: true }), rows, "solo", open)).toEqual({ kind: "cut", id: "solo" });
    expect(treeKeyAction(key("v", { ctrlKey: true }), rows, "deep", open)).toEqual({ kind: "paste", into: "deep" });
    expect(treeKeyAction(key("v", { metaKey: true }), rows, "web", open)).toEqual({ kind: "paste", into: "lab" });
    expect(treeKeyAction(key("v", { ctrlKey: true }), rows, "solo", open)).toEqual({ kind: "paste", into: null });
    expect(treeKeyAction(key("Escape"), rows, "solo", open)).toEqual({ kind: "cancel" });
  });
});
