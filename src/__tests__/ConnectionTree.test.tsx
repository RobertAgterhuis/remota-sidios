import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ConnectionTree } from "../components/ConnectionTree";
import type { Document } from "../lib/api";

const doc: Document = {
  nodes: [
    {
      type: "folder",
      id: "lab",
      name: "Lab",
      defaults: {},
      children: [{ type: "connection", id: "web", name: "web", conn: { protocol: "ssh", host: "10.0.0.5", credentials: {} } }],
    },
    { type: "folder", id: "prod", name: "Prod", defaults: {}, children: [] },
  ],
  trash: [],
};

function renderTree() {
  const handlers = {
    onSelect: vi.fn(),
    onOpen: vi.fn(),
    onOpenNew: vi.fn(),
    onDelete: vi.fn(),
    onNewConnection: vi.fn(),
    onNewFolder: vi.fn(),
    onMove: vi.fn(),
  };
  render(<ConnectionTree doc={doc} selectedId={null} {...handlers} />);
  return handlers;
}

describe("connection tree", () => {
  it("is an ARIA tree with one tab stop", () => {
    renderTree();
    const items = screen.getAllByRole("treeitem");
    expect(screen.getByRole("tree", { name: "Connections" })).toBeTruthy();
    expect(items.map((item) => item.getAttribute("tabindex"))).toEqual(["0", "-1", "-1"]);
    expect(items[0]?.getAttribute("aria-level")).toBe("1");
    expect(items[1]?.getAttribute("aria-level")).toBe("2");
  });

  it("selects with the arrows, opens with Enter, and trashes with Delete", () => {
    const h = renderTree();
    const tree = screen.getByRole("tree");
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    expect(h.onSelect).toHaveBeenLastCalledWith(expect.objectContaining({ id: "web" }));
    fireEvent.keyDown(screen.getAllByRole("treeitem")[1]!, { key: "Enter" });
    expect(h.onOpen).toHaveBeenCalledWith(expect.objectContaining({ id: "web" }));
    fireEvent.keyDown(screen.getAllByRole("treeitem")[1]!, { key: "Delete" });
    expect(h.onDelete).toHaveBeenCalledWith("web");
  });

  it("moves an item with Ctrl+X and Ctrl+V", () => {
    const h = renderTree();
    const tree = screen.getByRole("tree");
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    fireEvent.keyDown(tree, { key: "x", ctrlKey: true });
    expect(screen.getByRole("status").textContent).toMatch(/web cut/);
    fireEvent.keyDown(tree, { key: "ArrowDown" });
    fireEvent.keyDown(tree, { key: "v", ctrlKey: true });
    expect(h.onMove).toHaveBeenCalledWith("web", "prod");
  });

  it("moves an item by drag and drop onto a folder", () => {
    const h = renderTree();
    const [lab, web, prod] = screen.getAllByRole("treeitem");
    const dataTransfer = { setData: vi.fn(), effectAllowed: "", dropEffect: "" };
    fireEvent.dragStart(web!, { dataTransfer });
    fireEvent.dragOver(prod!, { dataTransfer });
    fireEvent.drop(prod!, { dataTransfer });
    expect(h.onMove).toHaveBeenCalledWith("web", "prod");
    expect(lab).toBeTruthy();
  });

  it("collapses a folder with Left so its contents leave the tree", () => {
    renderTree();
    const tree = screen.getByRole("tree");
    fireEvent.keyDown(tree, { key: "ArrowLeft" });
    expect(screen.getAllByRole("treeitem").map((i) => i.textContent)).not.toContain("web");
    expect(screen.queryByText(/10\.0\.0\.5/)).toBeNull();
  });
});
