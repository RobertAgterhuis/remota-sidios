import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MenuBar } from "../components/MenuBar";

describe("menu bar", () => {
  it("opens with the keyboard, moves with arrows, runs an item, and closes on Escape", () => {
    const exportAll = vi.fn();
    render(
      <MenuBar
        menus={[
          {
            title: "File",
            items: [
              { label: "Import…", onClick: vi.fn() },
              "sep",
              { label: "Export…", onClick: exportAll },
            ],
          },
        ]}
      />,
    );
    const file = screen.getByRole("button", { name: "File" });
    expect(file.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(file);
    const menu = screen.getByRole("menu", { name: "File" });
    expect(document.activeElement).toBe(
      screen.getByRole("menuitem", { name: "Import…" }),
    );
    fireEvent.keyDown(menu, { key: "ArrowDown" });
    expect(document.activeElement).toBe(
      screen.getByRole("menuitem", { name: "Export…" }),
    );
    fireEvent.keyDown(menu, { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(document.activeElement).toBe(file);

    fireEvent.click(file);
    fireEvent.click(screen.getByRole("menuitem", { name: "Export…" }));
    expect(exportAll).toHaveBeenCalled();
    expect(screen.queryByRole("menu")).toBeNull();
  });
});
