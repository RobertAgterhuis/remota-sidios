import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { AboutDialog } from "../components/AboutDialog";

const commit = "98dce4cec360cc8626201cf7c0cb96e703455d65";

describe("about dialog", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("shows the running commit and links to that exact source", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          name: "Remota for SidiOS",
          version: "0.1.8",
          license: "AGPL-3.0-only",
          commit,
          source: `https://github.com/RobertAgterhuis/remota-sidios/tree/${commit}`,
        }),
      ),
    );
    const onClose = vi.fn();
    render(<AboutDialog onClose={onClose} />);
    expect(screen.getByRole("dialog", { name: "About Remota" })).toBeTruthy();
    expect(await screen.findByText(commit)).toBeTruthy();
    const link = screen.getByRole("link", { name: "Get the source code" });
    expect(link.getAttribute("href")).toBe(
      `https://github.com/RobertAgterhuis/remota-sidios/tree/${commit}`,
    );
    expect(link.getAttribute("rel")).toContain("noopener");
    expect(document.activeElement).toBe(
      screen.getByRole("button", { name: "Close" }),
    );
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });

  it("still offers the repository when the build information cannot be loaded", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(null, { status: 500 })),
    );
    render(<AboutDialog onClose={vi.fn()} />);
    expect((await screen.findByRole("alert")).textContent).toContain(
      "could not be loaded",
    );
    expect(
      screen
        .getByRole("link", { name: "Get the source code" })
        .getAttribute("href"),
    ).toBe("https://github.com/RobertAgterhuis/remota-sidios");
  });
});
