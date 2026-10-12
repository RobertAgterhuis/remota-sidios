import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { ImportDialog } from "../components/ImportDialog";

const report = {
  folders: 3,
  connections: 4,
  passwords: 4,
  skipped: [{ name: "vnc-1", reason: "protocol_not_supported", detail: "VNC" }],
};

function respond(status: number, body: unknown) {
  return vi.fn(async () => Response.json(body, { status }));
}

function chooseFile() {
  const file = new File(["<Connections/>"], "confCons.xml", {
    type: "text/xml",
  });
  fireEvent.change(screen.getByLabelText("confCons.xml file"), {
    target: { files: [file] },
  });
}

describe("import dialog", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("sends the file and master password, then shows what was imported and skipped", async () => {
    const fetch = respond(200, {
      document: { nodes: [], trash: [] },
      report,
      folderId: "f",
    });
    vi.stubGlobal("fetch", fetch);
    const onImported = vi.fn();
    render(
      <ImportDialog
        kind="mremoteng"
        onClose={vi.fn()}
        onImported={onImported}
      />,
    );
    expect(
      screen.getByRole("dialog", { name: "Import from mRemoteNG" }),
    ).toBeTruthy();
    chooseFile();
    fireEvent.change(screen.getByLabelText(/Master password/), {
      target: { value: "master" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(onImported).toHaveBeenCalled());
    const [path, init] = fetch.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(path).toBe("/api/import/mremoteng");
    const form = init.body as FormData;
    expect(form.get("masterPassword")).toBe("master");
    expect((form.get("file") as File).name).toBe("confCons.xml");

    expect(screen.getByRole("status").textContent).toBe(
      "Imported 4 connections in 3 folders, with 4 passwords.",
    );
    const skipped = screen.getByRole("table", { name: "Not imported" });
    expect(
      within(skipped).getByRole("row", { name: /vnc-1/ }).textContent,
    ).toContain("protocol not supported (VNC)");
  });

  it("explains a wrong master password next to the field and imports nothing", async () => {
    vi.stubGlobal("fetch", respond(422, { code: "wrong_master_password" }));
    const onImported = vi.fn();
    render(
      <ImportDialog
        kind="mremoteng"
        onClose={vi.fn()}
        onImported={onImported}
      />,
    );
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe(
      "The master password is wrong. Nothing was imported.",
    );
    expect(
      screen.getByLabelText(/Master password/).getAttribute("aria-describedby"),
    ).toBe(alert.id);
    expect(onImported).not.toHaveBeenCalled();
  });

  it("omits an empty master password and closes on Escape", async () => {
    const fetch = respond(413, {});
    vi.stubGlobal("fetch", fetch);
    const onClose = vi.fn();
    render(
      <ImportDialog kind="mremoteng" onClose={onClose} onImported={vi.fn()} />,
    );
    chooseFile();
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    expect((await screen.findByRole("alert")).textContent).toBe(
      "The file is larger than 5 MB.",
    );
    const form = (fetch.mock.calls[0] as unknown as [string, RequestInit])[1]
      .body as FormData;
    expect(form.has("masterPassword")).toBe(false);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });
});
