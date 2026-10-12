import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { crumbs, FtpView, formatSize, joinPath, parentPath } from "../renderers/FtpView";
import { ConnectionEditor } from "../components/ConnectionEditor";

/** A WebSocket the test drives: it records what the page sends and answers like the server. */
class FakeSocket {
  static last: FakeSocket | null = null;
  static OPEN = 1;
  readyState = 1;
  sent: Record<string, unknown>[] = [];
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: ((ev: { reason: string }) => void) | null = null;
  constructor(readonly url: string) {
    FakeSocket.last = this;
  }
  send(data: string) {
    this.sent.push(JSON.parse(data));
  }
  close() {
    this.readyState = 3;
  }
  receive(message: unknown) {
    act(() => this.onmessage?.({ data: JSON.stringify(message) }));
  }
  /** Answers the last command. */
  answer(result: Record<string, unknown>) {
    const id = this.sent[this.sent.length - 1]?.id;
    this.receive({ type: "result", id, ok: true, ...result });
  }
}

function lastSent(socket: FakeSocket): Record<string, unknown> {
  return socket.sent[socket.sent.length - 1]!;
}

const listing = {
  path: "/srv",
  entries: [
    { name: "logs", kind: "dir", size: 0 },
    { name: "a b.txt", kind: "file", size: 2048 },
  ],
};

async function flush() {
  await act(async () => {
    await Promise.resolve();
  });
}

beforeEach(() => {
  vi.stubGlobal("WebSocket", FakeSocket);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("FTP paths", () => {
  it("joins, climbs, and splits paths", () => {
    expect(joinPath("/", "a")).toBe("/a");
    expect(joinPath("/srv", "a")).toBe("/srv/a");
    expect(parentPath("/srv/logs")).toBe("/srv");
    expect(parentPath("/srv")).toBe("/");
    expect(parentPath("/")).toBe("/");
    expect(crumbs("/srv/logs").map((c) => c.path)).toEqual(["/", "/srv", "/srv/logs"]);
    expect(formatSize(2048)).toBe("2.0 KB");
  });
});

describe("FtpView", () => {
  it("lists the start folder, opens folders, and goes up by keyboard", async () => {
    render(<FtpView wsUrl="ws://x/session/s?ticket=t" sessionId="s" secure />);
    const socket = FakeSocket.last!;
    socket.receive({ type: "ready", start: "/srv", secure: true });
    expect(lastSent(socket)).toMatchObject({ op: "list", path: "/srv" });
    socket.answer(listing);
    await flush();
    const table = screen.getByRole("table", { name: "Files in /srv" });
    expect(within(table).getByText("a b.txt")).toBeTruthy();
    expect(screen.queryByRole("note")).toBeNull();

    const folder = within(table).getByText("logs").closest("tr")!;
    fireEvent.keyDown(folder, { key: "Enter" });
    expect(lastSent(socket)).toMatchObject({ op: "list", path: "/srv/logs" });
    socket.answer({ path: "/srv/logs", entries: [] });
    await flush();
    expect(screen.getByText("This folder is empty.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Up" }));
    expect(lastSent(socket)).toMatchObject({ op: "list", path: "/srv" });
  });

  it("warns about plain FTP", () => {
    render(<FtpView wsUrl="ws://x" sessionId="s" secure={false} />);
    expect(screen.getByRole("note").textContent).toMatch(/unencrypted/u);
  });

  it("creates folders, renames, and deletes after confirming", async () => {
    render(<FtpView wsUrl="ws://x" sessionId="s" secure />);
    const socket = FakeSocket.last!;
    socket.receive({ type: "ready", start: "/srv" });
    socket.answer(listing);
    await flush();

    fireEvent.click(screen.getByRole("button", { name: "New folder" }));
    fireEvent.change(screen.getByLabelText("Folder name"), { target: { value: "new" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(lastSent(socket)).toMatchObject({ op: "mkdir", path: "/srv/new" });
    socket.answer({});
    await flush();
    socket.answer(listing);
    await flush();

    const file = screen.getByText("a b.txt").closest("tr")!;
    fireEvent.click(file);
    fireEvent.keyDown(file, { key: "F2" });
    fireEvent.change(screen.getByLabelText("New name"), { target: { value: "c.txt" } });
    fireEvent.click(
      within(screen.getByRole("form", { name: "Rename a b.txt" })).getByRole("button", { name: "Rename" }),
    );
    expect(lastSent(socket)).toMatchObject({ op: "rename", from: "/srv/a b.txt", to: "/srv/c.txt" });
    socket.receive({ type: "result", id: lastSent(socket).id, ok: false, code: "server_error", message: "553 Not allowed" });
    await flush();
    expect(screen.getByRole("alert").textContent).toBe("The server answered: 553 Not allowed");

    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const sent = socket.sent.length;
    fireEvent.keyDown(file, { key: "Delete" });
    expect(confirm).toHaveBeenCalled();
    expect(socket.sent.length).toBe(sent);
    confirm.mockReturnValue(true);
    fireEvent.keyDown(file, { key: "Delete" });
    expect(lastSent(socket)).toMatchObject({ op: "delete", path: "/srv/a b.txt", folder: false });
  });

  it("downloads and uploads through the session's transfer routes", async () => {
    const fetchMock = vi.fn(async () => Response.json({ size: 3 }, { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    render(<FtpView wsUrl="ws://x" sessionId="s-1" secure />);
    const socket = FakeSocket.last!;
    socket.receive({ type: "ready", start: "/srv" });
    socket.answer(listing);
    await flush();

    fireEvent.keyDown(screen.getByText("a b.txt").closest("tr")!, { key: "Enter" });
    const link = click.mock.contexts[0] as HTMLAnchorElement;
    expect(new URL(link.href).pathname + new URL(link.href).search).toBe(
      "/api/ftp/s-1/download?path=%2Fsrv%2Fa%20b.txt",
    );

    const file = new File(["abc"], "up.txt");
    fireEvent.change(screen.getByLabelText("Files to upload"), { target: { files: [file] } });
    await flush();
    await flush();
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/ftp/s-1/upload?path=%2Fsrv%2Fup.txt");
    expect(init.method).toBe("PUT");
    expect(init.body).toBe(file);
  });

  it("refuses files larger than 1 GB before sending them", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<FtpView wsUrl="ws://x" sessionId="s" secure />);
    const socket = FakeSocket.last!;
    socket.receive({ type: "ready", start: "/" });
    socket.answer({ path: "/", entries: [] });
    await flush();
    const big = new File(["x"], "big.iso");
    Object.defineProperty(big, "size", { value: 1024 ** 3 + 1 });
    fireEvent.change(screen.getByLabelText("Files to upload"), { target: { files: [big] } });
    await flush();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toBe("big.iso is larger than 1 GB.");
  });
});

describe("FTP connections in the editor", () => {
  it("warns about plain FTP and offers neither keys nor a jump host", () => {
    render(
      <ConnectionEditor
        node={{
          type: "connection",
          id: "f",
          name: "files",
          conn: { protocol: "ftp", host: "files.example", credentials: {} },
        }}
        inherited={{}}
        onSave={async () => {}}
      />,
    );
    expect(screen.getByRole("note").textContent).toMatch(/unencrypted/u);
    expect(screen.queryByText(/jump host/iu)).toBeNull();
    expect(screen.queryByText(/private key/iu)).toBeNull();
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "ftps" } });
    expect(screen.queryByRole("note")).toBeNull();
    expect(screen.getByText(/implicit on port 990/u)).toBeTruthy();
  });
});

describe("HTTPS connections in the editor", () => {
  it("splits a pasted https:// address into host, port, and path", async () => {
    const onSave = vi.fn(async () => {});
    render(<ConnectionEditor node={null} inherited={{}} onSave={onSave} />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "pve" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "https" } });
    fireEvent.change(screen.getByLabelText("Host"), {
      target: { value: "https://pve-node00.example.com:8006/ui/" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await flush();
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({
        conn: expect.objectContaining({
          protocol: "https",
          host: "pve-node00.example.com",
          port: 8006,
          path: "/ui/",
        }),
      }),
    );
  });
});

describe("SFTP in the file browser", () => {
  it("asks about a first-seen host key and sends the answer", () => {
    render(<FtpView wsUrl="ws://x" sessionId="s" secure />);
    const socket = FakeSocket.last!;
    socket.receive({ type: "trust", host: "files.example.com", port: 22, fingerprint: "SHA256:abc" });
    const dialog = screen.getByRole("alertdialog");
    expect(dialog.textContent).toContain("SHA256:abc");
    fireEvent.click(within(dialog).getByRole("button", { name: "Trust and connect" }));
    expect(lastSent(socket)).toEqual({ type: "trust", accept: true });
    expect(screen.queryByRole("alertdialog")).toBeNull();
  });

  it("shows why the server could not be reached", () => {
    render(<FtpView wsUrl="ws://x" sessionId="s" secure />);
    const socket = FakeSocket.last!;
    socket.receive({ type: "error", message: "files.example.com refused the sign-in for ada." });
    act(() => socket.onclose?.({ reason: "connection failed" }));
    expect(screen.getByRole("alert").textContent).toContain("refused the sign-in");
  });
});

describe("HTTP connections in the editor", () => {
  it("warns that plain HTTP is unencrypted and keeps a pasted http:// path", async () => {
    const onSave = vi.fn(async () => {});
    render(<ConnectionEditor node={null} inherited={{}} onSave={onSave} />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "extranet" } });
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "http" } });
    expect(screen.getByRole("note").textContent).toMatch(/unencrypted/u);
    fireEvent.change(screen.getByLabelText("Host"), {
      target: { value: "http://extranet.example.com:9080/app" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await flush();
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({
        conn: expect.objectContaining({
          protocol: "http",
          host: "extranet.example.com",
          port: 9080,
          path: "/app",
        }),
      }),
    );
  });

  it("offers a key and a jump host for SFTP, unlike FTP", () => {
    render(
      <ConnectionEditor
        node={{ type: "connection", id: "s", name: "s", conn: { protocol: "sftp", host: "h", credentials: {} } }}
        inherited={{}}
        onSave={async () => {}}
      />,
    );
    expect(screen.getAllByText(/jump host/iu).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/private key/iu).length).toBeGreaterThan(0);
  });
});
