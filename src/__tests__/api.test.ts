import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, treeApi } from "../lib/api";

const empty = { nodes: [], trash: [] };

function mockFetch(status: number, body: unknown) {
  const fetchMock = vi.fn().mockImplementation(
    async () =>
      new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => vi.unstubAllGlobals());

describe("tree API client", () => {
  it("saves a node with PUT and its parent", async () => {
    const fetchMock = mockFetch(200, empty);
    const node = {
      type: "connection" as const,
      id: "a b",
      name: "web",
      conn: { protocol: "ssh" as const, host: "h", credentials: { password: "pw" } },
    };
    await treeApi.saveNode("lab", node);
    const [path, init] = fetchMock.mock.calls[0]!;
    expect(path).toBe("/api/nodes/a%20b");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body)).toEqual({ node, parentId: "lab" });
  });

  it("turns refusals into readable errors with the server's code", async () => {
    mockFetch(422, { code: "too_deep" });
    const error = await treeApi.deleteNode("x").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 422, code: "too_deep", message: "Folders can be nested at most 10 levels deep." });
  });

  it("uses the trash routes", async () => {
    const fetchMock = mockFetch(200, empty);
    await treeApi.restoreNode("n1");
    await treeApi.deleteForever("n1");
    await treeApi.emptyTrash();
    expect(fetchMock.mock.calls.map(([path, init]) => `${init.method} ${path}`)).toEqual([
      "POST /api/trash/n1/restore",
      "DELETE /api/trash/n1",
      "DELETE /api/trash",
    ]);
  });
});

describe("session messages", () => {
  it("explains blocked targets and limit refusals", async () => {
    mockFetch(403, { code: "target_not_allowed" });
    await expect(treeApi.forgetHostKey("web")).rejects.toMatchObject({
      message:
        "This address cannot be reached from Remota: SidiOS's own networks, the SidiOS host, and loopback or link-local addresses are blocked.",
    });
    mockFetch(429, { code: "session_limit" });
    await expect(treeApi.forgetHostKey("web")).rejects.toMatchObject({
      message: "You have reached the number of open sessions. Close one and try again.",
    });
  });
});
