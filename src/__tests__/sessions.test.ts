import { afterEach, describe, expect, it, vi } from "vitest";
import { socketUrl, startSession } from "../state/useSessions";
import { parseControl } from "../lib/control";

afterEach(() => vi.unstubAllGlobals());

describe("sessions", () => {
  it("starts a session with a one-time password only when one is given", async () => {
    const fetchMock = vi.fn().mockImplementation(
      async () =>
        new Response(JSON.stringify({ sessionId: "s", websocket: "/session/s?ticket=t", protocol: "ssh" }), {
          status: 201,
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await startSession("web");
    await startSession("web", { password: "pw", save: true });
    expect(JSON.parse(fetchMock.mock.calls[0]![1].body)).toEqual({ connectionId: "web" });
    expect(JSON.parse(fetchMock.mock.calls[1]![1].body)).toEqual({
      connectionId: "web",
      oneTimeSecret: "pw",
      saveSecret: true,
    });
  });

  it("opens the WebSocket on this page's origin", () => {
    expect(socketUrl({ sessionId: "s", websocket: "/session/s?ticket=t", protocol: "ssh" })).toBe(
      `ws://${location.host}/session/s?ticket=t`,
    );
  });

  it("reads only known control messages", () => {
    expect(parseControl('{"type":"trust","host":"h","port":22,"fingerprint":"SHA256:x"}')).toMatchObject({
      type: "trust",
    });
    expect(parseControl('{"type":"error","message":"no"}')).toMatchObject({ type: "error" });
    expect(parseControl('{"type":"other"}')).toBeNull();
    expect(parseControl("not json")).toBeNull();
  });
});
