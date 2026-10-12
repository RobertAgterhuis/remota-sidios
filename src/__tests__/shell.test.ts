import { afterEach, describe, expect, it, vi } from "vitest";
import {
  httpsUrl,
  splitHttpsUrl,
  webUrl,
  OPEN_REQUEST,
  OPEN_RESULT,
  openInSidiosBrowser,
  shellOrigin,
} from "../lib/shell";

/** A Remota window inside a shell window, with the two origins SidiOS uses. */
function framed() {
  const listeners: ((event: MessageEvent) => void)[] = [];
  const parent = { postMessage: vi.fn() };
  const win = {
    location: { host: "remota.webos.example.com", protocol: "https:" },
    parent,
    addEventListener: (_: string, listener: (event: MessageEvent) => void) =>
      listeners.push(listener),
    removeEventListener: vi.fn(),
  } as unknown as Window;
  const deliver = (origin: string, data: unknown) =>
    listeners.forEach((listener) => listener({ origin, data } as MessageEvent));
  return { win, parent, deliver };
}

describe("HTTPS connections in the SidiOS Browser", () => {
  afterEach(() => vi.useRealTimers());

  it("builds the address and finds the shell's origin", () => {
    expect(httpsUrl("router.lan")).toBe("https://router.lan/");
    expect(httpsUrl("10.0.0.1", 8443)).toBe("https://10.0.0.1:8443/");
    expect(httpsUrl("fd00::1", 443)).toBe("https://[fd00::1]/");
    expect(httpsUrl("pve.lan", 8006, "/ui/?tab=1")).toBe("https://pve.lan:8006/ui/?tab=1");
    expect(webUrl("http", "extranet.lan", 80, "/app")).toBe("http://extranet.lan/app");
    expect(webUrl("http", "extranet.lan", 9080)).toBe("http://extranet.lan:9080/");
    expect(splitHttpsUrl("http://extranet.lan/app", "http")?.path).toBe("/app");
    expect(splitHttpsUrl("https://extranet.lan/app", "http")).toBeNull();
    expect(splitHttpsUrl("https://pve-node00.example.com")).toEqual({
      host: "pve-node00.example.com",
      port: undefined,
      path: undefined,
    });
    expect(splitHttpsUrl("HTTPS://[fd00::1]:8006/ui/?a=1#x")).toEqual({
      host: "fd00::1",
      port: 8006,
      path: "/ui/?a=1",
    });
    for (const bad of ["http://router.lan", "https://admin@router.lan", "router.lan", "ftp://x"]) {
      expect(splitHttpsUrl(bad)).toBeNull();
    }
    expect(
      shellOrigin({ host: "remota.webos.example.com", protocol: "https:" }),
    ).toBe("https://webos.example.com");
  });

  it("asks the shell on its origin only and accepts only its answer", async () => {
    const { win, parent, deliver } = framed();
    const pending = openInSidiosBrowser("https://router.lan/", win);
    expect(parent.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: OPEN_REQUEST,
        url: "https://router.lan/",
      }),
      "https://webos.example.com",
    );
    const { id } = parent.postMessage.mock.calls[0]![0] as { id: string };
    deliver("https://evil.example", { type: OPEN_RESULT, id, ok: true });
    deliver("https://webos.example.com", {
      type: OPEN_RESULT,
      id: "other",
      ok: true,
    });
    deliver("https://webos.example.com", {
      type: OPEN_RESULT,
      id,
      ok: false,
      code: "tool_unavailable",
    });
    expect(await pending).toEqual({ ok: false, code: "tool_unavailable" });
  });

  it("gives up without a shell", async () => {
    const win = {
      location: { host: "remota.x", protocol: "https:" },
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    } as unknown as Window;
    (win as unknown as { parent: Window }).parent = win;
    expect(await openInSidiosBrowser("https://a/", win)).toEqual({
      ok: false,
      code: "no_shell",
    });
  });
});
