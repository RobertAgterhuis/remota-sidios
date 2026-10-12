// Remota runs in a SidiOS tool window on its own origin (`remota.<domain>`). HTTPS connections open
// in the SidiOS Browser: Remota asks the shell, on the shell's origin only, and waits for its answer
// (SidiOS feature 015 US7).

export const OPEN_REQUEST = "sidios.browser.open";
export const OPEN_RESULT = "sidios.browser.result";

/** The SidiOS shell's origin: this page's host without the `remota.` prefix. */
export function shellOrigin(
  location: Pick<Location, "protocol" | "host">,
): string {
  return `${location.protocol}//${location.host.replace(/^remota\./u, "")}`;
}

/** The address of an HTTPS connection: `https://host[:port]/`. */
export function httpsUrl(host: string, port?: number): string {
  const name = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  return `https://${name}${port && port !== 443 ? `:${port}` : ""}/`;
}

export type OpenResult = { ok: true } | { ok: false; code: string };

/** Asks the shell to open `url` in the SidiOS Browser; gives up after 60 seconds. */
export function openInSidiosBrowser(
  url: string,
  win: Window = window,
): Promise<OpenResult> {
  const origin = shellOrigin(win.location);
  const id = crypto.randomUUID();
  return new Promise((resolve) => {
    const timer = setTimeout(
      () => finish({ ok: false, code: "no_answer" }),
      60_000,
    );
    function finish(result: OpenResult) {
      clearTimeout(timer);
      win.removeEventListener("message", onMessage);
      resolve(result);
    }
    function onMessage(event: MessageEvent) {
      const data = event.data as {
        type?: unknown;
        id?: unknown;
        ok?: unknown;
        code?: unknown;
      };
      if (
        event.origin !== origin ||
        data?.type !== OPEN_RESULT ||
        data.id !== id
      )
        return;
      finish(
        data.ok === true
          ? { ok: true }
          : { ok: false, code: String(data.code ?? "failed") },
      );
    }
    win.addEventListener("message", onMessage);
    if (win.parent === win) {
      finish({ ok: false, code: "no_shell" });
      return;
    }
    win.parent.postMessage({ id, type: OPEN_REQUEST, url }, origin);
  });
}
