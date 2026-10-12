import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ApiError, request } from "../lib/api";
import { certificateDecision, type SessionTab } from "../state/useSessions";
import { SessionView } from "../components/SessionView";

// The terminal and RDP renderers need a real canvas; these tests stop before either renders.
vi.mock("../renderers/SshView", () => ({ SshView: () => null }));
vi.mock("../renderers/RdpView", () => ({ RdpView: () => null }));

const fingerprint = "SHA256:uCn6PsJFSBoFS+4qwdH2StoXr8GT9ioyN7nhjoJ5beU";

function tab(kind: "unknown" | "changed"): SessionTab {
  return {
    id: "t",
    connId: "win",
    title: "win",
    protocol: "rdp",
    epoch: 0,
    certificate: { kind, fingerprint },
  };
}

describe("RDP certificates", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reads the fingerprint from a certificate refusal", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json(
          { code: "certificate_unknown", fingerprint },
          { status: 409 },
        ),
      ),
    );
    const error = await request("POST", "/api/sessions", {}).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(ApiError);
    expect(certificateDecision(error)).toEqual({
      kind: "unknown",
      fingerprint,
    });
    expect(
      certificateDecision(
        new ApiError(409, "certificate_changed", fingerprint),
      ),
    ).toEqual({
      kind: "changed",
      fingerprint,
    });
    expect(
      certificateDecision(new ApiError(403, "nla_required")),
    ).toBeUndefined();
  });

  it("trusts a first-seen certificate only after showing its fingerprint", () => {
    const onTrust = vi.fn();
    const onForget = vi.fn();
    render(
      <SessionView
        tab={tab("unknown")}
        onRetry={vi.fn()}
        onTrustCertificate={onTrust}
        onForgetCertificate={onForget}
      />,
    );
    const dialog = screen.getByRole("alertdialog", { name: "Trust win?" });
    expect(dialog.textContent).toContain(fingerprint);
    fireEvent.click(screen.getByRole("button", { name: "Trust and connect" }));
    expect(onTrust).toHaveBeenCalledTimes(1);
    expect(onForget).not.toHaveBeenCalled();
  });

  it("never offers to accept a changed certificate in one step", () => {
    const onTrust = vi.fn();
    const onForget = vi.fn();
    render(
      <SessionView
        tab={tab("changed")}
        onRetry={vi.fn()}
        onTrustCertificate={onTrust}
        onForgetCertificate={onForget}
      />,
    );
    expect(
      screen.getByRole("alertdialog", { name: "win: the certificate changed" }),
    ).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: "Trust and connect" }),
    ).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "Forget the old certificate" }),
    );
    expect(onForget).toHaveBeenCalledTimes(1);
    expect(onTrust).not.toHaveBeenCalled();
  });
});
