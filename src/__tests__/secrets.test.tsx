import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import {
  SecretField,
  type SecretForm,
  emptySecret,
  secretFromModel,
  secretToModel,
} from "../components/SecretField";

describe("write-only secrets", () => {
  it("keeps a saved credential when nothing new is typed", () => {
    expect(secretToModel(secretFromModel({ credential_id: "c1" }))).toEqual({ credential_id: "c1" });
  });

  it("sends a newly typed password instead of the saved credential", () => {
    const form = { ...secretFromModel({ credential_id: "c1" }), password: "new" };
    expect(secretToModel(form)).toEqual({ password: "new" });
  });

  it("prefers a private key and sends its passphrase", () => {
    const form: SecretForm = { ...emptySecret, password: "pw", privateKey: "KEY", passphrase: "pp" };
    expect(secretToModel(form)).toEqual({ private_key: "KEY", passphrase: "pp" });
  });

  it("drops the saved credential when the user removes it, so the folder's applies", () => {
    expect(secretToModel({ ...secretFromModel({ credential_id: "c1" }), remove: true })).toEqual({});
    expect(secretToModel(emptySecret)).toEqual({});
  });

  it("never shows a saved secret and lets the user remove or keep it", () => {
    const changes = vi.fn();
    function Harness() {
      const [value, setValue] = useState(secretFromModel({ credential_id: "c1" }));
      return (
        <SecretField
          prefix="Connection"
          allowKey
          value={value}
          onChange={(next) => {
            changes(next);
            setValue(next);
          }}
        />
      );
    }
    render(<Harness />);
    const password = screen.getByLabelText("Connection password") as HTMLInputElement;
    expect(password.value).toBe("");
    expect(password.placeholder).toMatch(/saved in SidiOS/);
    expect(screen.getByText("A secret is saved.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Remove saved secret" }));
    expect(screen.getByText("The saved secret will be removed.")).toBeTruthy();
    expect(changes).toHaveBeenLastCalledWith(expect.objectContaining({ remove: true }));
  });

  it("names the folder an empty secret is inherited from", () => {
    render(
      <SecretField prefix="Connection" allowKey={false} value={emptySecret} onChange={() => undefined} inheritedFrom="Production" />,
    );
    expect((screen.getByLabelText("Connection password") as HTMLInputElement).placeholder).toBe(
      "Inherited from Production",
    );
    expect(screen.queryByLabelText(/private key/)).toBeNull();
  });
});
