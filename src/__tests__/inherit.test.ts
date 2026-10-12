import { describe, expect, it } from "vitest";
import type { Document, Node } from "../lib/api";
import { ancestors, chainFor, inheritedValues } from "../lib/inherit";

const tree: Node[] = [
  {
    type: "folder",
    id: "prod",
    name: "Production",
    defaults: { username: "root", domain: "CORP", credential_id: "k1" },
    gateway: { host: "bastion" },
    children: [
      {
        type: "folder",
        id: "web",
        name: "Web",
        defaults: { username: "deploy" },
        children: [
          { type: "connection", id: "c1", name: "web-1", conn: { protocol: "ssh", host: "h", credentials: {} } },
        ],
      },
    ],
  },
];
const doc: Document = { nodes: tree, trash: [] };

describe("inheritance sources", () => {
  it("finds the folders above a node", () => {
    expect(ancestors(doc, "c1")?.map((n) => n.id)).toEqual(["prod", "web"]);
    expect(ancestors(doc, "prod")).toEqual([]);
    expect(ancestors(doc, "missing")).toBeNull();
  });

  it("uses the nearest folder for each value and names it", () => {
    const inherited = inheritedValues(ancestors(doc, "c1")!);
    expect(inherited.username).toEqual({ value: "deploy", from: "Web" });
    expect(inherited.domain).toEqual({ value: "CORP", from: "Production" });
    expect(inherited.secret).toEqual({ value: "saved", from: "Production" });
    expect(inherited.gateway?.from).toBe("Production");
  });

  it("works for a node not created yet, from its future parent", () => {
    expect(chainFor(doc, "web").map((n) => n.id)).toEqual(["prod", "web"]);
    expect(chainFor(doc, null)).toEqual([]);
  });
});
