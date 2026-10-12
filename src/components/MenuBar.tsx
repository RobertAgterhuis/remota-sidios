import {
  type CSSProperties,
  type KeyboardEvent,
  useEffect,
  useRef,
  useState,
} from "react";
import { colors } from "./styles";

export type MenuItem = { label: string; onClick: () => void } | "sep";
export type Menu = { title: string; items: MenuItem[] };

/** The mRemoteNG-style menu bar, as an ARIA menu bar: buttons open menus of menu items. */
export function MenuBar({ menus }: { menus: Menu[] }) {
  const [open, setOpen] = useState<string | null>(null);
  const triggers = useRef<Record<string, HTMLButtonElement | null>>({});
  const list = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open !== null)
      list.current
        ?.querySelector<HTMLButtonElement>("[role=menuitem]")
        ?.focus();
  }, [open]);

  function close(title: string) {
    setOpen(null);
    triggers.current[title]?.focus();
  }

  function onMenuKey(event: KeyboardEvent<HTMLDivElement>, title: string) {
    const items = [
      ...(list.current?.querySelectorAll<HTMLButtonElement>(
        "[role=menuitem]",
      ) ?? []),
    ];
    const index = items.indexOf(document.activeElement as HTMLButtonElement);
    const move = { ArrowDown: 1, ArrowUp: -1 }[event.key];
    if (move !== undefined) {
      event.preventDefault();
      items[(index + move + items.length) % items.length]?.focus();
    } else if (event.key === "Escape" || event.key === "Tab") {
      event.preventDefault();
      close(title);
    }
  }

  return (
    <div aria-label="Remota" role="menubar" style={bar}>
      {menus.map((m) => (
        <div key={m.title} style={{ position: "relative" }}>
          <button
            aria-expanded={open === m.title}
            aria-haspopup="menu"
            onClick={() => setOpen((o) => (o === m.title ? null : m.title))}
            onMouseEnter={() => setOpen((o) => (o !== null ? m.title : o))}
            ref={(element) => {
              triggers.current[m.title] = element;
            }}
            style={{
              ...itemStyle,
              background: open === m.title ? colors.panel : "transparent",
            }}
            type="button"
          >
            {m.title}
          </button>
          {open === m.title && (
            <>
              <div
                onClick={() => setOpen(null)}
                style={{ position: "fixed", inset: 0, zIndex: 40 }}
              />
              <div
                aria-label={m.title}
                onKeyDown={(event) => onMenuKey(event, m.title)}
                ref={list}
                role="menu"
                style={dropdown}
              >
                {m.items.map((it, i) =>
                  it === "sep" ? (
                    <div
                      key={i}
                      role="separator"
                      style={{
                        height: 1,
                        background: colors.border,
                        margin: "4px 6px",
                      }}
                    />
                  ) : (
                    <button
                      key={i}
                      onClick={() => {
                        setOpen(null);
                        it.onClick();
                      }}
                      onMouseEnter={(e) =>
                        (e.currentTarget.style.background =
                          "var(--color-hover)")
                      }
                      onMouseLeave={(e) =>
                        (e.currentTarget.style.background = "transparent")
                      }
                      role="menuitem"
                      style={menuItemStyle}
                      tabIndex={-1}
                      type="button"
                    >
                      {it.label}
                    </button>
                  ),
                )}
              </div>
            </>
          )}
        </div>
      ))}
    </div>
  );
}

const bar: CSSProperties = {
  display: "flex",
  alignItems: "stretch",
  height: 30,
  background: "var(--color-surface)",
  borderBottom: `1px solid ${colors.border}`,
  fontSize: 13,
  userSelect: "none",
};
const itemStyle: CSSProperties = {
  display: "flex",
  alignItems: "center",
  padding: "0 12px",
  cursor: "pointer",
  color: colors.text,
  background: "transparent",
  border: "none",
  font: "inherit",
};
const dropdown: CSSProperties = {
  position: "absolute",
  top: 30,
  left: 0,
  zIndex: 41,
  background: colors.panel,
  border: `1px solid ${colors.border}`,
  borderRadius: 6,
  padding: 4,
  minWidth: 260,
  boxShadow: "0 8px 24px rgba(0,0,0,0.5)",
  display: "grid",
};
const menuItemStyle: CSSProperties = {
  padding: "7px 12px",
  cursor: "pointer",
  color: colors.text,
  borderRadius: 4,
  fontSize: 13,
  background: "transparent",
  border: "none",
  textAlign: "left",
  font: "inherit",
};
