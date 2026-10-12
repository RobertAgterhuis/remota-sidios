# Remota for SidiOS

Remota is the browser-based SSH and RDP workspace embedded in SidiOS. This fork
removes the upstream desktop updater, VNC/Telnet renderers, and public
relay/agent system. It is built as a container and is reachable only through
the authenticated SidiOS gateway.

## Current scope

- SSH terminal sessions in the browser.
- RDP sessions in the browser, including Windows NLA/CredSSP targets.
- A headless Rust server that serves the web application and will host the
  local SSH/RDP gateway APIs.
- Browser-native clipboard, file import, and file export.

The `src-tauri` directory is retained temporarily as the source for gateway,
vault-model, and protocol code being migrated into `remota-server`. It is not a
shipping desktop application.

## Development

Requirements: Node.js 20+, npm, and stable Rust.

```sh
npm ci
npm run build
cargo test --manifest-path remota-server/Cargo.toml
cargo clippy --manifest-path remota-server/Cargo.toml --all-targets -- -D warnings
```

Run the UI development server with `npm run dev`. Run the headless server with:

```sh
REMOTA_UI_DIR=dist cargo run --manifest-path remota-server/Cargo.toml
```

The service listens on `0.0.0.0:8080` by default and exposes `GET /healthz`.
Set `REMOTA_LISTEN` to override the listen address.

## Source and license

This is the SidiOS-maintained fork of Remota. Source modifications are
published at <https://github.com/RobertAgterhuis/remota-sidios>.

Licensed under the GNU Affero General Public License v3.0 only. See
[`LICENSE`](LICENSE).
