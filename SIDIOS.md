# SidiOS fork

This branch is the public, network-source-compliant fork deployed by SidiOS. It is based on
upstream Remota commit `c9e3189c0c3c3ea0f022724de40a28ab978d215b` (v0.1.8).

## SidiOS changes

- Replace the Tauri desktop shell with a headless `remota-server` service that serves the React
  application and exposes health and HTTP/WebSocket endpoints.
- Obtain identity only from trusted `X-Webos-*` reverse-proxy headers; there is no Remota sign-in.
- Store the connection tree on the server and keep credentials in the SidiOS envelope-encrypted
  vault; remove Remota's local master-password vault.
- Require short-lived, single-use SidiOS tickets for sessions.
- Enforce the SidiOS fail-closed target policy before opening SSH or RDP traffic.
- Remove the updater, update checks, VNC, relay, agent, and gateway relay client.
- Adapt the UI to browser APIs and the SidiOS design system.
- Add server-side RDP credential injection only if the security spike passes.

Upstream changes are reviewed and merged deliberately. The deployed image pins an exact commit;
it never downloads or installs updates at runtime.
