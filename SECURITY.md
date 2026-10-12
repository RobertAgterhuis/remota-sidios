# Security policy

Report suspected vulnerabilities privately to the SidiOS maintainers. Do not
open a public issue containing credentials, connection details, exploit code,
or other sensitive data.

Include the affected commit, component, reproduction steps, impact, and any
suggested mitigation. Remove secrets and personal data from logs before
sharing them.

## Security boundary

The supported deployment is the `remota-server` container behind the
authenticated SidiOS Caddy gateway. The service must not be exposed directly
to an untrusted network. The public relay/agent system, VNC/Telnet renderers,
desktop updater, and desktop packaging are not part of this fork.

Treat SSH keys, passwords, RDP credentials, session cookies, and connection
exports as secrets. Never commit them to the repository or bake them into the
container image.

## Supported code

Security fixes target the current `sidios` branch. The retained `src-tauri`
code is migration input and is not a supported distributable.
