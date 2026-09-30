# Security

## Reporting
Please report vulnerabilities privately through GitHub's **Security → Report a vulnerability** on this repository, not in a public issue.

## Model
- Reads system files and runs a few standard tools; it makes no internet connections.
- Needs root only for opt-in actions (`capture`, `udev --install`, `usb-net --assign`), asked for via `sudo`/`pkexec`.
- **Do not treat its cable-snoop result as a security guarantee.** It is a work-in-progress heuristic.
- Capture files can contain personal data; review before sharing.

## Supported versions
Only the latest release.
