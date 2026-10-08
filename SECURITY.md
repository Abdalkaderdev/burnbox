# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's "Report a vulnerability" button on the Security tab of this repository, or by email to the address on [abdalkader.dev](https://abdalkader.dev). Do not open a public issue.

Include what you found, how to reproduce it and which version you used. You should hear back within a week.

## In scope

- A repository that runs code on the host during a static scan or a clone
- Escaping or weakening the sandbox through something burnbox configures (mount, flags, image)
- A malicious repository making burnbox report CLEAN while the sandbox clearly observed decoy access or network attempts
- Injection through report output (HTML report, terminal escape sequences)

## Out of scope

- Container or kernel escapes in Docker itself. Report those to Docker or your kernel vendor.
- Malware that behaves differently inside a sandbox. This is a documented limitation.
- Heuristic false negatives in the static rules. Open a normal issue with an inert example.

Please do not send live malware samples. Describe the technique or provide an inert reproduction.
