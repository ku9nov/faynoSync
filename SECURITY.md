# Security Policy

## Supported versions

Security fixes are released for the [latest release](https://github.com/ku9nov/faynoSync/releases/latest) only. Check that the issue reproduces on it before reporting.

## Reporting a vulnerability

Do not open a public issue, pull request, or discussion for a security problem.

Report it privately through GitHub: open the [Security tab](https://github.com/ku9nov/faynoSync/security) and click **Report a vulnerability**, or go directly to <https://github.com/ku9nov/faynoSync/security/advisories/new>.

Please include:

- the affected version or commit
- the component (API, dashboard, TUF metadata, storage, updater feeds)
- steps to reproduce or a proof of concept
- the impact you expect

## What to expect

- An initial response within 14 days.
- An assessment and, if confirmed, a fix plan. Progress is shared in the private advisory.
- Once a fix is released, a GitHub Security Advisory is published (with a CVE when applicable) and the fix is listed in the `### Security` section of [CHANGELOG.md](CHANGELOG.md).
- Credit in the advisory, unless you ask to stay anonymous.

## Scope

In scope: the faynoSync server, the embedded dashboard, TUF metadata handling, release binaries, and the `ku9nov/faynosync` Docker image.

Out of scope: vulnerabilities in your own deployment configuration (reverse proxy, storage bucket policies, leaked credentials), and third-party updaters or SDKs that are not part of this repository.
