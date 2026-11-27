# Security policy

## Supported versions

| Version | Security fixes |
|---|---|
| 1.0.x (latest) | Yes |
| < 1.0 | No; upgrade to the latest release ([upgrading](docs/upgrading.md)) |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub: **Security → Report a vulnerability** on the repository
(<https://github.com/fj4rr/just-another-threat-monitoring-platform/security/advisories/new>). Include:

- the version (footer of any page, or `app/__init__.py`) and how JATMP runs (source or Docker, single- or
  multi-user, SQLite or PostgreSQL);
- what an attacker needs (an account and its role, network position, a crafted feed or article…);
- steps to reproduce, and the impact you see.

What to expect:

- an acknowledgement within **7 days**;
- an assessment and a plan within **30 days**; a fix for a confirmed issue in a patch release, credited in the
  changelog unless you prefer not to be named;
- coordinated disclosure: please give us up to **90 days** before publishing details.

## Scope

In scope: the JATMP application in this repository (web UI, REST API, TAXII, webhooks, collectors, the
installer, `manage.py`) and the Docker image built from it.

Out of scope: vulnerabilities in third-party providers or feeds, findings that need an admin account to harm the
same install (admins are trusted by design), deployments that ignore the advice below, and missing hardening
headers without a working attack.

## Deploying safely

The design and the protections are described in [docs/security.md](docs/security.md). In short:

- finish the first-run setup from the machine itself (or with the setup token) before exposing the port;
- expose JATMP beyond localhost only behind a TLS-terminating reverse proxy, with `JATMP_SECURE_COOKIES=1` and
  `JATMP_FORWARDED_ALLOW_IPS` set to the proxy;
- use multi-user mode on anything shared; single-user mode has no login;
- back up `data/config.json` together with the database: it holds the key that decrypts stored API keys.
