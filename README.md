# Encrypted DNS Profiles (Auto-Signed Edition)

This repository publishes signed `.mobileconfig` profiles for iOS / iPadOS / macOS with an operations-first release workflow.

## Project Direction

Upstream ([paulmillr/encrypted-dns](https://github.com/paulmillr/encrypted-dns)) now has its own build/sign toolchain.

This fork continues to focus on:
* a simpler and reliability-oriented workflow (`uv` + Python tools)
* server-side automated re-signing
* rolling releases for end users

Roadmap note: we are evaluating a gradual shift toward automation-first maintenance of profile data and signed artifacts.

## Why Follow This Fork

* **Operational Simplicity**: One clear flow from sync -> sign -> release.
* **Production-First**: Real server pipeline (`systemd` timer/service), not manual local-only steps.
* **Fast Iteration**: Signed artifacts are regenerated and published with minimal manual work.

## Latest Snapshot

* **Last verified commit**: `5153a4a`
* **Unsigned profiles**: `64`
* **Signed profiles**: `64`
* **Updated on**: March 6, 2026

Watch this repository to follow upcoming release and maintenance changes.

## Downloads

**[Browse the `signed/` Directory](./signed)**

All `.mobileconfig` files in the link above are:
* **Signed**: Generated from the current signing pipeline.
* **Current**: Kept up-to-date by automated operational workflow.
* **Ready to Install**: Built for Apple profile installation flow.

### How to Install
1. Navigate to the `signed/` folder and choose your provider (e.g., Alidns, Google, Cloudflare).
2. Download the `.mobileconfig` file.
3. **iOS**: Go to `Settings` -> `Profile Downloaded` -> `Install`.
4. **macOS**: Go to `System Settings` -> `Privacy & Security` -> `Profiles`.

## Under the Hood (For Developers)

This project is powered by Python automation tools for signing and release operations.

* **Tech Stack**: Python (managed by [uv](https://github.com/astral-sh/uv)).
* **Core Logic**:
  * **Signing**: Scripted certificate loading and profile signing.
  * **Efficiency**: Fingerprint-based change detection to avoid redundant re-signing.
* **Runtime Modes**:
  * **Config Mode** for server/CI tasks.
  * **Force Mode** for explicit re-sign and publish runs.

Tool docs: **[tools/README.md](./tools/README.md)**

## Acknowledgements

This project is a fork of [paulmillr/encrypted-dns](https://github.com/paulmillr/encrypted-dns).
Credits for original profile templates and provider data belong to the upstream project.

---

*License: [The Unlicense](./LICENSE)*
