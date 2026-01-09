# Encrypted DNS Profiles (Auto-Signed Edition)

> **⚠️ The Issue with the Upstream Repo:**
> The signed profiles in the original repository contain expired certificates, causing "Not Verified" security warnings on iOS and macOS devices.
>
> **✅ The Solution in this Fork:**
> This repository implements a **Zero-Touch Automation Workflow** to regenerate and sign all profiles using valid certificates. Updates are triggered automatically via a secure, local pipeline.

## 📥 Downloads

**👉 [Browse the `signed/` Directory](./signed)**

All `.mobileconfig` files in the link above are:
* **Valid**: Signed with a current certificate (No red warnings).
* **Up-to-Date**: Automatically synchronized with upstream provider changes.
* **Safe**: Generated in a secure, offline environment.

### How to Install
1. Navigate to the `signed/` folder and choose your provider (e.g., Alidns, Google, Cloudflare).
2. Download the `.mobileconfig` file.
3. **iOS**: Go to `Settings` -> `Profile Downloaded` -> `Install`.
4. **macOS**: Go to `System Settings` -> `Privacy & Security` -> `Profiles`.

## ⚙️ Under the Hood (For Developers)

This project is powered by a set of **Python automation tools** designed for **Security** and **Efficiency**.

* **Tech Stack**: Python (managed by [uv](https://github.com/astral-sh/uv)).
* **Core Logic**:
    * **Signing**: A dedicated script to handle certificate loading and profile signing.
    * **Efficiency**: **Intelligent Change Detection** monitors source profiles, certificates, and automation logic to prevent redundant updates.
* **Flexibility**: The tools support both **Interactive Mode** (CLI Wizard) and **Config Mode** (CI/CD ready).

**Want to build your own signing workflow?**
👉 **[Check out the Tools Documentation](./tools/README.md)**

## 🔗 Acknowledgements

This project is a fork of the original work by [paulmillr/encrypted-dns](https://github.com/paulmillr/encrypted-dns).
All credits for the profile templates and provider data belong to the original author. This fork focuses solely on adding a **modern automation layer** to maintain validity.

---

*License: [The Unlicense](./LICENSE)*