### 🛠️ Auto-Signing Tools

This directory contains Python scripts to automate the signing of configuration profiles. It uses **[uv](https://github.com/astral-sh/uv)** for dependency management and fast execution.

## 🚀 Setup

1. Install `uv` (if you haven't already):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```


2. Sync dependencies:
```bash
cd tools
uv sync
```



## 📖 Usage

### 1. Interactive Mode (Manual)

Simply run the script. It will guide you through selecting a certificate and signing the profiles.

```bash
uv run sign_profiles.py
```

### 2. Silent Mode (Configuration Based)

For automation or headless environments, use a configuration file.

1. **Prepare Config**: Copy the template and edit it.
```bash
cp config.example.toml config.toml
```


2. **Configure Secure Passphrase (Recommended)**:
If your private key is encrypted, avoid hardcoding the password. Instead, map it to an environment variable in `config.toml`:
```toml
[signing]
cert_path = "/path/to/key.p12"
# Tell the script which env var holds the password
passphrase_env = "SIGNER_PASS"
```


3. **Run Silently**:
Inject the password at runtime (safe for CI/CD logs):
```bash
export SIGNER_PASS="my_secret_password"
uv run sign_profiles.py --config config.toml
```



### 3. Smart Update (`run_if_changed.py`)

A wrapper script designed for scheduled tasks (Cron/CI).

It calculates a **fingerprint** of your source profiles, certificate, and scripts. The signing process (which updates the git repo) is triggered **only** if a change is detected.

```bash
# Efficient run: Checks hash first, signs only if necessary
export SIGNER_PASS="my_secret_password"
uv run run_if_changed.py --config config.toml
```

## 📂 Files

* `sign_profiles.py`: Core logic. Handles interactive input, secure password retrieval, and signing.
* `run_if_changed.py`: Smart wrapper. Implements change detection to prevent redundant updates.
* `config.example.toml`: Template for silent mode configuration.