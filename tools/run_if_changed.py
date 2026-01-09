#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


TOOLS_DIR = Path(__file__).resolve().parent
DEFAULT_STATE_DIR = TOOLS_DIR / ".state"
DEFAULT_STATE_FILE = DEFAULT_STATE_DIR / "run_if_changed.state.json"


@dataclass(frozen=True)
class PathsFromConfig:
    config_path: Path
    profiles_dir: Path
    signer_cert: Path
    signer_key: Path
    chain_bundle: Optional[Path]
    out_signed_dir: Path


def _die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:
        _die("toml config requires python 3.11+ (tomllib). please upgrade python.")
    if not path.exists():
        _die(f"config file not found: {path}")
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        _die(f"failed to parse config toml: {e}")


def _resolve_path(base_dir: Path, raw: str) -> Path:
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (base_dir / p)
    return p


def _get_required_str(tbl: dict[str, Any], key: str, tbl_name: str) -> str:
    v = tbl.get(key)
    if not isinstance(v, str) or not v.strip():
        _die(f"config missing required string: [{tbl_name}].{key}")
    return v.strip()


def _get_optional_str(tbl: dict[str, Any], key: str) -> Optional[str]:
    v = tbl.get(key)
    if v is None:
        return None
    if not isinstance(v, str):
        _die(f"config value must be string: {key}")
    s = v.strip()
    return s if s else None


def _paths_from_config(config_path: Path) -> PathsFromConfig:
    data = _load_toml(config_path)
    base_dir = config_path.parent

    paths = data.get("paths", {})
    signing = data.get("signing", {})

    if not isinstance(paths, dict) or not isinstance(signing, dict):
        _die("invalid config structure: [paths] and [signing] must be tables")

    profiles_dir = _resolve_path(base_dir, _get_required_str(paths, "profiles_dir", "paths"))
    out_signed_dir = _resolve_path(base_dir, _get_required_str(paths, "out_signed_dir", "paths"))

    signer_cert = _resolve_path(base_dir, _get_required_str(signing, "signer_cert", "signing"))
    signer_key = _resolve_path(base_dir, _get_required_str(signing, "signer_key", "signing"))

    chain_raw = _get_optional_str(signing, "chain_bundle")
    chain_bundle = _resolve_path(base_dir, chain_raw) if chain_raw else None

    return PathsFromConfig(
        config_path=config_path,
        profiles_dir=profiles_dir,
        signer_cert=signer_cert,
        signer_key=signer_key,
        chain_bundle=chain_bundle,
        out_signed_dir=out_signed_dir,
    )


def _hash_file(h: "hashlib._Hash", path: Path) -> None:
    # include path + size + mtime + content hash (content is the real source of truth)
    h.update(path.as_posix().encode("utf-8"))
    st = path.stat()
    h.update(str(st.st_size).encode("utf-8"))
    h.update(str(int(st.st_mtime_ns)).encode("utf-8"))

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)


def _hash_profiles_dir(h: "hashlib._Hash", profiles_dir: Path) -> int:
    files = sorted(profiles_dir.rglob("*.mobileconfig"))
    for p in files:
        if p.is_file():
            _hash_file(h, p)
    return len(files)


def _compute_fingerprint(
    p: PathsFromConfig,
    *,
    include_config: bool,
    include_script: bool,
) -> tuple[str, dict[str, Any]]:
    if not p.profiles_dir.exists():
        _die(f"profiles directory not found: {p.profiles_dir}")
    if not p.signer_cert.exists():
        _die(f"signer cert not found: {p.signer_cert}")
    if not p.signer_key.exists():
        _die(f"signer key not found: {p.signer_key}")
    if p.chain_bundle is not None and not p.chain_bundle.exists():
        # warn only; allow self-signed / unusual layouts
        print(f"warning: chain bundle path does not exist: {p.chain_bundle}")

    h = hashlib.sha256()

    meta: dict[str, Any] = {
        "profiles_dir": p.profiles_dir.as_posix(),
        "out_signed_dir": p.out_signed_dir.as_posix(),
        "signer_cert": p.signer_cert.as_posix(),
        "signer_key": p.signer_key.as_posix(),
        "chain_bundle": p.chain_bundle.as_posix() if p.chain_bundle else "",
        "include_config": include_config,
        "include_script": include_script,
    }

    count = _hash_profiles_dir(h, p.profiles_dir)
    meta["profiles_count"] = count

    _hash_file(h, p.signer_cert)
    _hash_file(h, p.signer_key)
    if p.chain_bundle and p.chain_bundle.exists():
        _hash_file(h, p.chain_bundle)

    if include_config:
        _hash_file(h, p.config_path)

    if include_script:
        sign_script = TOOLS_DIR / "sign_profiles.py"
        if sign_script.exists():
            _hash_file(h, sign_script)
        else:
            print("warning: tools/sign_profiles.py not found; skipped script hashing")

    return h.hexdigest(), meta


def _read_state(path: Path) -> Optional[dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _run_sign(config_path: Path) -> int:
    sign_script = TOOLS_DIR / "sign_profiles.py"
    if not sign_script.exists():
        _die(f"sign script not found: {sign_script}")

    cmd = [sys.executable, str(sign_script), "--config", str(config_path)]
    proc = subprocess.run(cmd)
    return int(proc.returncode)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument(
        "--config",
        required=True,
        help="path to toml config file, e.g. tools/config.toml",
    )
    ap.add_argument(
        "--state",
        default=str(DEFAULT_STATE_FILE),
        help="path to state json file (default: tools/.state/run_if_changed.state.json)",
    )
    ap.add_argument(
        "--include-config",
        action="store_true",
        default=True,
        help="include config.toml itself in fingerprint (default: true)",
    )
    ap.add_argument(
        "--exclude-config",
        action="store_true",
        default=False,
        help="exclude config.toml from fingerprint",
    )
    ap.add_argument(
        "--include-script",
        action="store_true",
        default=True,
        help="include tools/sign_profiles.py in fingerprint (default: true)",
    )
    ap.add_argument(
        "--exclude-script",
        action="store_true",
        default=False,
        help="exclude tools/sign_profiles.py from fingerprint",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="force run regardless of fingerprint",
    )
    return ap.parse_args(argv)


def main() -> None:
    args = _parse_args()

    config_path = Path(args.config).expanduser()
    state_path = Path(args.state).expanduser()

    include_config = bool(args.include_config) and not bool(args.exclude_config)
    include_script = bool(args.include_script) and not bool(args.exclude_script)

    p = _paths_from_config(config_path)
    fp, meta = _compute_fingerprint(p, include_config=include_config, include_script=include_script)

    prev = _read_state(state_path)
    prev_fp = (prev or {}).get("fingerprint")

    should_run = args.force or (prev_fp != fp)

    if not should_run:
        print("no changes detected; skip")
        raise SystemExit(0)

    print("changes detected; running signer...")
    rc = _run_sign(config_path)

    if rc == 0:
        _write_state(
            state_path,
            {
                "fingerprint": fp,
                "meta": meta,
            },
        )
        print("done; state updated")
        raise SystemExit(0)

    print(f"signer failed with exit code={rc}; state not updated", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    main()