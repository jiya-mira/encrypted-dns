#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import plistlib
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

import questionary
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID
from tqdm import tqdm

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class SignMaterial:
    signer_cert: x509.Certificate
    signer_key: PrivateKeyTypes
    extra_certs: Sequence[x509.Certificate]


@dataclass(frozen=True)
class AppConfig:
    profiles_dir: Path
    out_signed_dir: Path
    signer_cert_path: Path
    signer_key_path: Path
    chain_path: Optional[Path]
    new_payload_identifier: Optional[str]
    concurrency: int
    passphrase_env: Optional[str]
    clear_output_dir: bool


def _read_file(path: Path) -> bytes:
    return path.read_bytes()


def _load_cert_any(path: Path) -> x509.Certificate:
    data = _read_file(path)
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError:
        return x509.load_der_x509_certificate(data)


def _load_cert_bundle(path: Path) -> list[x509.Certificate]:
    """
    load a cert bundle which is usually PEM (may contain multiple certs).
    if not PEM bundle, try single DER.
    """
    data = _read_file(path)

    marker = b"-----BEGIN CERTIFICATE-----"
    if marker in data:
        certs: list[x509.Certificate] = []
        parts = data.split(marker)
        for part in parts:
            chunk = part.strip()
            if not chunk:
                continue
            block = marker + part
            try:
                certs.append(x509.load_pem_x509_certificate(block))
            except ValueError:
                continue
        return certs

    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []


def _try_load_private_key(path: Path, passphrase: Optional[str]) -> PrivateKeyTypes:
    data = _read_file(path)
    pwd = passphrase.encode("utf-8") if passphrase else None
    try:
        return serialization.load_pem_private_key(data, password=pwd)
    except ValueError:
        return serialization.load_der_private_key(data, password=pwd)


def _needs_private_key_passphrase(key_path: Path) -> bool:
    try:
        _ = _try_load_private_key(key_path, None)
        return False
    except (TypeError, ValueError):
        return True


def _ask_private_key_passphrase(key_path: Path) -> str:
    pw = questionary.password("private key passphrase (leave empty if none)").ask() or ""
    if not pw:
        raise SystemExit("failed to load private key without passphrase, but no passphrase provided")
    try:
        _ = _try_load_private_key(key_path, pw)
    except (TypeError, ValueError) as e:
        raise SystemExit(f"failed to load private key with provided passphrase: {e}") from e
    return pw


def _get_cert_cn(cert: x509.Certificate) -> Optional[str]:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    cn = str(attrs[0].value).strip()
    if not cn:
        return None
    if cn.startswith("*."):
        cn = cn[2:]
    return cn or None


def _default_payload_identifier(cert: x509.Certificate) -> str:
    cn = _get_cert_cn(cert)
    if cn:
        return f"{cn}.encrypted-dns"
    return "cn.angleline.encrypted-dns"


def _uuid_v5_upper(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed)).upper()


def _uuid_v5_lower(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed)).lower()


def _ensure_dict(obj: object) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValueError("plist root is not a dict")
    return obj  # type: ignore[return-value]


def _ensure_list(obj: object) -> list[Any]:
    if obj is None:
        return []
    if not isinstance(obj, list):
        raise ValueError("payloadcontent is not a list")
    return obj


def _normalize_ip_address(value: str) -> str:
    s = value.strip()
    if not s:
        raise ValueError("empty IP address")
    try:
        return str(ipaddress.ip_address(s))
    except ValueError as e:
        raise ValueError(f"invalid IP address: {value!r}") from e


def _normalize_server_addresses(
    item_dict: dict[str, Any],
    *,
    payload_index: int,
    rel_path: Path,
) -> None:
    dns_settings = item_dict.get("DNSSettings")
    if dns_settings is None:
        return
    if not isinstance(dns_settings, dict):
        raise ValueError(
            f"dnssettings is not a dict: {rel_path.as_posix()} payload[{payload_index}]"
        )

    addrs = dns_settings.get("ServerAddresses")
    if addrs is None:
        return
    if not isinstance(addrs, list):
        raise ValueError(
            f"serveraddresses is not a list: {rel_path.as_posix()} payload[{payload_index}]"
        )

    normalized: list[str] = []
    for addr_index, addr in enumerate(addrs):
        if not isinstance(addr, str):
            raise ValueError(
                f"server address is not a string: {rel_path.as_posix()} payload[{payload_index}]"
                f" server[{addr_index}]"
            )
        try:
            normalized.append(_normalize_ip_address(addr))
        except ValueError as e:
            raise ValueError(
                f"invalid server address: {rel_path.as_posix()} payload[{payload_index}]"
                f" server[{addr_index}] ({e})"
            ) from e

    dns_settings["ServerAddresses"] = normalized


def _patch_profile_dict(
    root: dict[str, Any],
    *,
    rel_path: Path,
    new_root_identifier: Optional[str],
) -> dict[str, Any]:
    """
    minimal, template-friendly patch:
    - force PayloadScope = System
    - optionally rewrite root PayloadIdentifier
    - deterministically rewrite PayloadUUID at root + each payload in PayloadContent
    - keep inner PayloadIdentifier unless it's com.apple.dnsSettings.managed.<uuid>,
      in which case keep the prefix and align suffix uuid with rewritten PayloadUUID.
    """
    root["PayloadScope"] = "System"

    root_identifier = str(root.get("PayloadIdentifier", "")).strip()
    if new_root_identifier is not None and new_root_identifier.strip():
        root_identifier = new_root_identifier.strip()
        root["PayloadIdentifier"] = root_identifier

    if not root_identifier:
        root_identifier = "encrypted-dns"

    rel = rel_path.as_posix()

    root_uuid = _uuid_v5_upper(f"{root_identifier}::root::{rel}")
    root["PayloadUUID"] = root_uuid

    pc = _ensure_list(root.get("PayloadContent"))
    for i, item in enumerate(pc):
        if not isinstance(item, dict):
            continue
        item_dict: dict[str, Any] = item  # narrow type
        _normalize_server_addresses(item_dict, payload_index=i, rel_path=rel_path)

        if "PayloadUUID" in item_dict:
            pu = _uuid_v5_upper(f"{root_identifier}::payload::{i}::{rel}")
            item_dict["PayloadUUID"] = pu

            pid = item_dict.get("PayloadIdentifier")
            if isinstance(pid, str) and pid.startswith("com.apple.dnsSettings.managed."):
                item_dict["PayloadIdentifier"] = f"com.apple.dnsSettings.managed.{_uuid_v5_lower(f'{root_identifier}::payload::{i}::{rel}')}"
                # note: suffix uses the same deterministic payload uuid (lowercase)

    return root


def _build_signed_der(*, xml_data: bytes, sm: SignMaterial) -> bytes:
    b = pkcs7.PKCS7SignatureBuilder().set_data(xml_data).add_signer(
        sm.signer_cert,
        sm.signer_key,
        hashes.SHA256(),
    )

    signer_fp = sm.signer_cert.fingerprint(hashes.SHA256())
    for c in sm.extra_certs:
        try:
            if c.fingerprint(hashes.SHA256()) == signer_fp:
                continue
        except Exception:
            pass
        b = b.add_certificate(c)

    return b.sign(
        encoding=serialization.Encoding.DER,
        options=[pkcs7.PKCS7Options.Binary],
    )


def _warn_cert_chain(extra_certs: Sequence[x509.Certificate], chain_path: Optional[Path]) -> None:
    if chain_path is None:
        print("warning: no chain bundle provided (ok for self-signed, may affect trust for public ca)")
        return
    if not chain_path.exists():
        print(f"warning: chain bundle path does not exist: {chain_path}")
        return
    if not extra_certs:
        print(f"warning: chain bundle loaded 0 certs: {chain_path} (format mismatch?)")


def _warn_key_mismatch(cert: x509.Certificate, key: PrivateKeyTypes) -> None:
    try:
        pub1 = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub2 = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if pub1 != pub2:
            print("warning: signer cert public key does not match private key")
    except Exception:
        print("warning: failed to compare cert/key public key; skipped")


async def _process_one(
    sem: asyncio.Semaphore,
    *,
    sm: SignMaterial,
    src: Path,
    profiles_dir: Path,
    out_signed_dir: Path,
    new_root_identifier: Optional[str],
) -> None:
    async with sem:
        rel = src.relative_to(profiles_dir)
        dst = out_signed_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)

        raw = await asyncio.to_thread(src.read_bytes)

        try:
            plist_obj = plistlib.loads(raw)
            root = _ensure_dict(plist_obj)
        except Exception as e:
            raise RuntimeError(f"failed to parse plist: {rel.as_posix()} ({e})") from e

        patched = _patch_profile_dict(
            root,
            rel_path=rel,
            new_root_identifier=new_root_identifier,
        )

        xml_data = plistlib.dumps(patched, fmt=plistlib.FMT_XML, sort_keys=False)
        der = await asyncio.to_thread(_build_signed_der, xml_data=xml_data, sm=sm)
        await asyncio.to_thread(dst.write_bytes, der)


def _resolve_path(base_dir: Path, raw: str) -> Path:
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = (base_dir / p)
    return p


def _load_config_file(path: Path) -> AppConfig:
    if tomllib is None:
        raise SystemExit("toml config requires python 3.11+ (tomllib). please upgrade python.")

    if not path.exists():
        raise SystemExit(f"config file not found: {path}")

    base_dir = path.parent
    data = tomllib.loads(path.read_text(encoding="utf-8"))

    paths = data.get("paths", {})
    signing = data.get("signing", {})
    runtime = data.get("runtime", {})

    def req_str(tbl: dict[str, Any], key: str) -> str:
        v = tbl.get(key)
        if not isinstance(v, str) or not v.strip():
            raise SystemExit(f"config missing required string: [{tbl_name(tbl)}].{key}")
        return v.strip()

    def opt_str(tbl: dict[str, Any], key: str) -> Optional[str]:
        v = tbl.get(key)
        if v is None:
            return None
        if not isinstance(v, str):
            raise SystemExit(f"config value must be string: [{tbl_name(tbl)}].{key}")
        s = v.strip()
        return s if s else None

    def opt_bool(tbl: dict[str, Any], key: str, default: bool) -> bool:
        v = tbl.get(key, default)
        if not isinstance(v, bool):
            raise SystemExit(f"config value must be bool: [{tbl_name(tbl)}].{key}")
        return v

    def opt_int(tbl: dict[str, Any], key: str, default: int) -> int:
        v = tbl.get(key, default)
        if not isinstance(v, int):
            raise SystemExit(f"config value must be int: [{tbl_name(tbl)}].{key}")
        return max(1, v)

    def tbl_name(tbl: dict[str, Any]) -> str:
        if tbl is paths:
            return "paths"
        if tbl is signing:
            return "signing"
        if tbl is runtime:
            return "runtime"
        return "config"

    profiles_dir = _resolve_path(base_dir, req_str(paths, "profiles_dir"))
    out_signed_dir = _resolve_path(base_dir, req_str(paths, "out_signed_dir"))
    signer_cert_path = _resolve_path(base_dir, req_str(signing, "signer_cert"))
    signer_key_path = _resolve_path(base_dir, req_str(signing, "signer_key"))

    chain_raw = opt_str(signing, "chain_bundle")
    chain_path = _resolve_path(base_dir, chain_raw) if chain_raw else None

    new_pid = opt_str(signing, "new_payload_identifier")

    passphrase_env = opt_str(signing, "passphrase_env")

    concurrency = opt_int(runtime, "concurrency", os.cpu_count() or 1)
    clear_output_dir = opt_bool(runtime, "clear_output_dir", True)

    return AppConfig(
        profiles_dir=profiles_dir,
        out_signed_dir=out_signed_dir,
        signer_cert_path=signer_cert_path,
        signer_key_path=signer_key_path,
        chain_path=chain_path,
        new_payload_identifier=new_pid,
        concurrency=concurrency,
        passphrase_env=passphrase_env,
        clear_output_dir=clear_output_dir,
    )


def _build_config_interactive() -> AppConfig:
    print("--- encrypted dns profile signer (no openssl cli) ---")

    cpu_default = os.cpu_count() or 8

    profiles_dir = Path(
        (questionary.text(
            "profiles directory (input, unsigned)",
            default=str(REPO_ROOT / "profiles"),
        ).ask() or "").strip()
    ).expanduser()

    out_signed_dir = Path(
        (questionary.text(
            "output signed directory (will be fully overwritten)",
            default=str(REPO_ROOT / "signed"),
        ).ask() or "").strip()
    ).expanduser()

    cert_path = Path(
        (questionary.path(
            "signer certificate path (leaf cert, pem/der)",
            default="",
        ).ask() or "").strip()
    ).expanduser()

    key_path = Path(
        (questionary.path(
            "signer private key path (pem/der)",
            default="",
        ).ask() or "").strip()
    ).expanduser()

    chain_in = (questionary.path(
        "chain/ca cert bundle path (optional)",
        default="",
    ).ask() or "").strip()
    chain_path = Path(chain_in).expanduser() if chain_in else None

    concurrency_raw = (questionary.text(
        "concurrency (async workers)",
        default=str(cpu_default),
    ).ask() or "").strip()

    try:
        concurrency = max(1, int(concurrency_raw))
    except ValueError as e:
        raise SystemExit(f"invalid concurrency: {concurrency_raw}") from e

    clear_output_dir = True

    return AppConfig(
        profiles_dir=profiles_dir,
        out_signed_dir=out_signed_dir,
        signer_cert_path=cert_path,
        signer_key_path=key_path,
        chain_path=chain_path,
        new_payload_identifier=None,  # will ask after cert loaded
        concurrency=concurrency,
        passphrase_env=None,
        clear_output_dir=clear_output_dir,
    )


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument("--config", type=str, default="", help="path to toml config file")
    return p.parse_args(argv)


def main() -> None:
    args = _parse_args()

    cfg: AppConfig
    config_path = (args.config or "").strip()
    if config_path:
        cfg = _load_config_file(Path(config_path).expanduser())
        interactive = False
        print("--- encrypted dns profile signer (config mode) ---")
    else:
        cfg = _build_config_interactive()
        interactive = True

    if not cfg.profiles_dir.exists():
        raise SystemExit(f"profiles directory not found: {cfg.profiles_dir}")
    if not cfg.signer_cert_path.exists():
        raise SystemExit(f"signer cert not found: {cfg.signer_cert_path}")
    if not cfg.signer_key_path.exists():
        raise SystemExit(f"signer key not found: {cfg.signer_key_path}")

    signer_cert = _load_cert_any(cfg.signer_cert_path)

    # in interactive mode, we can ask for optional payloadidentifier default based on cn
    default_id = _default_payload_identifier(signer_cert)
    new_root_identifier: Optional[str]
    if interactive:
        raw = (questionary.text(
            "new payloadidentifier (optional; leave empty to keep original)",
            default=default_id,
        ).ask() or "")
        new_root_identifier = raw.strip() or None
    else:
        # config mode: use toml value as-is; if not provided, keep original
        new_root_identifier = cfg.new_payload_identifier.strip() if cfg.new_payload_identifier else None

    # private key passphrase handling
    passphrase: Optional[str] = None
    if _needs_private_key_passphrase(cfg.signer_key_path):
        env_name = cfg.passphrase_env
        if env_name:
            passphrase = os.environ.get(env_name, "") or None
            if not passphrase:
                print(f"warning: passphrase_env set but env var empty: {env_name}")
        if passphrase is None and interactive:
            passphrase = _ask_private_key_passphrase(cfg.signer_key_path)
        if passphrase is None and not interactive:
            raise SystemExit("private key requires passphrase, but no passphrase_env provided (config mode is non-interactive)")

    signer_key = _try_load_private_key(cfg.signer_key_path, passphrase)

    extra_certs: list[x509.Certificate] = []
    if cfg.chain_path and cfg.chain_path.exists():
        extra_certs = _load_cert_bundle(cfg.chain_path)

    _warn_cert_chain(extra_certs, cfg.chain_path)
    _warn_key_mismatch(signer_cert, signer_key)

    files = sorted(cfg.profiles_dir.rglob("*.mobileconfig"))
    if not files:
        raise SystemExit(f"no .mobileconfig found under: {cfg.profiles_dir}")

    # clear output dir before signing (you asked to always clear first)
    if cfg.clear_output_dir and cfg.out_signed_dir.exists():
        shutil.rmtree(cfg.out_signed_dir)
    cfg.out_signed_dir.mkdir(parents=True, exist_ok=True)

    sm = SignMaterial(signer_cert=signer_cert, signer_key=signer_key, extra_certs=extra_certs)

    async def runner() -> None:
        sem = asyncio.Semaphore(cfg.concurrency)
        tasks = [
            asyncio.create_task(_process_one(
                sem,
                sm=sm,
                src=f,
                profiles_dir=cfg.profiles_dir,
                out_signed_dir=cfg.out_signed_dir,
                new_root_identifier=new_root_identifier,
            ))
            for f in files
        ]

        with tqdm(total=len(tasks), desc="signing", unit="file") as bar:
            for coro in asyncio.as_completed(tasks):
                try:
                    await coro
                except Exception as e:
                    bar.write(f"[fail] {e}")
                bar.update(1)

        print(f"done; output: {cfg.out_signed_dir}")

    asyncio.run(runner())


if __name__ == "__main__":
    main()
