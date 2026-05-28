#!/usr/bin/env python3
"""vault_pricing.py — Collect HashiCorp Vault metrics for client pricing.

Usage:
    export VAULT_ADDR=https://vault.example.com
    export VAULT_TOKEN=hvs.xxx
    export VAULT_NAMESPACE=admin   # optional, Enterprise/HCP only
    python3 vault_pricing.py

Dependencies:
    pip install requests              # required
    pip install cryptography          # optional — enables accurate PKI TTL calc
"""

import os
import sys
from datetime import datetime, timezone
from typing import Optional

try:
    import requests
except ImportError:
    print("Erreur : 'requests' manquant. Installez avec : pip install requests")
    sys.exit(1)

try:
    from cryptography import x509 as cx509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ── Constants ─────────────────────────────────────────────────────────────────
HOURS_PER_MONTH = 730

# Auth methods whose roles count as dynamic secrets
AUTH_DYNAMIC = {"approle", "aws", "azure", "gcp", "jwt", "kubernetes",
                "ldap", "oidc", "okta", "radius", "userpass"}
# Secret engines whose roles count as dynamic secrets
ENGINE_DYNAMIC = {"aws", "azure", "database", "gcp", "nomad", "rabbitmq"}

# ── ANSI helpers ──────────────────────────────────────────────────────────────
B = lambda s: f"\033[1m{s}\033[0m"
D = lambda s: f"\033[2m{s}\033[0m"
G = lambda s: f"\033[92m\033[1m{s}\033[0m"
Y = lambda s: f"\033[93m{s}\033[0m"
R = lambda s: f"\033[91m{s}\033[0m"
C = lambda s: f"\033[96m{s}\033[0m"
W = 64  # console width


# ── Vault HTTP client ─────────────────────────────────────────────────────────
class Vault:
    def __init__(self, addr: str, token: str, namespace: str = ""):
        self.addr = addr.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"X-Vault-Token": token, "X-Vault-Request": "true"})
        if namespace:
            self.s.headers["X-Vault-Namespace"] = namespace

    def list(self, path: str) -> list[str]:
        r = self.s.request("LIST", f"{self.addr}/v1/{path.lstrip('/')}")
        if r.status_code in (403, 404):
            return []
        r.raise_for_status()
        return r.json().get("data", {}).get("keys", [])

    def read(self, path: str) -> dict:
        r = self.s.get(f"{self.addr}/v1/{path.lstrip('/')}")
        if r.status_code in (403, 404):
            return {}
        r.raise_for_status()
        return r.json().get("data", {})

    def sys_mounts(self) -> dict:
        r = self.s.get(f"{self.addr}/v1/sys/mounts")
        r.raise_for_status()
        d = r.json()
        return d.get("data", d)

    def sys_auth(self) -> dict:
        r = self.s.get(f"{self.addr}/v1/sys/auth")
        r.raise_for_status()
        d = r.json()
        return d.get("data", d)


# ── Metric collectors ─────────────────────────────────────────────────────────
def _to_hours(ttl) -> float:
    """Convert Vault TTL (int seconds or string like '72h') to float hours."""
    if not ttl:
        return 0.0
    s = str(ttl).strip()
    try:
        if s.endswith("h"):  return float(s[:-1])
        if s.endswith("m"):  return float(s[:-1]) / 60
        if s.endswith("s"):  return float(s[:-1]) / 3600
        return float(s) / 3600
    except ValueError:
        return 0.0


def _cert_expiry_ts(pem: str) -> Optional[float]:
    """Return Unix timestamp of a PEM certificate's expiry, or None."""
    if not HAS_CRYPTO or not pem:
        return None
    try:
        cert = cx509.load_pem_x509_certificate(pem.encode(), default_backend())
        try:
            return cert.not_valid_after_utc.timestamp()
        except AttributeError:
            return cert.not_valid_after.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def count_kv(vault: Vault, mount: str, version: str) -> tuple[int, list[str]]:
    """Recursively count all secrets in a KV mount (v1 or v2)."""
    errors: list[str] = []

    def recurse(path: str) -> int:
        try:
            keys = vault.list(path)
        except Exception as e:
            errors.append(f"list {path}: {e}")
            return 0
        return sum(recurse(path + k) if k.endswith("/") else 1 for k in keys)

    base = f"{mount}/metadata/" if version == "2" else f"{mount}/"
    return recurse(base), errors


def count_roles(vault: Vault, *paths: str) -> int:
    """Try each path, return non-folder key count from first non-empty hit."""
    for path in paths:
        try:
            keys = vault.list(path)
            if keys:
                return len([k for k in keys if not k.endswith("/")])
        except Exception:
            pass
    return 0


def pki_metrics(vault: Vault, mount: str) -> tuple[float, int, list[str]]:
    """Compute PKI RU = Σ (remaining_hours / 730) for active certs."""
    errors: list[str] = []
    now = datetime.now(timezone.utc).timestamp()
    serials = vault.list(f"{mount}/certs")
    ru, active = 0.0, 0

    for serial in serials:
        if serial.endswith("/"):
            continue
        try:
            data = vault.read(f"{mount}/cert/{serial}")
            expiry = _cert_expiry_ts(data.get("certificate", ""))
            if expiry is None:
                raw = data.get("expiration")
                expiry = float(raw) if raw else None
            if expiry and expiry > now:
                active += 1
                ru += ((expiry - now) / 3600) / HOURS_PER_MONTH
        except Exception as e:
            errors.append(f"pki cert {serial}: {e}")

    return ru, active, errors


def ssh_metrics(vault: Vault, mount: str) -> tuple[float, int, list[str]]:
    """Compute SSH RU = Σ (role_TTL_hours / 730) across all roles."""
    errors: list[str] = []
    roles = vault.list(f"{mount}/roles")
    ru, count = 0.0, 0

    for role in roles:
        if role.endswith("/"):
            continue
        try:
            data = vault.read(f"{mount}/roles/{role}")
            ttl = data.get("ttl") or data.get("default_ttl", 0)
            h = _to_hours(ttl)
            if h > 0:
                count += 1
                ru += h / HOURS_PER_MONTH
        except Exception as e:
            errors.append(f"ssh role {role}: {e}")

    return ru, count, errors


# ── Print helpers ─────────────────────────────────────────────────────────────
def section(title: str):
    print()
    print(C(B("━" * W)))
    print(C(B(f"  {title}")))
    print(C(B("━" * W)))


def row(label: str, val: str):
    """One data row with dot fill."""
    pad = W - 2 - len(label) - len(val)
    print(f"  {label}{D('·' * max(pad, 1))}{val}")


def total_line(label: str, val: str):
    """Separator + bold total."""
    print(D("  " + "─" * (W - 2)))
    pad = W - 2 - len(label) - len(val)
    print(f"  {B(label)}{' ' * max(pad, 1)}{G(val)}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    addr  = os.environ.get("VAULT_ADDR",      "http://127.0.0.1:8200")
    token = os.environ.get("VAULT_TOKEN",     "")
    ns    = os.environ.get("VAULT_NAMESPACE", "")

    if not token:
        print(R("✗  VAULT_TOKEN non défini. Exportez-le avant d'exécuter ce script."))
        sys.exit(1)

    # Header box
    inner = W - 2
    print()
    print(B(C("╔" + "═" * inner + "╗")))
    title = f"  VAULT PRICING — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    print(B(C("║")) + title.ljust(inner) + B(C("║")))
    print(B(C("╠" + "═" * inner + "╣")))
    print(B(C("║")) + f"  Vault : {addr}".ljust(inner) + B(C("║")))
    if ns:
        print(B(C("║")) + f"  NS    : {ns}".ljust(inner) + B(C("║")))
    if not HAS_CRYPTO:
        warn = "  ⚠  'cryptography' absent — TTL PKI estimé (pip install cryptography)"
        print(B(C("║")) + Y(warn).ljust(inner + 9) + B(C("║")))
    print(B(C("╚" + "═" * inner + "╝")))

    vault = Vault(addr, token, ns)
    all_errors: list[str] = []

    try:
        smounts = vault.sys_mounts()
        amounts = vault.sys_auth()
    except Exception as e:
        print(R(f"\n✗  Impossible de lister les mounts Vault : {e}"))
        sys.exit(1)

    # ── 1. Static Secrets (KV) ─────────────────────────────────────────────
    section("1. SECRETS STATIQUES  (KV)  — high-water mark : snapshot courant")

    kv_items = [(m, i) for m, i in smounts.items() if i.get("type") in ("kv", "generic")]
    total_kv = 0
    for mount, info in sorted(kv_items):
        m = mount.rstrip("/")
        ver = info.get("options", {}).get("version", "1")
        n, errs = count_kv(vault, m, ver)
        all_errors.extend(errs)
        total_kv += n
        row(f"{m:<28} (kv v{ver})", f"{n:>5} secrets")
    if not kv_items:
        print(D("  (aucun mount KV détecté)"))
    total_line("TOTAL Secrets Statiques", f"{total_kv:>5}")

    # ── 2. Dynamic Secrets (Roles) ─────────────────────────────────────────
    section("2. SECRETS DYNAMIQUES  — rôles configurés (high-water mark)")

    total_dyn = 0

    for mount, info in sorted(amounts.items()):
        mt = info.get("type", "")
        if mt not in AUTH_DYNAMIC:
            continue
        m = mount.rstrip("/")
        n = count_roles(vault, f"auth/{m}/role", f"auth/{m}/roles", f"auth/{m}/groups")
        if n:
            total_dyn += n
            row(f"{m:<28} ({mt})", f"{n:>5} rôles")

    for mount, info in sorted(smounts.items()):
        mt = info.get("type", "")
        if mt not in ENGINE_DYNAMIC:
            continue
        m = mount.rstrip("/")
        n = count_roles(vault, f"{m}/roles", f"{m}/role", f"{m}/roleset")
        if n:
            total_dyn += n
            row(f"{m:<28} ({mt} engine)", f"{n:>5} rôles")

    if not total_dyn:
        print(D("  (aucun rôle de secrets dynamiques détecté)"))
    total_line("TOTAL Dynamic Roles", f"{total_dyn:>5}")

    # ── 3. PKI Certificates ────────────────────────────────────────────────
    section("3. PKI  —  RU = nb_certs_actifs × (TTL_restant_h ÷ 730)")

    pki_items = [(m.rstrip("/"), i) for m, i in smounts.items() if i.get("type") == "pki"]
    total_pki = 0.0
    for mount, _ in sorted(pki_items):
        ru, n_certs, errs = pki_metrics(vault, mount)
        all_errors.extend(errs)
        total_pki += ru
        row(f"{mount:<28} ({n_certs} certs actifs)", f"{ru:>8.3f} RU")
    if not pki_items:
        print(D("  (aucun mount PKI détecté)"))
    total_line("TOTAL PKI", f"{total_pki:>8.3f} RU")

    # ── 4. SSH ─────────────────────────────────────────────────────────────
    section("4. SSH  —  RU = Σ (TTL_rôle_h ÷ 730)  par rôle")

    ssh_items = [(m.rstrip("/"), i) for m, i in smounts.items() if i.get("type") == "ssh"]
    total_ssh = 0.0
    for mount, _ in sorted(ssh_items):
        ru, n_roles, errs = ssh_metrics(vault, mount)
        all_errors.extend(errs)
        total_ssh += ru
        row(f"{mount:<28} ({n_roles} rôles)", f"{ru:>8.3f} RU")
    if not ssh_items:
        print(D("  (aucun mount SSH détecté)"))
    total_line("TOTAL SSH", f"{total_ssh:>8.3f} RU")

    # ── 5. Transit / Transform / KMSE ─────────────────────────────────────
    section("5. TRANSIT / TRANSFORM & KMSE")

    transit   = [(m.rstrip("/"), i) for m, i in smounts.items() if i.get("type") == "transit"]
    transform = [(m.rstrip("/"), i) for m, i in smounts.items() if i.get("type") == "transform"]
    kmse      = [(m.rstrip("/"), i) for m, i in smounts.items() if i.get("type") == "keymgmt"]

    total_tr = total_tf = total_km = 0

    for mount, _ in sorted(transit):
        n = count_roles(vault, f"{mount}/keys")
        total_tr += n
        row(f"{mount:<28} (transit)", f"{n:>5} clés")
    for mount, _ in sorted(transform):
        n = count_roles(vault, f"{mount}/role", f"{mount}/roles")
        total_tf += n
        row(f"{mount:<28} (transform)", f"{n:>5} rôles")
    for mount, _ in sorted(kmse):
        n = count_roles(vault, f"{mount}/key")
        total_km += n
        row(f"{mount:<28} (KMSE)", f"{n:>5} clés managées")

    if not (transit or transform or kmse):
        print(D("  (aucun mount Transit/Transform/KMSE détecté)"))
    if transit or transform:
        print()
        print(D("  Transit/Transform : facturé par appel API — comptage non disponible ici"))
        total_line("Clés Transit + Transform configurées", f"{total_tr + total_tf:>5}")
    if kmse:
        total_line("TOTAL KMSE (clés managées)", f"{total_km:>5}")

    # ── Résumé global ──────────────────────────────────────────────────────
    print()
    print(C(B("═" * W)))
    print(C(B("  RÉSUMÉ PRICING")))
    print(C(B("═" * W)))

    summary = [
        ("Secrets Statiques (KV)",           f"{total_kv:>5}"),
        ("Dynamic Roles",                     f"{total_dyn:>5}"),
        ("PKI (RU)",                          f"{total_pki:>8.3f}"),
        ("SSH (RU)",                          f"{total_ssh:>8.3f}"),
    ]
    if transit or transform:
        summary.append(("Transit/Transform (clés)",    f"{total_tr + total_tf:>5}"))
    if kmse:
        summary.append(("KMSE (clés managées)",        f"{total_km:>5}"))

    for label, val in summary:
        pad = W - 2 - len(label) - len(val)
        print(f"  {label}{' ' * max(pad, 1)}{G(val)}")

    print(C(B("═" * W)))

    # ── Avertissements ─────────────────────────────────────────────────────
    if all_errors:
        print()
        print(Y(f"  ⚠  {len(all_errors)} avertissement(s) :"))
        for err in all_errors[:10]:
            print(D(f"     • {err}"))
        if len(all_errors) > 10:
            print(D(f"     ... et {len(all_errors) - 10} autres"))

    print()


if __name__ == "__main__":
    main()
