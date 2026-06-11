"""
conftest.py
===========
Testinfra pytest configuration supporting:

  - Multiple inventory roots  (one infra at a time via --infra=infra1)
  - Multi-directory inventory layout:
      inventories/<infra>/
          conf.ini           <- INI-format Ansible inventory  (also accepts hosts.ini)
          group_vars/        <- flat file or per-group directory
          host_vars/         <- per-host YAML files
          infra_vars.yml     <- optional infra-level overrides
  - Multiple roles  (--role-roots=role1,role2,role3,role4)
      All role defaults are equal-weight fallbacks;
      group_vars always beats role defaults.

Variable merge order (lowest → highest priority):
  all role defaults (merged, equal weight)
    └─▶ group_vars/all.yml
          └─▶ group_vars/certificate_group.yml
                └─▶ infra_vars.yml
                      └─▶ host_vars/<hostname>.yml   (per-test only)

NOTE ON PARAMETRISATION
  pytest_generate_tests() here reads hosts.ini at *collection time* using
  only CLI options (no fixtures).  This is the only correct approach —
  fixture values are not available during collection, which is why
  `params=lambda` and `_store` tricks raise TypeError.
"""

import os
import re
import pathlib

import pytest
import yaml


# ─────────────────────────────────────────────────────────────────────────────
# YAML / merge helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_yaml(path: str) -> dict:
    p = pathlib.Path(path)
    if not p.is_file():
        return {}
    data = yaml.safe_load(p.read_text()) or {}
    return data if isinstance(data, dict) else {}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into a copy of *base*. Override wins."""
    result = base.copy()
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _load_group_vars_dir(group_vars_dir: str, group_name: str) -> dict:
    """
    Load group_vars for *group_name*.
    Handles: group_vars/<name>.yml  AND  group_vars/<name>/  (directory).
    Also loads group_vars/all first (lowest layer).
    """
    base = pathlib.Path(group_vars_dir)
    result: dict = {}

    def _absorb(target: str) -> None:
        nonlocal result
        flat = base / f"{target}.yml"
        if flat.is_file():
            result = _deep_merge(result, _load_yaml(str(flat)))
        d = base / target
        if d.is_dir():
            for f in sorted(d.glob("*.yml")):
                result = _deep_merge(result, _load_yaml(str(f)))

    _absorb("all")
    _absorb(group_name)
    return result


def _load_host_vars(host_vars_dir: str, hostname: str) -> dict:
    """Load host_vars/<hostname>.yml or host_vars/<hostname>/."""
    base = pathlib.Path(host_vars_dir)
    result: dict = {}
    flat = base / f"{hostname}.yml"
    if flat.is_file():
        result = _deep_merge(result, _load_yaml(str(flat)))
    d = base / hostname
    if d.is_dir():
        for f in sorted(d.glob("*.yml")):
            result = _deep_merge(result, _load_yaml(str(f)))
    return result


def _load_all_role_defaults(role_roots: list) -> dict:
    """Merge defaults/main.yml from every role. All roles equal weight."""
    merged: dict = {}
    for role_path in role_roots:
        defaults = _load_yaml(os.path.join(role_path, "defaults", "main.yml"))
        merged = _deep_merge(merged, defaults)
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# INI inventory parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ini_hosts(hosts_ini_path: str, group: str) -> list:
    """
    Parse an Ansible INI inventory and return all hostnames under *group*.

    Uses plain line-by-line parsing — NOT configparser.
    configparser splits on '=' so a line like:
        server1.example.com ansible_host=10.0.0.1
    produces the key 'server1.example.com ansible_host', not 'server1.example.com'.

    This parser correctly:
      - Ignores bare lines before the first [section] (e.g. localhost ...)
      - Normalises spaces around ':' in headers ([group: children] is valid Ansible)
      - Extracts only the first token of each host line as the hostname
      - Resolves [group:children] one level deep
      - Excludes localhost / 127.0.0.1 (controller-only entries)
    """
    p = pathlib.Path(hosts_ini_path)
    if not p.is_file():
        return []

    sections: dict = {}        # section_name -> [hostname, ...]
    current_section = None
    section_re = re.compile(r"^\[(.+?)\]\s*$")

    for raw_line in p.read_text().splitlines():
        line = raw_line.strip()

        # skip blank lines and comments
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        m = section_re.match(line)
        if m:
            # normalise "group : children" -> "group:children"
            header = re.sub(r"\s*:\s*", ":", m.group(1)).strip()
            current_section = header
            sections.setdefault(current_section, [])
            continue

        if current_section is None:
            # bare line before first [section] (e.g. localhost ...) — skip
            continue

        # First whitespace-delimited token is the hostname or child-group name
        hostname = line.split()[0]
        sections[current_section].append(hostname)

    def _hosts_in(section: str) -> list:
        return sections.get(section, [])

    hosts = list(_hosts_in(group))

    # Resolve :children one level deep
    for child_group in _hosts_in(f"{group}:children"):
        hosts.extend(_hosts_in(child_group))

    # Deduplicate, preserve order, exclude controller-only entries
    _exclude = {"localhost", "127.0.0.1"}
    seen: set = set()
    unique: list = []
    for h in hosts:
        if h not in seen and h not in _exclude:
            seen.add(h)
            unique.append(h)
    return unique


def _find_hosts_ini(infra_dir: str) -> str:
    """Find the INI inventory file inside an infra directory.
    conf.ini is checked first as that is the convention for this project.
    """
    for candidate in ("conf.ini", "hosts.ini", "hosts", "inventory.ini"):
        p = os.path.join(infra_dir, candidate)
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(
        f"No INI inventory file found under {infra_dir}. "
        "Tried: conf.ini, hosts.ini, hosts, inventory.ini"
    )


# ─────────────────────────────────────────────────────────────────────────────
# CLI options
# ─────────────────────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption(
        "--infra",
        default=os.environ.get("INFRA", ""),
        help="Infra name to test, e.g. --infra=infra1  (maps to inventories/<infra>/)",
    )
    parser.addoption(
        "--inventories",
        default=os.environ.get("INVENTORIES_ROOT", "inventories"),
        help="Root folder containing per-infra inventory subdirectories (default: inventories)",
    )
    parser.addoption(
        "--role-roots",
        default=os.environ.get("ROLE_ROOTS", "roles/ipa_cert"),
        help=(
            "Comma-separated role directories whose defaults/main.yml are loaded. "
            "Example: roles/ipa_cert,roles/ipa_client,roles/common_tls"
        ),
    )
    parser.addoption(
        "--cert-group",
        default=os.environ.get("CERT_GROUP", "ipa_client"),
        help="Ansible group name containing certificate hosts (default: ipa_client)",
    )


# ─────────────────────────────────────────────────────────────────────────────
# pytest_generate_tests — the ONLY correct place to parametrise with hosts
#
# This hook runs at COLLECTION TIME when no fixtures are available yet.
# We read CLI options directly via metafunc.config.getoption().
# ─────────────────────────────────────────────────────────────────────────────

def pytest_generate_tests(metafunc):
    """
    Inject cert_host parameter for any test that declares it as a fixture.
    Reads hosts from:
      1. CERTIFICATE_HOSTS env var (comma-separated)  — highest priority
      2. hosts.ini parsed for [<cert_group>]
    """
    if "cert_host" not in metafunc.fixturenames:
        return

    # 1. env-var override (useful for quick targeted runs)
    env_hosts = os.environ.get("CERTIFICATE_HOSTS", "")
    if env_hosts:
        hosts = [h.strip() for h in env_hosts.split(",") if h.strip()]
        metafunc.parametrize("cert_host", hosts, scope="module")
        return

    # 2. parse hosts.ini at collection time using CLI options only
    infra      = metafunc.config.getoption("--infra")
    inv_root   = metafunc.config.getoption("--inventories")
    cert_group = metafunc.config.getoption("--cert-group")

    if not infra:
        pytest.exit(
            "ERROR: --infra is required.\n"
            "  Example: pytest tests/ --infra=infra1\n"
            "  Or set:  export INFRA=infra1",
            returncode=1,
        )

    infra_dir = os.path.join(inv_root, infra)
    if not os.path.isdir(infra_dir):
        pytest.exit(
            f"ERROR: Inventory directory not found: {infra_dir}\n"
            f"  Expected: {inv_root}/<infra>/hosts.ini",
            returncode=1,
        )

    try:
        hosts_ini = _find_hosts_ini(infra_dir)
    except FileNotFoundError as exc:
        pytest.exit(f"ERROR: {exc}", returncode=1)

    hosts = _parse_ini_hosts(hosts_ini, cert_group)
    if not hosts:
        pytest.exit(
            f"ERROR: No hosts found under [{cert_group}] in {hosts_ini}.\n"
            "  Check your inventory or set CERTIFICATE_HOSTS env var.",
            returncode=1,
        )

    metafunc.parametrize("cert_host", hosts, scope="module")


# ─────────────────────────────────────────────────────────────────────────────
# Path fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def infra_name(request) -> str:
    name = request.config.getoption("--infra")
    assert name, "--infra is required (or set INFRA env var)"
    return name


@pytest.fixture(scope="session")
def inventories_root(request) -> str:
    return request.config.getoption("--inventories")


@pytest.fixture(scope="session")
def infra_inventory_dir(infra_name, inventories_root) -> str:
    d = os.path.join(inventories_root, infra_name)
    assert os.path.isdir(d), f"Inventory directory not found: {d}"
    return d


@pytest.fixture(scope="session")
def role_roots(request) -> list:
    raw = request.config.getoption("--role-roots")
    return [r.strip() for r in raw.split(",") if r.strip()]


@pytest.fixture(scope="session")
def cert_group_name(request) -> str:
    return request.config.getoption("--cert-group")


@pytest.fixture(scope="session")
def hosts_ini_path(infra_inventory_dir) -> str:
    return _find_hosts_ini(infra_inventory_dir)


# ─────────────────────────────────────────────────────────────────────────────
# Variable merge fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def all_role_defaults(role_roots) -> dict:
    """Merge defaults/main.yml from all roles. Equal weight, lowest priority."""
    return _load_all_role_defaults(role_roots)


@pytest.fixture(scope="session")
def group_vars_data(infra_inventory_dir, cert_group_name) -> dict:
    """Load group_vars/all + group_vars/certificate_group from the infra dir."""
    gv_dir = os.path.join(infra_inventory_dir, "group_vars")
    return _load_group_vars_dir(gv_dir, cert_group_name)


@pytest.fixture(scope="session")
def infra_vars_data(infra_inventory_dir) -> dict:
    """Load optional infra_vars.yml (infra-level overrides)."""
    for candidate in (
        os.path.join(infra_inventory_dir, "infra_vars.yml"),
        os.path.join(infra_inventory_dir, "infra_vars", "main.yml"),
    ):
        data = _load_yaml(candidate)
        if data:
            return data
    return {}


@pytest.fixture(scope="session")
def merged_vars(all_role_defaults, group_vars_data, infra_vars_data) -> dict:
    """
    Session-level merged variable dict (no host_vars yet).
    Merge order: role defaults < group_vars/all < group_vars/<group> < infra_vars
    """
    base = _deep_merge(all_role_defaults, group_vars_data)
    return _deep_merge(base, infra_vars_data)


# ─────────────────────────────────────────────────────────────────────────────
# Public helper — apply host_vars per test
# ─────────────────────────────────────────────────────────────────────────────

def host_merged_vars_for(hostname: str, infra_inventory_dir: str, base_vars: dict) -> dict:
    """
    Apply host_vars/<hostname> on top of the session-level merged_vars.
    Call this inside individual tests that need per-host variable overrides:

        hvars = host_merged_vars_for(cert_host, infra_inventory_dir, merged_vars)
        owner = hvars.get("cert_owner", cert_owner)
    """
    hv_dir = os.path.join(infra_inventory_dir, "host_vars")
    hv = _load_host_vars(hv_dir, hostname)
    return _deep_merge(base_vars, hv)


# ─────────────────────────────────────────────────────────────────────────────
# Derived variable fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def cert_base_dir(merged_vars) -> str:
    return merged_vars.get("cert_base_dir", "/data/certificates")

@pytest.fixture(scope="session")
def cert_types(merged_vars) -> list:
    return merged_vars.get("cert_types", ["client", "server"])

@pytest.fixture(scope="session")
def cert_validity_days(merged_vars) -> int:
    return int(merged_vars.get("cert_validity_days", 365))

@pytest.fixture(scope="session")
def ipa_realm(merged_vars) -> str:
    return merged_vars.get("ipa_realm", "")

@pytest.fixture(scope="session")
def ipa_domain(merged_vars) -> str:
    return merged_vars.get("ipa_domain", "")

@pytest.fixture(scope="session")
def ipa_ca_subject(merged_vars) -> str:
    return merged_vars.get("ipa_ca_subject", "Certificate Authority")

@pytest.fixture(scope="session")
def cert_owner(merged_vars) -> str:
    return merged_vars.get("cert_owner", "root")

@pytest.fixture(scope="session")
def cert_group(merged_vars) -> str:
    return merged_vars.get("cert_group", "root")

@pytest.fixture(scope="session")
def cert_file_mode(merged_vars) -> str:
    return merged_vars.get("cert_file_mode", "0644")

@pytest.fixture(scope="session")
def key_file_mode(merged_vars) -> str:
    return merged_vars.get("key_file_mode", "0600")

@pytest.fixture(scope="session")
def ipaclient_host_name(merged_vars) -> str:
    return (
        merged_vars.get("ipaclient_host")
        or os.environ.get("IPACLIENT_HOST", "")
    )

@pytest.fixture(scope="session")
def certificate_hosts(hosts_ini_path, cert_group_name) -> list:
    """
    Session fixture version of the host list (used in test_ipaclient.py etc.
    where cert_host parametrisation is not needed but the list is).
    """
    env_hosts = os.environ.get("CERTIFICATE_HOSTS", "")
    if env_hosts:
        return [h.strip() for h in env_hosts.split(",") if h.strip()]
    return _parse_ini_hosts(hosts_ini_path, cert_group_name)


# ─────────────────────────────────────────────────────────────────────────────
# Debug — print resolved config at session start
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def _print_resolved_config(
    infra_name, role_roots, merged_vars,
    certificate_hosts, cert_base_dir,
    ipa_realm, ipa_domain, ipaclient_host_name,
):
    print("\n" + "═" * 64)
    print(f"  INFRA          : {infra_name}")
    print(f"  ROLE ROOTS     : {role_roots}")
    print(f"  CERT HOSTS     : {certificate_hosts}")
    print(f"  CERT BASE DIR  : {cert_base_dir}")
    print(f"  IPA REALM      : {ipa_realm  or '(not set)'}")
    print(f"  IPA DOMAIN     : {ipa_domain or '(not set)'}")
    print(f"  IPACLIENT HOST : {ipaclient_host_name or '(not set)'}")
    print("═" * 64 + "\n")
