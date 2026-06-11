"""
conftest.py
===========
Testinfra pytest configuration supporting:

  - Multiple inventory roots (one infra at a time via --infra=infra1)
  - Multi-directory inventory layout:
      inventories/<infra>/
          hosts.ini          <- INI-format Ansible inventory
          group_vars/        <- YAML files, may be flat or split per-group
          host_vars/         <- YAML files per host
          infra_vars.yml     <- optional infra-level overrides
  - Multiple roles (--role-roots=role1,role2,role3,role4)
      All role defaults are treated as equal-weight fallbacks;
      group_vars beats all role defaults.

Variable merge order (lowest → highest priority):
  all role defaults (merged, equal weight)
    └─▶ group_vars/all.yml          (if present)
          └─▶ group_vars/certificate_group.yml
                └─▶ infra_vars.yml  (infra-level overrides)
                      └─▶ host_vars/<hostname>.yml  (per-test, not session)

CLI flags (all have env-var fallbacks):
  --infra         name of the infra under inventories/  (e.g. infra1)
  --inventories   root folder that contains per-infra subdirs  (default: inventories)
  --role-roots    comma-separated list of role directories     (default: roles/ipa_cert)
"""

import configparser
import os
import pathlib
from typing import Optional

import pytest
import yaml


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_yaml(path: str) -> dict:
    """Load a YAML file; silently return {} if missing or empty."""
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
    Load group_vars for *group_name*. Handles two Ansible conventions:
      1. group_vars/<group_name>.yml          (single file)
      2. group_vars/<group_name>/             (directory of YAMLs)
    Also loads group_vars/all.yml / group_vars/all/ as the lowest layer.
    """
    base = pathlib.Path(group_vars_dir)
    result: dict = {}

    def _absorb(target: str) -> None:
        nonlocal result
        # flat file
        flat = base / f"{target}.yml"
        if flat.is_file():
            result = _deep_merge(result, _load_yaml(str(flat)))
        # directory of YAML files
        d = base / target
        if d.is_dir():
            for f in sorted(d.glob("*.yml")):
                result = _deep_merge(result, _load_yaml(str(f)))

    _absorb("all")            # lowest layer — global group_vars
    _absorb(group_name)       # group-specific layer
    return result


def _load_host_vars(host_vars_dir: str, hostname: str) -> dict:
    """
    Load host_vars for *hostname*. Handles:
      1. host_vars/<hostname>.yml
      2. host_vars/<hostname>/  (directory of YAMLs)
    """
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


def _load_all_role_defaults(role_roots: list[str]) -> dict:
    """
    Load defaults/main.yml from every role.  All roles are equal weight —
    later roles in the list win only on key collision (stable, predictable).
    group_vars will override everything loaded here.
    """
    merged: dict = {}
    for role_path in role_roots:
        defaults = _load_yaml(os.path.join(role_path, "defaults", "main.yml"))
        merged = _deep_merge(merged, defaults)
    return merged


def _parse_ini_hosts(hosts_ini_path: str, group: str) -> list[str]:
    """
    Parse an Ansible INI inventory file and return all hosts under *group*.
    Handles:
      - [group] sections with bare hostnames
      - [group:children] meta-sections (recursively resolved one level)
      - Ansible host patterns are NOT expanded (use simple hostnames)
    """
    p = pathlib.Path(hosts_ini_path)
    if not p.is_file():
        return []

    cfg = configparser.RawConfigParser(allow_no_value=True, delimiters=("=",))
    cfg.optionxform = str          # preserve case
    cfg.read(str(p))

    def _section_hosts(section: str) -> list[str]:
        if not cfg.has_section(section):
            return []
        return [k for k, _ in cfg.items(section)]

    # direct hosts
    hosts = _section_hosts(group)

    # hosts from child groups  [group:children]
    children_section = f"{group}:children"
    for child_group in _section_hosts(children_section):
        hosts.extend(_section_hosts(child_group))

    # deduplicate while preserving order
    seen: set = set()
    unique: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


# ─────────────────────────────────────────────────────────────────────────────
# CLI options
# ─────────────────────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption(
        "--infra",
        default=os.environ.get("INFRA", ""),
        help="Infra name to test (e.g. infra1). Maps to inventories/<infra>/",
    )
    parser.addoption(
        "--inventories",
        default=os.environ.get("INVENTORIES_ROOT", "inventories"),
        help="Root folder containing per-infra inventory directories (default: inventories)",
    )
    parser.addoption(
        "--role-roots",
        default=os.environ.get("ROLE_ROOTS", "roles/ipa_cert"),
        help=(
            "Comma-separated list of role directories whose defaults/main.yml "
            "should be loaded (e.g. roles/ipa_cert,roles/ipa_client). "
            "All role defaults are equal weight; group_vars overrides all."
        ),
    )
    parser.addoption(
        "--cert-group",
        default=os.environ.get("CERT_GROUP", "certificate_group"),
        help="Ansible group name that contains certificate hosts (default: certificate_group)",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Path fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def infra_name(request) -> str:
    name = request.config.getoption("--infra")
    assert name, (
        "--infra is required. Example: pytest tests/ --infra=infra1\n"
        "Or set the INFRA environment variable."
    )
    return name


@pytest.fixture(scope="session")
def inventories_root(request) -> str:
    return request.config.getoption("--inventories")


@pytest.fixture(scope="session")
def infra_inventory_dir(infra_name, inventories_root) -> str:
    """Absolute path to inventories/<infra>/"""
    d = os.path.join(inventories_root, infra_name)
    assert os.path.isdir(d), (
        f"Inventory directory not found: {d}\n"
        f"Expected structure: {inventories_root}/<infra>/hosts.ini"
    )
    return d


@pytest.fixture(scope="session")
def role_roots(request) -> list[str]:
    """List of role root paths parsed from --role-roots."""
    raw = request.config.getoption("--role-roots")
    roots = [r.strip() for r in raw.split(",") if r.strip()]
    missing = [r for r in roots if not os.path.isdir(r)]
    if missing:
        pytest.warnings.warn(
            f"Role directories not found (defaults skipped): {missing}"
        )
    return roots


@pytest.fixture(scope="session")
def cert_group_name(request) -> str:
    return request.config.getoption("--cert-group")


@pytest.fixture(scope="session")
def hosts_ini_path(infra_inventory_dir) -> str:
    """Path to the hosts.ini file inside the infra inventory dir."""
    candidates = ["hosts.ini", "hosts", "inventory.ini", "conf.ini"]
    for c in candidates:
        p = os.path.join(infra_inventory_dir, c)
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(
        f"No INI inventory file found under {infra_inventory_dir}. "
        f"Tried: {candidates}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Variable merge fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def all_role_defaults(role_roots) -> dict:
    """
    Merge defaults/main.yml from all roles.
    All roles are equal weight — this is the lowest-priority layer.
    """
    return _load_all_role_defaults(role_roots)


@pytest.fixture(scope="session")
def group_vars_data(infra_inventory_dir, cert_group_name) -> dict:
    """
    Load group_vars for 'all' and 'certificate_group' from the infra inventory.
    Handles both flat-file and directory-per-group conventions.
    """
    gv_dir = os.path.join(infra_inventory_dir, "group_vars")
    return _load_group_vars_dir(gv_dir, cert_group_name)


@pytest.fixture(scope="session")
def infra_vars_data(infra_inventory_dir) -> dict:
    """
    Load optional infra-level variable overrides.
    Looks for infra_vars.yml (or infra_vars/main.yml) in the infra dir.
    """
    candidates = [
        os.path.join(infra_inventory_dir, "infra_vars.yml"),
        os.path.join(infra_inventory_dir, "infra_vars", "main.yml"),
    ]
    for c in candidates:
        data = _load_yaml(c)
        if data:
            return data
    return {}


@pytest.fixture(scope="session")
def merged_vars(all_role_defaults, group_vars_data, infra_vars_data) -> dict:
    """
    Final merged variable dict (session-scoped, no host_vars applied yet).

    Merge order (lowest → highest):
      all role defaults
        └─▶ group_vars/all  +  group_vars/certificate_group
              └─▶ infra_vars.yml

    host_vars are applied per-test via host_merged_vars_for().
    """
    base = _deep_merge(all_role_defaults, group_vars_data)
    return _deep_merge(base, infra_vars_data)


# ─────────────────────────────────────────────────────────────────────────────
# Public helper: apply host_vars on top of session merged_vars
# ─────────────────────────────────────────────────────────────────────────────

def host_merged_vars_for(hostname: str, infra_inventory_dir: str, base_vars: dict) -> dict:
    """
    Return the fully merged variable dict for a specific host.

    Precedence (lowest → highest):
      all role defaults < group_vars < infra_vars < host_vars/<hostname>

    Call this inside tests that need per-host variable overrides:
        vars = host_merged_vars_for(cert_host, infra_inventory_dir, merged_vars)
    """
    hv_dir = os.path.join(infra_inventory_dir, "host_vars")
    hv = _load_host_vars(hv_dir, hostname)
    return _deep_merge(base_vars, hv)


# ─────────────────────────────────────────────────────────────────────────────
# Host discovery fixture
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def certificate_hosts(hosts_ini_path, cert_group_name, merged_vars) -> list[str]:
    """
    Ordered list of hostnames in the certificate_group.
    Discovery order:
      1. CERTIFICATE_HOSTS env var (comma-separated) — highest priority
      2. hosts.ini parsed for [certificate_group]
    """
    env_hosts = os.environ.get("CERTIFICATE_HOSTS", "")
    if env_hosts:
        return [h.strip() for h in env_hosts.split(",") if h.strip()]
    hosts = _parse_ini_hosts(hosts_ini_path, cert_group_name)
    assert hosts, (
        f"No hosts found under [{cert_group_name}] in {hosts_ini_path}.\n"
        f"Check your inventory or set CERTIFICATE_HOSTS env var."
    )
    return hosts


# ─────────────────────────────────────────────────────────────────────────────
# Derived variable fixtures  (all read from merged_vars)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def cert_base_dir(merged_vars) -> str:
    return merged_vars.get("cert_base_dir", "/data/certificates")

@pytest.fixture(scope="session")
def cert_types(merged_vars) -> list[str]:
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


# ─────────────────────────────────────────────────────────────────────────────
# Debug fixture — print the resolved variable set at session start
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def _print_resolved_config(
    infra_name, role_roots, merged_vars, certificate_hosts, cert_base_dir,
    ipa_realm, ipa_domain, ipaclient_host_name
):
    """Print a summary of resolved variables so failures are easy to diagnose."""
    print("\n" + "═" * 60)
    print(f"  INFRA             : {infra_name}")
    print(f"  ROLE ROOTS        : {role_roots}")
    print(f"  CERT HOSTS        : {certificate_hosts}")
    print(f"  CERT BASE DIR     : {cert_base_dir}")
    print(f"  IPA REALM         : {ipa_realm or '(not set)'}")
    print(f"  IPA DOMAIN        : {ipa_domain or '(not set)'}")
    print(f"  IPACLIENT HOST    : {ipaclient_host_name or '(not set)'}")
    print("═" * 60 + "\n")
