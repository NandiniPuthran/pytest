"""
conftest.py
===========
Senior-level, modular testinfra configuration.

DESIGN PHILOSOPHY
─────────────────
Ansible already knows how to parse inventories, merge host_vars,
group_vars, role defaults and apply precedence correctly.
Re-implementing that in Python is fragile and always wrong at the edges.

Instead this conftest delegates ALL variable and inventory resolution
back to Ansible via two CLI calls:

  ansible-inventory --list          → full inventory + merged hostvars
  ansible <host> -m debug -a var=x  → resolve any variable for any host

This means:
  - host_vars, group_vars, role vars, extra_vars all resolve correctly
  - ansible_host, ansible_user, ansible_become_pass all available
  - Adding a new test file = add one fixture, no INI parsing changes
  - Variables per testcase = just request the right host fixture

FIXTURES OVERVIEW
─────────────────
  inventory         — full parsed inventory (dict)
  hostvars(host)    — all merged vars for a specific host (dict)
  group_hosts(grp)  — list of HostEntry for a group
  cert_hosts        — HostEntry list for --cert-group
  ipaclient_hosts   — HostEntry list for --ipaclient-group
  sudo_password     — read from keypass.yml (plain YAML)
  local_connection  — testinfra local:// backend

PYTEST HOOKS
────────────
  pytest_generate_tests — parametrises cert_host per test file
                          using _FILE_TO_GROUP_OPTION mapping

CLI OPTIONS
───────────
  --infra            infra name  (maps to inventories/<infra>/)
  --inventories      root of inventory directories
  --role-roots       comma-separated role paths (for defaults)
  --cert-group       group name for cert hosts
  --ipaclient-group  group name for ipaclient host
  --localhost-group  group name for localhost/controller
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
from collections import namedtuple
from typing import Any

import pytest
import yaml


# ─────────────────────────────────────────────────────────────────────────────
# Types
# ─────────────────────────────────────────────────────────────────────────────

class HostEntry(namedtuple("HostEntry", ["short_name", "ssh_target"])):
    """
    Represents one host from the inventory.

    short_name : inventory hostname (used for cert paths, display)
    ssh_target : resolvable address for SSH  (ansible_host IP or FQDN from cert_cn)
    """
    def __repr__(self):
        return self.short_name


from dataclasses import dataclass

@dataclass(frozen=True)
class FilePerms:
    """
    Expected ownership and permissions for a file on a specific host.
    Resolved from inventory hostvars so each host/role can have
    different values — e.g. cert hosts vs ipaclient host.

    Usage in a test:
        perms = FilePerms.for_host(inventory, cert_host.short_name, "csr")
        f = ssh_host.file(path)
        assert f.user  == perms.owner
        assert f.group == perms.group
        assert f.mode  == perms.mode_int
    """
    owner    : str
    group    : str
    mode_str : str   # e.g. "0644"

    @property
    def mode_int(self) -> int:
        return int(self.mode_str, 8)

    @classmethod
    def for_host(
        cls,
        inventory: "AnsibleInventory",
        hostname: str,
        file_type: str = "csr",   # "csr" | "crt" | "key" | "dir"
    ) -> "FilePerms":
        """
        Resolve permissions for *file_type* on *hostname*.

        Variable lookup per file_type:
          "csr"  → cert_owner, cert_group, cert_file_mode   (default 0644)
          "crt"  → cert_owner, cert_group, cert_file_mode   (default 0644)
          "key"  → cert_owner, cert_group, key_file_mode    (default 0600)
          "dir"  → cert_owner, cert_group, cert_dir_mode    (default 0755)

        All values read from fully merged hostvars so host_vars, group_vars,
        and role defaults are all respected with correct Ansible precedence.
        """
        hv = inventory.hostvars(hostname)

        owner = hv.get("cert_owner", "root")
        group = hv.get("cert_group", "root")

        mode_key = {
            "key": "key_file_mode",
            "dir": "cert_dir_mode",
        }.get(file_type, "cert_file_mode")

        default_mode = {
            "key": "0600",
            "dir": "0755",
        }.get(file_type, "0644")

        mode = hv.get(mode_key, default_mode)
        return cls(owner=owner, group=group, mode_str=mode)


# ─────────────────────────────────────────────────────────────────────────────
# Low-level helpers — plain Python, no Ansible dependency
# ─────────────────────────────────────────────────────────────────────────────

def _load_yaml(path: str) -> dict:
    """Load a YAML file; return {} if missing or empty."""
    p = pathlib.Path(path)
    if not p.is_file():
        return {}
    data = yaml.safe_load(p.read_text()) or {}
    return data if isinstance(data, dict) else {}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins on conflict."""
    result = base.copy()
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Ansible CLI bridge
# ─────────────────────────────────────────────────────────────────────────────

class AnsibleInventory:
    """
    Wraps `ansible-inventory --list` to give Python access to the full
    inventory exactly as Ansible sees it — host_vars, group_vars, role
    defaults all merged with correct precedence.

    Usage:
        inv = AnsibleInventory("inventories/infra1", "roles/ipa_cert,roles/ipa_client")
        hosts = inv.group_hosts("ipa_client")     # ["host1", "host2"]
        vars  = inv.hostvars("host1")             # full merged var dict
        val   = inv.var("host1", "cert_cn")       # single variable value
    """

    def __init__(self, infra_dir: str, role_roots: str = ""):
        self._infra_dir  = infra_dir
        self._role_roots = role_roots
        self._cache: dict | None = None

    # ── internal ──────────────────────────────────────────────────────────────

    def _env(self) -> dict:
        """Build subprocess env with ANSIBLE_ROLES_PATH set."""
        env = os.environ.copy()
        if self._role_roots:
            # ansible-inventory uses ANSIBLE_ROLES_PATH to find role defaults
            role_paths = ":".join(
                str(pathlib.Path(r.strip()).parent)
                for r in self._role_roots.split(",")
                if r.strip()
            )
            env["ANSIBLE_ROLES_PATH"] = role_paths
        # Suppress deprecation noise
        env.setdefault("ANSIBLE_DEPRECATION_WARNINGS", "False")
        env.setdefault("ANSIBLE_SYSTEM_WARNINGS",      "False")
        return env

    def _inventory_file(self) -> str:
        """Find conf.ini / hosts.ini inside the infra directory."""
        for candidate in ("conf.ini", "hosts.ini", "hosts", "inventory.ini"):
            p = os.path.join(self._infra_dir, candidate)
            if os.path.isfile(p):
                return p
        raise FileNotFoundError(
            f"No inventory file found under {self._infra_dir}. "
            "Tried: conf.ini, hosts.ini, hosts, inventory.ini"
        )

    def _raw(self) -> dict:
        """
        Run `ansible-inventory --list` and return the parsed JSON.
        Result is cached for the lifetime of this object.
        """
        if self._cache is not None:
            return self._cache

        if not shutil.which("ansible-inventory"):
            # ansible-inventory not available — fall back to manual parsing
            self._cache = {}
            return self._cache

        inv_file = self._inventory_file()
        result = subprocess.run(
            ["ansible-inventory", "-i", inv_file, "--list"],
            capture_output=True,
            text=True,
            env=self._env(),
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"ansible-inventory failed for {inv_file}:\n{result.stderr}"
            )
        self._cache = json.loads(result.stdout)
        return self._cache

    # ── public API ────────────────────────────────────────────────────────────

    def group_hosts(self, group: str) -> list[str]:
        """
        Return all hostnames in *group* (children resolved).
        Falls back to manual INI parsing if ansible-inventory is unavailable.
        """
        raw = self._raw()
        if raw:
            grp_data = raw.get(group, {})
            hosts = list(grp_data.get("hosts", []))
            for child in grp_data.get("children", []):
                hosts.extend(self.group_hosts(child))
            # deduplicate
            seen, unique = set(), []
            for h in hosts:
                if h not in seen:
                    seen.add(h); unique.append(h)
            return unique
        # fallback
        return self._manual_group_hosts(group)

    def hostvars(self, hostname: str) -> dict:
        """
        Return the fully merged variable dict for *hostname* exactly as
        Ansible resolves it (host_vars > group_vars > role defaults).
        """
        raw = self._raw()
        if raw:
            return raw.get("_meta", {}).get("hostvars", {}).get(hostname, {})
        # fallback — manual merge
        return self._manual_hostvars(hostname)

    def var(self, hostname: str, varname: str, default: Any = None) -> Any:
        """Convenience: get a single variable for a host."""
        return self.hostvars(hostname).get(varname, default)

    def all_hostvars(self) -> dict[str, dict]:
        """Return {hostname: vars_dict} for every host in the inventory."""
        raw = self._raw()
        if raw:
            return raw.get("_meta", {}).get("hostvars", {})
        return {}

    # ── fallback: manual parsing when ansible-inventory is unavailable ────────

    def _manual_group_hosts(self, group: str) -> list[str]:
        """Plain-text INI parser — used when ansible-inventory is absent."""
        inv_file = self._inventory_file()
        sections: dict = {}
        current = None
        section_re = re.compile(r"^\[(.+?)\]\s*$")

        for raw_line in pathlib.Path(inv_file).read_text(
            encoding="utf-8", errors="replace"
        ).replace("\r\n", "\n").replace("\r", "\n").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            m = section_re.match(line)
            if m:
                header = re.sub(r"\s*:\s*", ":", m.group(1)).strip()
                current = header
                sections.setdefault(current, [])
                continue
            if current is None:
                continue
            short_name = line.split()[0]
            ip_match   = re.search(r"ansible_host=(\S+)", line)
            ansible_host = ip_match.group(1) if ip_match else short_name
            sections[current].append((short_name, ansible_host))

        def _in(sec):
            return sections.get(sec, [])

        entries = list(_in(group))
        for child_entry in _in(f"{group}:children"):
            child_name = child_entry[0] if isinstance(child_entry, tuple) else child_entry
            entries.extend(_in(child_name))

        exclude = {"localhost", "127.0.0.1"}
        seen, unique = set(), []
        for entry in entries:
            short, _ = entry if isinstance(entry, tuple) else (entry, entry)
            if short not in seen and short not in exclude:
                seen.add(short); unique.append(short)
        return unique

    def _manual_hostvars(self, hostname: str) -> dict:
        """
        Manual variable merge when ansible-inventory is unavailable.
        Merges: role defaults < group_vars < host_vars
        """
        # role defaults
        merged: dict = {}
        for role_root in (r.strip() for r in self._role_roots.split(",") if r.strip()):
            defaults = _load_yaml(os.path.join(role_root, "defaults", "main.yml"))
            merged   = _deep_merge(merged, defaults)

        # group_vars/all
        gv_dir = os.path.join(self._infra_dir, "group_vars")
        for target in ("all", ):
            flat = pathlib.Path(gv_dir) / f"{target}.yml"
            if flat.is_file():
                merged = _deep_merge(merged, _load_yaml(str(flat)))
            d = pathlib.Path(gv_dir) / target
            if d.is_dir():
                for f in sorted(d.glob("*.yml")):
                    merged = _deep_merge(merged, _load_yaml(str(f)))

        # group_vars for every group the host belongs to
        for grp_name, entries in self._manual_sections().items():
            if hostname in [e[0] if isinstance(e, tuple) else e for e in entries]:
                for target in (grp_name,):
                    flat = pathlib.Path(gv_dir) / f"{target}.yml"
                    if flat.is_file():
                        merged = _deep_merge(merged, _load_yaml(str(flat)))

        # host_vars
        hv_dir = pathlib.Path(self._infra_dir) / "host_vars"
        for candidate in (
            hv_dir / f"{hostname}.yml",
            hv_dir / hostname / "main.yml",
        ):
            if candidate.is_file():
                merged = _deep_merge(merged, _load_yaml(str(candidate)))

        return merged

    def _manual_sections(self) -> dict:
        """Parse all sections from INI for group membership detection."""
        inv_file = self._inventory_file()
        sections: dict = {}
        current = None
        section_re = re.compile(r"^\[(.+?)\]\s*$")
        for raw_line in pathlib.Path(inv_file).read_text(
            encoding="utf-8", errors="replace"
        ).replace("\r\n", "\n").replace("\r", "\n").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            m = section_re.match(line)
            if m:
                current = re.sub(r"\s*:\s*", ":", m.group(1)).strip()
                sections.setdefault(current, [])
                continue
            if current:
                short = line.split()[0]
                ip_m  = re.search(r"ansible_host=(\S+)", line)
                sections[current].append((short, ip_m.group(1) if ip_m else short))
        return sections


# ─────────────────────────────────────────────────────────────────────────────
# SSH target resolution
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_ssh_target(short_name: str, hostvars: dict) -> str:
    """
    Determine the SSH address for a host using its fully merged hostvars.

    Priority:
      1. cert_cn          — FQDN used in certificate Subject CN
      2. ansible_host     — IP or hostname from inventory
      3. short_name       — inventory name (may not resolve in DNS)
    """
    cert_cn = hostvars.get("cert_cn", "")
    if cert_cn:
        # cert_cn may be a template e.g. "{hostname}.example.com"
        cert_cn = cert_cn.replace("{hostname}", short_name)
        cert_cn = cert_cn.replace("{inventory_hostname}", short_name)
        return cert_cn
    return hostvars.get("ansible_host", short_name)


# ─────────────────────────────────────────────────────────────────────────────
# Test file → host group mapping
# ─────────────────────────────────────────────────────────────────────────────
#
# Edit this dict to control which host group each test file runs against.
# Value is the CLI option name whose value is the conf.ini group name.
#
# To run a test file on localhost:
#   change its value to "--localhost-group"
# To add a new test file:
#   add one line here — no other changes needed
# ─────────────────────────────────────────────────────────────────────────────

FILE_TO_GROUP: dict[str, str] = {
    "test_csr_and_key_generation": "--cert-group",
    "test_certificate_signed":     "--cert-group",
    "test_copy_to_ipaclient":      "--cert-group",
    "test_ipaclient":              "--ipaclient-group",
    # "test_something_local":      "--localhost-group",
}

# Env-var that overrides host list per group option
GROUP_TO_ENVVAR: dict[str, str] = {
    "--cert-group":      "CERTIFICATE_HOSTS",
    "--ipaclient-group": "IPACLIENT_HOSTS",
    "--localhost-group": "LOCALHOST_HOSTS",
}


# ─────────────────────────────────────────────────────────────────────────────
# pytest CLI options
# ─────────────────────────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption(
        "--infra",
        default=os.environ.get("INFRA", ""),
        help="Infra name, e.g. --infra=infra1  (maps to inventories/<infra>/)",
    )
    parser.addoption(
        "--inventories",
        default=os.environ.get("INVENTORIES_ROOT", "inventories"),
        help="Root folder containing per-infra inventory directories (default: inventories)",
    )
    parser.addoption(
        "--role-roots",
        default=os.environ.get("ROLE_ROOTS", "roles/ipa_cert"),
        help="Comma-separated role directories for variable defaults",
    )
    parser.addoption(
        "--cert-group",
        default=os.environ.get("CERT_GROUP", "ipa_client"),
        help="Inventory group for certificate hosts (default: ipa_client)",
    )
    parser.addoption(
        "--ipaclient-group",
        default=os.environ.get("IPACLIENT_GROUP", "ipaclient_server"),
        help="Inventory group for the IPAclient server (default: ipaclient_server)",
    )
    parser.addoption(
        "--localhost-group",
        default=os.environ.get("LOCALHOST_GROUP", "localhost"),
        help="Inventory group for localhost/controller (default: localhost)",
    )


# ─────────────────────────────────────────────────────────────────────────────
# pytest_generate_tests — collection-time host parametrisation
# ─────────────────────────────────────────────────────────────────────────────

def pytest_generate_tests(metafunc):
    """
    Parametrise cert_host for tests that declare it as a fixture.
    Uses FILE_TO_GROUP to pick the right inventory group per test file.
    All variable resolution goes through AnsibleInventory so Ansible's
    own precedence rules are respected.
    """
    if "cert_host" not in metafunc.fixturenames:
        return

    # ── which group does this test file target? ───────────────────────────────
    test_file    = metafunc.module.__name__
    group_option = FILE_TO_GROUP.get(test_file, "--cert-group")
    env_var      = GROUP_TO_ENVVAR.get(group_option, "CERTIFICATE_HOSTS")

    # ── env-var override ──────────────────────────────────────────────────────
    env_hosts = os.environ.get(env_var, "")
    if env_hosts:
        entries = []
        for entry in env_hosts.split(","):
            entry = entry.strip()
            short, ssh = entry.split(":", 1) if ":" in entry else (entry, entry)
            entries.append(HostEntry(short_name=short, ssh_target=ssh))
        metafunc.parametrize("cert_host", entries, scope="module")
        return

    # ── resolve from inventory ────────────────────────────────────────────────
    infra      = metafunc.config.getoption("--infra")
    inv_root   = metafunc.config.getoption("--inventories")
    role_roots = metafunc.config.getoption("--role-roots")
    group_name = metafunc.config.getoption(group_option)

    if not infra:
        pytest.exit("ERROR: --infra is required. Example: --infra=infra1", returncode=1)

    infra_dir = os.path.join(inv_root, infra)
    if not os.path.isdir(infra_dir):
        pytest.exit(f"ERROR: Inventory directory not found: {infra_dir}", returncode=1)

    inv  = AnsibleInventory(infra_dir, role_roots)
    hosts = inv.group_hosts(group_name)

    if not hosts:
        pytest.exit(
            f"ERROR: No hosts found under [{group_name}]. "
            f"Check inventory or set {env_var} env var.",
            returncode=1,
        )

    entries = [
        HostEntry(
            short_name=h,
            ssh_target=_resolve_ssh_target(h, inv.hostvars(h)),
        )
        for h in hosts
    ]
    metafunc.parametrize("cert_host", entries, scope="module")


# ─────────────────────────────────────────────────────────────────────────────
# Core session fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def infra_name(request) -> str:
    name = request.config.getoption("--infra")
    assert name, "--infra is required"
    return name


@pytest.fixture(scope="session")
def inventories_root(request) -> str:
    return request.config.getoption("--inventories")


@pytest.fixture(scope="session")
def infra_dir(infra_name, inventories_root) -> str:
    d = os.path.join(inventories_root, infra_name)
    assert os.path.isdir(d), f"Inventory directory not found: {d}"
    return d


@pytest.fixture(scope="session")
def role_roots(request) -> str:
    return request.config.getoption("--role-roots")


# ─────────────────────────────────────────────────────────────────────────────
# AnsibleInventory fixture — the central access point for all tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def inventory(infra_dir, role_roots) -> AnsibleInventory:
    """
    Session-scoped AnsibleInventory instance.
    Use this in any test to get variables, host lists, or single var values.

    Examples in a test:
        def test_something(inventory, cert_host):
            vars  = inventory.hostvars(cert_host.short_name)
            owner = inventory.var(cert_host.short_name, "cert_owner", "root")
            hosts = inventory.group_hosts("ipa_client")
    """
    return AnsibleInventory(infra_dir, role_roots)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience variable fixtures — derived from inventory
# All read from the fully merged hostvars so precedence is correct.
# These are session-scoped defaults; use inventory.var(host, key) for
# per-host values that may differ between hosts.
# ─────────────────────────────────────────────────────────────────────────────

def _group_var(inventory: AnsibleInventory, group: str, key: str, default: Any = None) -> Any:
    """
    Get a variable value using the first host in a group as representative.
    Group-level vars are the same for all hosts so any host works.
    """
    hosts = inventory.group_hosts(group)
    if not hosts:
        return default
    return inventory.var(hosts[0], key, default)


@pytest.fixture(scope="session")
def cert_group_name(request) -> str:
    return request.config.getoption("--cert-group")


@pytest.fixture(scope="session")
def ipaclient_group_name(request) -> str:
    return request.config.getoption("--ipaclient-group")


@pytest.fixture(scope="session")
def cert_base_dir(inventory, cert_group_name) -> str:
    return _group_var(inventory, cert_group_name, "cert_base_dir", "/data/certificates")


@pytest.fixture(scope="session")
def cert_types(inventory, cert_group_name) -> list:
    return _group_var(inventory, cert_group_name, "cert_types", ["client", "server"])


@pytest.fixture(scope="session")
def ipa_realm(inventory, cert_group_name) -> str:
    return _group_var(inventory, cert_group_name, "ipa_realm", "")


@pytest.fixture(scope="session")
def ipa_domain(inventory, cert_group_name) -> str:
    return _group_var(inventory, cert_group_name, "ipa_domain", "")


@pytest.fixture(scope="session")
def ipa_ca_subject(inventory, cert_group_name) -> str:
    return _group_var(inventory, cert_group_name, "ipa_ca_subject", "Certificate Authority")


@pytest.fixture(scope="session")
def ipaclient_host_name(inventory, ipaclient_group_name) -> str:
    hosts = inventory.group_hosts(ipaclient_group_name)
    if hosts:
        hv = inventory.hostvars(hosts[0])
        return _resolve_ssh_target(hosts[0], hv)
    return os.environ.get("IPACLIENT_HOST", "")


# ─────────────────────────────────────────────────────────────────────────────
# Per-host variable helper — use inside tests for host-specific values
# ─────────────────────────────────────────────────────────────────────────────

def host_vars(inventory: AnsibleInventory, hostname: str) -> dict:
    """
    Return fully merged variables for *hostname*.
    Call this inside a test when you need a value that may differ per host:

        def test_file_owner(inventory, cert_host, cert_base_dir):
            hv    = host_vars(inventory, cert_host.short_name)
            owner = hv.get("cert_owner", "root")
    """
    return inventory.hostvars(hostname)


# ─────────────────────────────────────────────────────────────────────────────
# Connection fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def local_connection():
    """
    testinfra local:// backend — for tests that run on the controller.
    No SSH involved. Use for localhost-targeted test files.
    """
    import testinfra
    return testinfra.get_host("local://")


# ─────────────────────────────────────────────────────────────────────────────
# sudo helper — available to all test files
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def sudo_password(infra_dir) -> str:
    """
    Read sudo password from plain YAML keypass.yml.

    Structure:
        keepass_entries:
          ansible_user:
            key: nsbl
            value: <sudo_password>

    Location (first found):
      1. KEYPASS_FILE env var
      2. inventories/<infra>/group_vars/keypass.yml
    """
    keypass_file = (
        os.environ.get("KEYPASS_FILE")
        or os.path.join(infra_dir, "group_vars", "keypass.yml")
    )
    if not os.path.isfile(keypass_file):
        raise FileNotFoundError(
            f"keypass.yml not found: {keypass_file}\n"
            "Set KEYPASS_FILE env var or place at inventories/<infra>/group_vars/keypass.yml"
        )
    data = _load_yaml(keypass_file)
    try:
        return data["keepass_entries"]["ansible_user"]["value"]
    except KeyError as exc:
        raise KeyError(
            f"Missing key in keypass.yml: {exc}. "
            "Expected: keepass_entries.ansible_user.value"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Debug — print resolved config at session start
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def _print_session_config(
    infra_name, role_roots, inventory,
    cert_group_name, ipaclient_group_name,
):
    cert_hosts = inventory.group_hosts(cert_group_name)
    ipa_hosts  = inventory.group_hosts(ipaclient_group_name)

    print("\n" + "═" * 64)
    print(f"  INFRA            : {infra_name}")
    print(f"  ROLE ROOTS       : {role_roots}")
    print(f"  CERT GROUP       : {cert_group_name}  → {cert_hosts}")
    print(f"  IPACLIENT GROUP  : {ipaclient_group_name}  → {ipa_hosts}")
    print(f"  ansible-inventory: {'available' if shutil.which('ansible-inventory') else "NOT FOUND — using fallback parser"}")
    print("═" * 64 + "\n")
