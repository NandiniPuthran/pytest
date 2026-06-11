"""
test_csr_and_key_generation.py
==============================
Validates CSR and private key files on every host in certificate_group.

cert_host is parametrised automatically by pytest_generate_tests() in
conftest.py at collection time — no params= or lambda needed here.

Checks per host × cert_type (client / server):
  - Directory exists
  - CSR file exists, non-empty, correct owner/group/permissions
  - CSR is valid PEM  (openssl req -verify)
  - CSR Subject CN contains the hostname
  - Private key exists, non-empty, correct owner/group/permissions
  - Private key passes integrity check  (openssl rsa/pkey -check)
  - CSR and key are a matching pair  (modulus md5 comparison)
"""

import pytest
import testinfra
from conftest import host_merged_vars_for


# ─────────────────────────────────────────────────────────────────────────────
# cert_host fixture
# cert_host is injected as a plain fixture — its values come from
# pytest_generate_tests() in conftest.py (collection-time, CLI options only).
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def cert_host(request):
    """Parametrised by conftest.pytest_generate_tests — one host per invocation."""
    return request.param


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _conn(hostname: str):
    return testinfra.get_host(f"ssh://{hostname}")

def _cert_dir(base: str, hostname: str) -> str:
    return f"{base}/{hostname}"


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCertDirectory:

    def test_per_host_directory_exists(self, cert_host, cert_base_dir):
        """Per-host certificate directory must exist."""
        d = _conn(cert_host).file(_cert_dir(cert_base_dir, cert_host))
        assert d.exists and d.is_directory, (
            f"Certificate directory missing: {_cert_dir(cert_base_dir, cert_host)}"
        )


class TestCSRFiles:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_exists_and_non_empty(
        self, cert_host, cert_type,
        cert_base_dir, cert_owner, cert_group, cert_file_mode,
        infra_inventory_dir, merged_vars,
    ):
        """CSR file must exist with correct ownership and permissions."""
        hvars = host_merged_vars_for(cert_host, infra_inventory_dir, merged_vars)
        owner = hvars.get("cert_owner", cert_owner)
        grp   = hvars.get("cert_group", cert_group)
        mode  = hvars.get("cert_file_mode", cert_file_mode)

        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.csr"
        f = _conn(cert_host).file(path)

        assert f.exists,                f"CSR not found: {path}"
        assert f.size > 0,              f"CSR is empty: {path}"
        assert f.user  == owner,        f"CSR owner mismatch: got {f.user!r}, want {owner!r}"
        assert f.group == grp,          f"CSR group mismatch: got {f.group!r}, want {grp!r}"
        assert f.mode  == int(mode, 8), f"CSR mode mismatch: got {oct(f.mode)}, want {mode}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_is_valid_pem(self, cert_host, cert_type, cert_base_dir):
        """openssl req -verify must succeed."""
        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.csr"
        r = _conn(cert_host).run(f"openssl req -verify -noout -in {path}")
        assert r.rc == 0, f"CSR PEM invalid [{cert_type}] on {cert_host}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_subject_cn_matches_hostname(self, cert_host, cert_type, cert_base_dir):
        """CSR Subject CN must contain the hostname."""
        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.csr"
        r = _conn(cert_host).run(f"openssl req -noout -subject -in {path}")
        assert r.rc == 0, f"Could not read CSR subject on {cert_host}"
        assert cert_host.lower() in r.stdout.lower(), (
            f"Hostname not in CSR Subject CN [{cert_type}] on {cert_host}: {r.stdout}"
        )


class TestPrivateKeyFiles:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_key_exists_and_non_empty(
        self, cert_host, cert_type,
        cert_base_dir, cert_owner, cert_group, key_file_mode,
        infra_inventory_dir, merged_vars,
    ):
        """Private key must exist with restricted permissions (0600)."""
        hvars = host_merged_vars_for(cert_host, infra_inventory_dir, merged_vars)
        owner = hvars.get("cert_owner", cert_owner)
        grp   = hvars.get("cert_group", cert_group)
        mode  = hvars.get("key_file_mode", key_file_mode)

        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.key"
        f = _conn(cert_host).file(path)

        assert f.exists,                f"Key not found: {path}"
        assert f.size > 0,              f"Key is empty: {path}"
        assert f.user  == owner,        f"Key owner mismatch: got {f.user!r}, want {owner!r}"
        assert f.group == grp,          f"Key group mismatch: got {f.group!r}, want {grp!r}"
        assert f.mode  == int(mode, 8), f"Key mode mismatch: got {oct(f.mode)}, want {mode}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_private_key_is_valid(self, cert_host, cert_type, cert_base_dir):
        """openssl rsa/pkey -check must succeed."""
        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.key"
        r = _conn(cert_host).run(
            f"openssl rsa -check -noout -in {path} 2>/dev/null || "
            f"openssl pkey -check -noout -in {path}"
        )
        assert r.rc == 0, f"Key check failed [{cert_type}] on {cert_host}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_and_key_modulus_match(self, cert_host, cert_type, cert_base_dir):
        """CSR and private key must form a matching pair (modulus md5 check)."""
        base  = _cert_dir(cert_base_dir, cert_host)
        host  = _conn(cert_host)
        csr_m = host.run(f"openssl req -noout -modulus -in {base}/{cert_type}.csr | openssl md5")
        key_m = host.run(f"openssl rsa -noout -modulus -in {base}/{cert_type}.key | openssl md5")
        assert csr_m.rc == 0 and key_m.rc == 0, f"Modulus read failed on {cert_host}"
        assert csr_m.stdout.strip() == key_m.stdout.strip(), (
            f"CSR/key modulus mismatch [{cert_type}] on {cert_host} — "
            "files may have been mixed up during copy"
        )
