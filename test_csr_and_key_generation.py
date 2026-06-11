"""
test_csr_and_key_generation.py
==============================
Validates CSR and private key files on every host in certificate_group.

Checks per host × cert_type (client / server):
  - File exists, is non-empty, correct owner / group / permissions
  - CSR is valid PEM  (openssl req -verify)
  - CSR Subject CN contains the hostname
  - Private key passes integrity check  (openssl rsa/pkey -check)
  - CSR and key are a matching pair  (modulus md5 comparison)
"""

import pytest
import testinfra
from conftest import host_merged_vars_for


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic parametrisation  — driven by session fixture, not re-parsed here
# ─────────────────────────────────────────────────────────────────────────────

def pytest_generate_tests(metafunc):
    """Parametrise cert_host from the session-level certificate_hosts fixture."""
    if "cert_host" in metafunc.fixturenames:
        hosts = metafunc.config._store.get(
            pytest.StashKey(), None  # resolved via fixture at collection time
        )
        # Fallback: read CERTIFICATE_HOSTS env var directly during collection
        import os
        raw = os.environ.get("CERTIFICATE_HOSTS", "")
        if raw:
            hosts = [h.strip() for h in raw.split(",") if h.strip()]
            metafunc.parametrize("cert_host", hosts, scope="module")
            return

        # Let the fixture drive parametrisation via indirect
        metafunc.parametrize("cert_host", [], scope="module")  # filled at runtime


@pytest.fixture(params=lambda request: request.getfixturevalue("certificate_hosts"))
def cert_host(request, certificate_hosts):
    """One host from certificate_group per test invocation."""
    return request.param


# ─────────────────────────────────────────────────────────────────────────────
# Helper
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
        host = _conn(cert_host)
        d = host.file(_cert_dir(cert_base_dir, cert_host))
        assert d.exists and d.is_directory, (
            f"Certificate directory missing: {_cert_dir(cert_base_dir, cert_host)}"
        )


class TestCSRFiles:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_exists_and_non_empty(
        self, cert_host, cert_type,
        cert_base_dir, cert_owner, cert_group, cert_file_mode,
        infra_inventory_dir, merged_vars
    ):
        """CSR file must exist with correct ownership and permissions."""
        # Apply host_vars on top of session vars for this specific host
        hvars = host_merged_vars_for(cert_host, infra_inventory_dir, merged_vars)
        owner = hvars.get("cert_owner", cert_owner)
        grp   = hvars.get("cert_group", cert_group)
        mode  = hvars.get("cert_file_mode", cert_file_mode)

        host = _conn(cert_host)
        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.csr"
        f = host.file(path)

        assert f.exists,                  f"CSR not found: {path}"
        assert f.size > 0,                f"CSR is empty: {path}"
        assert f.user  == owner,          f"CSR owner mismatch: got {f.user}, want {owner}"
        assert f.group == grp,            f"CSR group mismatch: got {f.group}, want {grp}"
        assert f.mode  == int(mode, 8),   f"CSR mode mismatch: got {oct(f.mode)}, want {mode}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_is_valid_pem(self, cert_host, cert_type, cert_base_dir):
        """openssl req -verify must succeed."""
        host = _conn(cert_host)
        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.csr"
        r = host.run(f"openssl req -verify -noout -in {path}")
        assert r.rc == 0, f"CSR PEM invalid [{cert_type}] on {cert_host}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_subject_cn_matches_hostname(self, cert_host, cert_type, cert_base_dir):
        """CSR Subject CN must contain the hostname."""
        host = _conn(cert_host)
        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.csr"
        r = host.run(f"openssl req -noout -subject -in {path}")
        assert r.rc == 0, f"Could not read CSR subject on {cert_host}"
        assert cert_host.lower() in r.stdout.lower(), (
            f"Hostname not in CSR Subject CN [{cert_type}] on {cert_host}: {r.stdout}"
        )


class TestPrivateKeyFiles:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_key_exists_and_non_empty(
        self, cert_host, cert_type,
        cert_base_dir, cert_owner, cert_group, key_file_mode,
        infra_inventory_dir, merged_vars
    ):
        """Private key must exist with restricted permissions."""
        hvars = host_merged_vars_for(cert_host, infra_inventory_dir, merged_vars)
        owner = hvars.get("cert_owner", cert_owner)
        grp   = hvars.get("cert_group", cert_group)
        mode  = hvars.get("key_file_mode", key_file_mode)

        host = _conn(cert_host)
        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.key"
        f = host.file(path)

        assert f.exists,                 f"Key not found: {path}"
        assert f.size > 0,               f"Key is empty: {path}"
        assert f.user  == owner,         f"Key owner mismatch: got {f.user}, want {owner}"
        assert f.group == grp,           f"Key group mismatch: got {f.group}, want {grp}"
        assert f.mode  == int(mode, 8),  f"Key mode mismatch: got {oct(f.mode)}, want {mode}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_private_key_is_valid(self, cert_host, cert_type, cert_base_dir):
        """openssl rsa/pkey -check must succeed."""
        host = _conn(cert_host)
        path = f"{_cert_dir(cert_base_dir, cert_host)}/{cert_type}.key"
        r = host.run(
            f"openssl rsa -check -noout -in {path} 2>/dev/null || "
            f"openssl pkey -check -noout -in {path}"
        )
        assert r.rc == 0, f"Key check failed [{cert_type}] on {cert_host}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_and_key_modulus_match(self, cert_host, cert_type, cert_base_dir):
        """CSR and private key must form a matching pair (modulus md5 check)."""
        host = _conn(cert_host)
        base = _cert_dir(cert_base_dir, cert_host)
        csr_m = host.run(f"openssl req -noout -modulus -in {base}/{cert_type}.csr | openssl md5")
        key_m = host.run(f"openssl rsa -noout -modulus -in {base}/{cert_type}.key | openssl md5")
        assert csr_m.rc == 0 and key_m.rc == 0, f"Modulus read failed on {cert_host}"
        assert csr_m.stdout.strip() == key_m.stdout.strip(), (
            f"CSR/key modulus mismatch [{cert_type}] on {cert_host} — "
            "files may have been mixed up during copy"
        )
