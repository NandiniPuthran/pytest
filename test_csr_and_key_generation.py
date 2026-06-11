"""
test_csr_and_key_generation.py
==============================
cert_host   — HostEntry(short_name, ssh_target) from conftest.pytest_generate_tests
ssh_host    — testinfra connection via cert_host.ssh_target (FQDN from cert_cn or IP)
cert_host.short_name — used for /data/certificates/<short_name>/ path only
"""

import pytest
import testinfra
from conftest import host_merged_vars_for


@pytest.fixture()
def cert_host(request):
    """Parametrised by conftest.pytest_generate_tests — one HostEntry per invocation."""
    return request.param


@pytest.fixture()
def ssh_host(cert_host):
    """testinfra connection using the resolvable SSH target (FQDN or IP)."""
    return testinfra.get_host(f"ssh://{cert_host.ssh_target}")


def _cert_dir(base: str, hostname: str) -> str:
    return f"{base}/{hostname}"


class TestCertDirectory:

    def test_per_host_directory_exists(self, ssh_host, cert_host, cert_base_dir):
        d = ssh_host.file(_cert_dir(cert_base_dir, cert_host.short_name))
        assert d.exists and d.is_directory, (
            f"Certificate directory missing for {cert_host.short_name}"
        )


class TestCSRFiles:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_exists_and_non_empty(
        self, ssh_host, cert_host, cert_type,
        cert_base_dir, cert_owner, cert_group, cert_file_mode,
        infra_inventory_dir, merged_vars,
    ):
        hvars = host_merged_vars_for(cert_host.short_name, infra_inventory_dir, merged_vars)
        owner = hvars.get("cert_owner", cert_owner)
        grp   = hvars.get("cert_group", cert_group)
        mode  = hvars.get("cert_file_mode", cert_file_mode)

        path = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        f = ssh_host.file(path)

        assert f.exists,                f"CSR not found: {path}"
        assert f.size > 0,              f"CSR is empty: {path}"
        assert f.user  == owner,        f"CSR owner mismatch: got {f.user!r}, want {owner!r}"
        assert f.group == grp,          f"CSR group mismatch: got {f.group!r}, want {grp!r}"
        assert f.mode  == int(mode, 8), f"CSR mode mismatch: got {oct(f.mode)}, want {mode}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_is_valid_pem(self, ssh_host, cert_host, cert_type, cert_base_dir):
        path = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        r = ssh_host.run(f"openssl req -verify -noout -in {path}")
        assert r.rc == 0, f"CSR PEM invalid [{cert_type}] on {cert_host.short_name}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_subject_cn_matches_hostname(
        self, ssh_host, cert_host, cert_type, cert_base_dir
    ):
        path = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        r = ssh_host.run(f"openssl req -noout -subject -in {path}")
        assert r.rc == 0
        # Check against FQDN (ssh_target) since cert_cn is the FQDN used in the CSR
        assert cert_host.ssh_target.lower() in r.stdout.lower(), (
            f"FQDN not in CSR Subject CN [{cert_type}] on {cert_host.short_name}: {r.stdout}"
        )


class TestPrivateKeyFiles:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_key_exists_and_non_empty(
        self, ssh_host, cert_host, cert_type,
        cert_base_dir, cert_owner, cert_group, key_file_mode,
        infra_inventory_dir, merged_vars,
    ):
        hvars = host_merged_vars_for(cert_host.short_name, infra_inventory_dir, merged_vars)
        owner = hvars.get("cert_owner", cert_owner)
        grp   = hvars.get("cert_group", cert_group)
        mode  = hvars.get("key_file_mode", key_file_mode)

        path = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.key"
        f = ssh_host.file(path)

        assert f.exists,                f"Key not found: {path}"
        assert f.size > 0,              f"Key is empty: {path}"
        assert f.user  == owner,        f"Key owner mismatch: got {f.user!r}, want {owner!r}"
        assert f.group == grp,          f"Key group mismatch: got {f.group!r}, want {grp!r}"
        assert f.mode  == int(mode, 8), f"Key mode mismatch: got {oct(f.mode)}, want {mode}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_private_key_is_valid(self, ssh_host, cert_host, cert_type, cert_base_dir):
        path = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.key"
        r = ssh_host.run(
            f"openssl rsa -check -noout -in {path} 2>/dev/null || "
            f"openssl pkey -check -noout -in {path}"
        )
        assert r.rc == 0, f"Key check failed [{cert_type}] on {cert_host.short_name}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_and_key_modulus_match(self, ssh_host, cert_host, cert_type, cert_base_dir):
        base  = _cert_dir(cert_base_dir, cert_host.short_name)
        csr_m = ssh_host.run(f"openssl req -noout -modulus -in {base}/{cert_type}.csr | openssl md5")
        key_m = ssh_host.run(f"openssl rsa -noout -modulus -in {base}/{cert_type}.key | openssl md5")
        assert csr_m.rc == 0 and key_m.rc == 0
        assert csr_m.stdout.strip() == key_m.stdout.strip(), (
            f"CSR/key modulus mismatch [{cert_type}] on {cert_host.short_name}"
        )
