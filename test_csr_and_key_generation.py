"""
test_csr_and_key_generation.py
==============================
Target hosts : --cert-group  (remote cert hosts, e.g. [ipa_client])

Permissions are resolved per host from inventory.hostvars() via
FilePerms.for_host() — so cert hosts and ipaclient hosts can have
different cert_owner, cert_group, cert_file_mode, key_file_mode
defined in their respective host_vars or group_vars.
"""

import pytest
import testinfra
from conftest import FilePerms, host_vars


@pytest.fixture()
def cert_host(request):
    """Parametrised by conftest.pytest_generate_tests."""
    return request.param


@pytest.fixture()
def ssh_host(cert_host):
    return testinfra.get_host(f"ssh://{cert_host.ssh_target}")


def _cert_dir(base: str, hostname: str) -> str:
    return f"{base}/{hostname}"


def _sudo(host, cmd: str, password: str):
    """Run cmd as root: echo <password> | sudo -S bash -c '<cmd>'"""
    safe = cmd.replace("'", r"'\''")
    return host.run(f"echo {password!r} | sudo -S bash -c '{safe}' 2>/dev/null")


# ─────────────────────────────────────────────────────────────────────────────
# Directory
# ─────────────────────────────────────────────────────────────────────────────

class TestCertDirectory:

    def test_directory_exists(self, ssh_host, cert_host, cert_base_dir):
        d = ssh_host.file(_cert_dir(cert_base_dir, cert_host.short_name))
        assert d.exists and d.is_directory, (
            f"Certificate directory missing for {cert_host.short_name}"
        )

    def test_directory_permissions(self, ssh_host, cert_host, cert_base_dir, inventory):
        """
        Directory owner/group/mode read from this host's vars.
        Defined via cert_dir_mode (default 0755) in host_vars or group_vars.
        """
        perms = FilePerms.for_host(inventory, cert_host.short_name, file_type="dir")
        d = ssh_host.file(_cert_dir(cert_base_dir, cert_host.short_name))
        assert d.user  == perms.owner,    f"Dir owner: got {d.user!r}, want {perms.owner!r}"
        assert d.group == perms.group,    f"Dir group: got {d.group!r}, want {perms.group!r}"
        assert d.mode  == perms.mode_int, f"Dir mode: got {oct(d.mode)}, want {perms.mode_str}"


# ─────────────────────────────────────────────────────────────────────────────
# CSR file checks
# ─────────────────────────────────────────────────────────────────────────────

class TestCSRFiles:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_exists_and_permissions(
        self, ssh_host, cert_host, cert_type, cert_base_dir, inventory
    ):
        """
        Permissions resolved from this host's merged vars.
        Override per-host in host_vars/<hostname>.yml:
            cert_owner: someuser
            cert_file_mode: "0640"
        """
        perms = FilePerms.for_host(inventory, cert_host.short_name, file_type="csr")
        path  = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        f = ssh_host.file(path)

        assert f.exists,                f"CSR not found: {path}"
        assert f.size > 0,              f"CSR is empty: {path}"
        assert f.user  == perms.owner,  f"CSR owner: got {f.user!r}, want {perms.owner!r}"
        assert f.group == perms.group,  f"CSR group: got {f.group!r}, want {perms.group!r}"
        assert f.mode  == perms.mode_int, f"CSR mode: got {oct(f.mode)}, want {perms.mode_str}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_is_valid_pem(
        self, ssh_host, cert_host, cert_type, cert_base_dir, sudo_password
    ):
        path = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        r = _sudo(ssh_host, f"openssl req -verify -noout -in {path}", sudo_password)
        assert r.rc == 0, f"CSR invalid [{cert_type}] on {cert_host.short_name}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_subject_cn(self, ssh_host, cert_host, cert_type, cert_base_dir, sudo_password):
        path = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        r = _sudo(ssh_host, f"openssl req -noout -subject -in {path}", sudo_password)
        assert r.rc == 0
        assert cert_host.ssh_target.lower() in r.stdout.lower(), (
            f"FQDN not in Subject CN [{cert_type}] on {cert_host.short_name}: {r.stdout}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Private key checks
# ─────────────────────────────────────────────────────────────────────────────

class TestPrivateKeyFiles:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_key_exists_and_permissions(
        self, ssh_host, cert_host, cert_type, cert_base_dir, inventory
    ):
        """
        Key permissions resolved from this host's vars.
        Override per-host in host_vars/<hostname>.yml:
            key_file_mode: "0600"   # must be restrictive
        """
        perms = FilePerms.for_host(inventory, cert_host.short_name, file_type="key")
        path  = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.key"
        f = ssh_host.file(path)

        assert f.exists,                f"Key not found: {path}"
        assert f.size > 0,              f"Key is empty: {path}"
        assert f.user  == perms.owner,  f"Key owner: got {f.user!r}, want {perms.owner!r}"
        assert f.group == perms.group,  f"Key group: got {f.group!r}, want {perms.group!r}"
        assert f.mode  == perms.mode_int, f"Key mode: got {oct(f.mode)}, want {perms.mode_str}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_key_is_valid(self, ssh_host, cert_host, cert_type, cert_base_dir, sudo_password):
        path = f"{_cert_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.key"
        r = _sudo(
            ssh_host,
            f"openssl rsa -check -noout -in {path} 2>/dev/null || "
            f"openssl pkey -check -noout -in {path}",
            sudo_password,
        )
        assert r.rc == 0, f"Key check failed [{cert_type}] on {cert_host.short_name}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_key_modulus_match(
        self, ssh_host, cert_host, cert_type, cert_base_dir, sudo_password
    ):
        base = _cert_dir(cert_base_dir, cert_host.short_name)
        csr_m = ssh_host.run(
            f"echo {sudo_password!r} | sudo -S bash -c "
            f"'openssl req -noout -modulus -in {base}/{cert_type}.csr | openssl md5' 2>/dev/null"
        )
        key_m = ssh_host.run(
            f"echo {sudo_password!r} | sudo -S bash -c "
            f"'openssl rsa -noout -modulus -in {base}/{cert_type}.key | openssl md5' 2>/dev/null"
        )
        assert csr_m.rc == 0, f"CSR modulus read failed: {csr_m.stderr}"
        assert key_m.rc == 0, f"Key modulus read failed: {key_m.stderr}"
        csr_hash = csr_m.stdout.strip()
        key_hash = key_m.stdout.strip()
        assert csr_hash, f"CSR modulus empty [{cert_type}] on {cert_host.short_name}"
        assert key_hash, f"Key modulus empty [{cert_type}] on {cert_host.short_name}"
        assert csr_hash == key_hash, (
            f"Modulus mismatch [{cert_type}] on {cert_host.short_name}:\n"
            f"  CSR: {csr_hash}\n  KEY: {key_hash}"
        )
