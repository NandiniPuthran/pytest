"""
test_copy_to_ipaclient.py
=========================
Target hosts : --cert-group  (iterates each cert host)
IPAclient    : --ipaclient-group (single host, module-scoped)

PERMISSION DESIGN
─────────────────
Cert files on the CERT HOST     → FilePerms.for_host(inventory, cert_host.short_name)
Cert files on the IPACLIENT HOST → FilePerms.for_host(inventory, ipaclient_short_name)

This means you can define different cert_owner/cert_file_mode in:
  host_vars/<cert_hostname>.yml        → applies to cert host checks
  host_vars/<ipaclient_hostname>.yml   → applies to ipaclient checks
  group_vars/ipaclient_server.yml      → applies to all ipaclient checks
"""

import pytest
import testinfra
from conftest import FilePerms


@pytest.fixture()
def cert_host(request):
    """Parametrised by conftest.pytest_generate_tests."""
    return request.param


@pytest.fixture()
def ssh_host(cert_host):
    return testinfra.get_host(f"ssh://{cert_host.ssh_target}")


@pytest.fixture(scope="module")
def ipaclient_entry(inventory, ipaclient_group_name):
    """
    Returns HostEntry for the ipaclient server.
    Variables for this host come from inventory.hostvars(ipaclient_entry.short_name)
    — separate from cert host vars.
    """
    from conftest import HostEntry, _resolve_ssh_target
    hosts = inventory.group_hosts(ipaclient_group_name)
    assert hosts, f"No hosts in [{ipaclient_group_name}]"
    h  = hosts[0]
    hv = inventory.hostvars(h)
    return HostEntry(short_name=h, ssh_target=_resolve_ssh_target(h, hv))


@pytest.fixture(scope="module")
def ipaclient(ipaclient_entry):
    return testinfra.get_host(f"ssh://{ipaclient_entry.ssh_target}")


def _dir(base, short_name): return f"{base}/{short_name}"


def _sudo(host, cmd, password):
    safe = cmd.replace("'", r"'\''")
    return host.run(f"echo {password!r} | sudo -S bash -c '{safe}' 2>/dev/null")


# ─────────────────────────────────────────────────────────────────────────────
# CSR arrived on IPAclient
# ─────────────────────────────────────────────────────────────────────────────

class TestCSROnIPAClient:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_present(self, ipaclient, cert_host, cert_type, cert_base_dir):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        f = ipaclient.file(path)
        assert f.exists and f.size > 0, f"CSR missing on IPAclient: {path}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_permissions_on_ipaclient(
        self, ipaclient, ipaclient_entry, cert_host, cert_type, cert_base_dir, inventory
    ):
        """
        Permissions checked against the IPACLIENT HOST's vars.
        Define in group_vars/ipaclient_server.yml or
        host_vars/<ipaclient_hostname>.yml:
            cert_owner: root
            cert_file_mode: "0644"
        """
        perms = FilePerms.for_host(inventory, ipaclient_entry.short_name, file_type="csr")
        path  = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        f = ipaclient.file(path)
        assert f.user  == perms.owner,    f"CSR owner on IPAclient: got {f.user!r}, want {perms.owner!r}"
        assert f.group == perms.group,    f"CSR group on IPAclient: got {f.group!r}, want {perms.group!r}"
        assert f.mode  == perms.mode_int, f"CSR mode on IPAclient: got {oct(f.mode)}, want {perms.mode_str}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_md5_matches_source(
        self, ssh_host, ipaclient, cert_host, cert_type, cert_base_dir, sudo_password
    ):
        path  = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        src   = _sudo(ssh_host,  f"md5sum {path}", sudo_password)
        dst   = _sudo(ipaclient, f"md5sum {path}", sudo_password)
        assert src.rc == 0 and dst.rc == 0
        assert src.stdout.split()[0] == dst.stdout.split()[0], (
            f"CSR md5 mismatch [{cert_type}] for {cert_host.short_name}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Security — private keys must NOT be on IPAclient
# ─────────────────────────────────────────────────────────────────────────────

class TestPrivateKeyIsolation:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    @pytest.mark.security
    def test_key_not_on_ipaclient(self, ipaclient, cert_host, cert_type, cert_base_dir):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.key"
        assert not ipaclient.file(path).exists, (
            f"SECURITY: private key found on IPAclient: {path}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Signed CRT distribution
# ─────────────────────────────────────────────────────────────────────────────

class TestSignedCRTDistribution:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_on_ipaclient(
        self, ipaclient, ipaclient_entry, cert_host, cert_type, cert_base_dir, inventory
    ):
        """
        CRT permissions on IPAclient checked against ipaclient host's vars.
        cert_file_mode in group_vars/ipaclient_server.yml controls this.
        """
        perms = FilePerms.for_host(inventory, ipaclient_entry.short_name, file_type="crt")
        path  = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        f = ipaclient.file(path)
        assert f.exists and f.size > 0, f"Signed CRT missing on IPAclient: {path}"
        assert f.user  == perms.owner,    f"CRT owner on IPAclient: {f.user!r}"
        assert f.group == perms.group,    f"CRT group on IPAclient: {f.group!r}"
        assert f.mode  == perms.mode_int, f"CRT mode on IPAclient: {oct(f.mode)}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_back_on_origin_host(
        self, ssh_host, cert_host, cert_type, cert_base_dir, inventory
    ):
        """
        CRT permissions on the CERT HOST checked against cert host's vars.
        cert_file_mode in group_vars/ipa_client.yml or host_vars/<host>.yml controls this.
        """
        perms = FilePerms.for_host(inventory, cert_host.short_name, file_type="crt")
        path  = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        f = ssh_host.file(path)
        assert f.exists and f.size > 0, f"Signed CRT missing on origin host: {path}"
        assert f.user  == perms.owner,    f"CRT owner on cert host: {f.user!r}"
        assert f.group == perms.group,    f"CRT group on cert host: {f.group!r}"
        assert f.mode  == perms.mode_int, f"CRT mode on cert host: {oct(f.mode)}"
