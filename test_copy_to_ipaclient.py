"""
test_copy_to_ipaclient.py
=========================
cert_host.short_name — used for file paths on both hosts
cert_host.ssh_target — FQDN/IP used to SSH into the origin cert host
"""

import pytest
import testinfra


@pytest.fixture()
def cert_host(request):
    return request.param


@pytest.fixture()
def ssh_host(cert_host):
    return testinfra.get_host(f"ssh://{cert_host.ssh_target}")


@pytest.fixture(scope="module")
def ipaclient(ipaclient_host_name):
    assert ipaclient_host_name, (
        "ipaclient_host not set — add to group_vars or set IPACLIENT_HOST"
    )
    return testinfra.get_host(f"ssh://{ipaclient_host_name}")


def _dir(base, short_name): return f"{base}/{short_name}"


class TestCSROnIPAClient:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_present_on_ipaclient(self, ipaclient, cert_host, cert_type, cert_base_dir):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        f = ipaclient.file(path)
        assert f.exists,   f"CSR not on IPAclient: {path}"
        assert f.size > 0, f"CSR empty on IPAclient: {path}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_content_matches_source(
        self, ssh_host, ipaclient, cert_host, cert_type, cert_base_dir,
    ):
        path     = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.csr"
        src      = ssh_host.run(f"md5sum {path}")
        dst      = ipaclient.run(f"md5sum {path}")
        assert src.rc == 0 and dst.rc == 0
        assert src.stdout.split()[0] == dst.stdout.split()[0], (
            f"CSR md5 mismatch [{cert_type}] for {cert_host.short_name}"
        )


class TestPrivateKeyIsolation:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    @pytest.mark.security
    def test_key_not_on_ipaclient(self, ipaclient, cert_host, cert_type, cert_base_dir):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.key"
        assert not ipaclient.file(path).exists, (
            f"SECURITY: private key found on IPAclient: {path}"
        )


class TestSignedCRTDistribution:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_signed_crt_on_ipaclient(self, ipaclient, cert_host, cert_type, cert_base_dir):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        f = ipaclient.file(path)
        assert f.exists and f.size > 0, f"Signed CRT missing on IPAclient: {path}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_signed_crt_back_on_origin_host(
        self, ssh_host, cert_host, cert_type, cert_base_dir,
    ):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        f = ssh_host.file(path)
        assert f.exists and f.size > 0, (
            f"Signed CRT not on origin host {cert_host.short_name}: {path}"
        )
