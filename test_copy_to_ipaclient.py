"""
test_copy_to_ipaclient.py
=========================
Validates the CSR copy step TO the IPAclient server and the signed CRT
copy BACK to each cert host.

  - CSR arrived on IPAclient (exists, md5 matches source host)
  - Private key was NOT copied to IPAclient (security boundary)
  - Signed CRT is present on IPAclient after IPA signing
  - Signed CRT is present back on the origin cert host
"""

import pytest
import testinfra


@pytest.fixture(scope="module")
def ipaclient(ipaclient_host_name):
    assert ipaclient_host_name, (
        "ipaclient_host not set — add to group_vars or set IPACLIENT_HOST env var"
    )
    return testinfra.get_host(f"ssh://{ipaclient_host_name}")


@pytest.fixture(params=lambda request: request.getfixturevalue("certificate_hosts"))
def cert_host(request, certificate_hosts):
    return request.param

def _dir(base, h): return f"{base}/{h}"


class TestCSROnIPAClient:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_present_on_ipaclient(self, ipaclient, cert_host, cert_type, cert_base_dir):
        path = f"{_dir(cert_base_dir, cert_host)}/{cert_type}.csr"
        f = ipaclient.file(path)
        assert f.exists,   f"CSR not on IPAclient: {path} (for {cert_host})"
        assert f.size > 0, f"CSR empty on IPAclient: {path}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_csr_content_matches_source(
        self, ipaclient, cert_host, cert_type, cert_base_dir
    ):
        """md5 of CSR on IPAclient must equal md5 on the source host."""
        path = f"{_dir(cert_base_dir, cert_host)}/{cert_type}.csr"
        src   = testinfra.get_host(f"ssh://{cert_host}").run(f"md5sum {path}")
        dst   = ipaclient.run(f"md5sum {path}")
        assert src.rc == 0,  f"md5sum failed on {cert_host}"
        assert dst.rc == 0,  f"md5sum failed on IPAclient for {cert_host}"
        assert src.stdout.split()[0] == dst.stdout.split()[0], (
            f"CSR content mismatch [{cert_type}] for {cert_host}: "
            f"src={src.stdout.split()[0]} ipa={dst.stdout.split()[0]}"
        )


class TestPrivateKeyIsolation:
    """Security: private keys must NOT be present on the IPAclient server."""

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    @pytest.mark.security
    def test_key_not_on_ipaclient(
        self, ipaclient, cert_host, cert_type, cert_base_dir
    ):
        path = f"{_dir(cert_base_dir, cert_host)}/{cert_type}.key"
        assert not ipaclient.file(path).exists, (
            f"SECURITY VIOLATION: private key found on IPAclient: {path} "
            f"(host={cert_host}) — keys must never leave the origin host"
        )


class TestSignedCRTDistribution:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_signed_crt_on_ipaclient(
        self, ipaclient, cert_host, cert_type, cert_base_dir
    ):
        path = f"{_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        f = ipaclient.file(path)
        assert f.exists,   f"Signed CRT not on IPAclient: {path}"
        assert f.size > 0, f"Signed CRT empty on IPAclient: {path}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_signed_crt_valid_pem_on_ipaclient(
        self, ipaclient, cert_host, cert_type, cert_base_dir
    ):
        path = f"{_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        r = ipaclient.run(f"openssl x509 -noout -in {path}")
        assert r.rc == 0, (
            f"CRT on IPAclient is not valid PEM [{cert_type}] for {cert_host}:\n{r.stderr}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_signed_crt_back_on_origin_host(
        self, cert_host, cert_type, cert_base_dir
    ):
        """Signed CRT must also be present on the originating cert host."""
        path = f"{_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        host = testinfra.get_host(f"ssh://{cert_host}")
        f = host.file(path)
        assert f.exists,   f"Signed CRT not found on origin host {cert_host}: {path}"
        assert f.size > 0, f"Signed CRT empty on origin host {cert_host}: {path}"
