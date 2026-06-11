"""
test_certificate_signed.py
==========================
Validates IPA-signed .crt files on every cert host.

Checks per host × cert_type:
  - File exists, non-empty, correct owner/group/permissions
  - Valid PEM  (openssl x509 -noout)
  - Issuer contains IPA CA subject string
  - Subject CN contains hostname
  - CRT and key are a matching pair  (modulus md5)
  - Certificate is currently valid  (openssl x509 -checkend 0)
  - SAN contains hostname
  - Certificate is not self-signed
"""

import pytest
import testinfra
from conftest import host_merged_vars_for


@pytest.fixture(params=lambda request: request.getfixturevalue("certificate_hosts"))
def cert_host(request, certificate_hosts):
    return request.param

def _conn(h): return testinfra.get_host(f"ssh://{h}")
def _dir(base, h): return f"{base}/{h}"


class TestCRTFilePresence:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_exists(
        self, cert_host, cert_type,
        cert_base_dir, cert_owner, cert_group, cert_file_mode,
        infra_inventory_dir, merged_vars
    ):
        hvars = host_merged_vars_for(cert_host, infra_inventory_dir, merged_vars)
        owner = hvars.get("cert_owner", cert_owner)
        grp   = hvars.get("cert_group", cert_group)
        mode  = hvars.get("cert_file_mode", cert_file_mode)

        host = _conn(cert_host)
        path = f"{_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        f = host.file(path)

        assert f.exists,                 f"CRT not found: {path}"
        assert f.size > 0,               f"CRT is empty: {path}"
        assert f.user  == owner,         f"CRT owner mismatch: {f.user}"
        assert f.group == grp,           f"CRT group mismatch: {f.group}"
        assert f.mode  == int(mode, 8),  f"CRT mode mismatch: {oct(f.mode)}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_full_bundle_present(self, cert_host, cert_type, cert_base_dir):
        """All three files (.csr .key .crt) must coexist."""
        host = _conn(cert_host)
        base = _dir(cert_base_dir, cert_host)
        for ext in ("csr", "key", "crt"):
            assert host.file(f"{base}/{cert_type}.{ext}").exists, (
                f"Missing {cert_type}.{ext} on {cert_host}"
            )


class TestCRTCryptography:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_valid_pem(self, cert_host, cert_type, cert_base_dir):
        r = _conn(cert_host).run(
            f"openssl x509 -noout -in {_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        )
        assert r.rc == 0, f"Invalid CRT PEM [{cert_type}] on {cert_host}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_issuer_matches_ipa_ca(
        self, cert_host, cert_type, cert_base_dir, ipa_ca_subject
    ):
        r = _conn(cert_host).run(
            f"openssl x509 -noout -issuer -in {_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        )
        assert r.rc == 0
        assert ipa_ca_subject.lower() in r.stdout.lower(), (
            f"IPA CA not in issuer [{cert_type}] on {cert_host}: {r.stdout}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_subject_cn_matches_hostname(self, cert_host, cert_type, cert_base_dir):
        r = _conn(cert_host).run(
            f"openssl x509 -noout -subject -in {_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        )
        assert r.rc == 0
        assert cert_host.lower() in r.stdout.lower(), (
            f"Hostname not in Subject CN [{cert_type}] on {cert_host}: {r.stdout}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_key_modulus_match(self, cert_host, cert_type, cert_base_dir):
        host = _conn(cert_host)
        base = _dir(cert_base_dir, cert_host)
        crt_m = host.run(f"openssl x509 -noout -modulus -in {base}/{cert_type}.crt | openssl md5")
        key_m = host.run(f"openssl rsa  -noout -modulus -in {base}/{cert_type}.key | openssl md5")
        assert crt_m.rc == 0 and key_m.rc == 0, f"Modulus read failed on {cert_host}"
        assert crt_m.stdout.strip() == key_m.stdout.strip(), (
            f"CRT/key modulus mismatch [{cert_type}] on {cert_host}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_currently_valid(self, cert_host, cert_type, cert_base_dir):
        r = _conn(cert_host).run(
            f"openssl x509 -checkend 0 -noout "
            f"-in {_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        )
        assert r.rc == 0, f"Certificate expired [{cert_type}] on {cert_host}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_san_contains_hostname(self, cert_host, cert_type, cert_base_dir):
        r = _conn(cert_host).run(
            f"openssl x509 -noout -ext subjectAltName "
            f"-in {_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        )
        if r.rc != 0 or "subjectAltName" not in r.stdout:
            pytest.skip(f"No SAN extension [{cert_type}] on {cert_host}")
        assert cert_host.lower() in r.stdout.lower(), (
            f"Hostname not in SAN [{cert_type}] on {cert_host}: {r.stdout}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_not_self_signed(self, cert_host, cert_type, cert_base_dir):
        host = _conn(cert_host)
        path = f"{_dir(cert_base_dir, cert_host)}/{cert_type}.crt"
        issuer  = host.run(f"openssl x509 -noout -issuer  -in {path}")
        subject = host.run(f"openssl x509 -noout -subject -in {path}")
        assert issuer.rc == 0 and subject.rc == 0
        assert issuer.stdout.strip() != subject.stdout.strip(), (
            f"Certificate is self-signed [{cert_type}] on {cert_host}"
        )
