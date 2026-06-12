"""
test_certificate_signed.py
==========================
cert_host.short_name — used for cert file paths
cert_host.ssh_target — FQDN/IP used for SSH and expected in cert Subject CN/SAN
"""

import pytest
import testinfra
from conftest import host_vars


@pytest.fixture()
def cert_host(request):
    return request.param


@pytest.fixture()
def ssh_host(cert_host):
    return testinfra.get_host(f"ssh://{cert_host.ssh_target}")


def _dir(base, short_name): return f"{base}/{short_name}"


def _sudo(host, cmd: str, password: str) -> object:
    """Run cmd as root via: echo <password> | sudo -S bash -c '<cmd>'"""
    safe_cmd = cmd.replace("'", r"'\''")
    return host.run(f"echo {password!r} | sudo -S bash -c '{safe_cmd}' 2>/dev/null")



class TestCRTFilePresence:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_exists(
        self, ssh_host, cert_host, cert_type,
        cert_base_dir, cert_owner, cert_group, cert_file_mode, inventory):
        hvars = host_vars(inventory, cert_host.short_name)
        owner = hvars.get("cert_owner", cert_owner)
        grp   = hvars.get("cert_group", cert_group)
        mode  = hvars.get("cert_file_mode", cert_file_mode)
        path  = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        f = ssh_host.file(path)
        assert f.exists,                f"CRT not found: {path}"
        assert f.size > 0,              f"CRT is empty: {path}"
        assert f.user  == owner,        f"CRT owner: got {f.user!r}, want {owner!r}"
        assert f.group == grp,          f"CRT group: got {f.group!r}, want {grp!r}"
        assert f.mode  == int(mode, 8), f"CRT mode: got {oct(f.mode)}, want {mode}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_full_bundle_present(self, ssh_host, cert_host, cert_type, cert_base_dir, inventory):
        base = _dir(cert_base_dir, cert_host.short_name)
        for ext in ("csr", "key", "crt"):
            assert ssh_host.file(f"{base}/{cert_type}.{ext}").exists, (
                f"Missing {cert_type}.{ext} on {cert_host.short_name}"
            )


class TestCRTCryptography:

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_valid_pem(self, ssh_host, cert_host, cert_type, cert_base_dir, inventory):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        r = _sudo(ssh_host, f"openssl x509 -noout -in {path}", sudo_password)
        assert r.rc == 0, f"Invalid CRT [{cert_type}] on {cert_host.short_name}:\n{r.stderr}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_issuer_matches_ipa_ca(
        self, ssh_host, cert_host, cert_type, cert_base_dir, ipa_ca_subject, inventory):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        r = _sudo(ssh_host, f"openssl x509 -noout -issuer -in {path}", sudo_password)
        assert r.rc == 0
        assert ipa_ca_subject.lower() in r.stdout.lower(), (
            f"IPA CA not in issuer [{cert_type}] on {cert_host.short_name}: {r.stdout}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_subject_cn_matches_fqdn(self, ssh_host, cert_host, cert_type, cert_base_dir, inventory):
        """Subject CN must match the FQDN from cert_cn (ssh_target)."""
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        r = _sudo(ssh_host, f"openssl x509 -noout -subject -in {path}", sudo_password)
        assert r.rc == 0
        assert cert_host.ssh_target.lower() in r.stdout.lower(), (
            f"FQDN {cert_host.ssh_target!r} not in Subject CN [{cert_type}] "
            f"on {cert_host.short_name}: {r.stdout}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_key_modulus_match(self, ssh_host, cert_host, cert_type, cert_base_dir, inventory):
        base  = _dir(cert_base_dir, cert_host.short_name)
        crt_m = _sudo(ssh_host, f"openssl x509 -noout -modulus -in {base}/{cert_type}.crt | openssl md5", sudo_password)
        key_m = _sudo(ssh_host, f"openssl rsa  -noout -modulus -in {base}/{cert_type}.key | openssl md5", sudo_password)
        assert crt_m.rc == 0 and key_m.rc == 0
        assert crt_m.stdout.strip() == key_m.stdout.strip(), (
            f"CRT/key mismatch [{cert_type}] on {cert_host.short_name}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_currently_valid(self, ssh_host, cert_host, cert_type, cert_base_dir, inventory):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        r = _sudo(ssh_host, f"openssl x509 -checkend 0 -noout -in {path}", sudo_password)
        assert r.rc == 0, f"Certificate expired [{cert_type}] on {cert_host.short_name}"

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_san_contains_fqdn(self, ssh_host, cert_host, cert_type, cert_base_dir, inventory):
        path = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        r = _sudo(ssh_host, f"openssl x509 -noout -ext subjectAltName -in {path}", sudo_password)
        if r.rc != 0 or "subjectAltName" not in r.stdout:
            pytest.skip(f"No SAN [{cert_type}] on {cert_host.short_name}")
        assert cert_host.ssh_target.lower() in r.stdout.lower(), (
            f"FQDN not in SAN [{cert_type}] on {cert_host.short_name}: {r.stdout}"
        )

    @pytest.mark.parametrize("cert_type", ["client", "server"])
    def test_crt_not_self_signed(self, ssh_host, cert_host, cert_type, cert_base_dir, inventory):
        path    = f"{_dir(cert_base_dir, cert_host.short_name)}/{cert_type}.crt"
        issuer  = _sudo(ssh_host, f"openssl x509 -noout -issuer  -in {path}", sudo_password)
        subject = _sudo(ssh_host, f"openssl x509 -noout -subject -in {path}", sudo_password)
        assert issuer.rc == 0 and subject.rc == 0
        assert issuer.stdout.strip() != subject.stdout.strip(), (
            f"Certificate is self-signed [{cert_type}] on {cert_host.short_name}"
        )
