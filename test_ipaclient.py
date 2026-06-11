"""
test_ipaclient.py
=================
Validates IPAclient installation and Kerberos enrollment on the
ipaclient_server host. No cert_host parametrisation needed here.
"""

import pytest
import testinfra


@pytest.fixture(scope="module")
def ipaclient(ipaclient_host_name):
    assert ipaclient_host_name, (
        "ipaclient_host not set — add 'ipaclient_host' to "
        "group_vars/certificate_group.yml or set IPACLIENT_HOST env var."
    )
    return testinfra.get_host(f"ssh://{ipaclient_host_name}")


class TestIPAClientPackage:

    def test_freeipa_client_installed(self, ipaclient):
        pkg = ipaclient.package("freeipa-client")
        if not pkg.is_installed:
            pkg = ipaclient.package("ipa-client")
        assert pkg.is_installed, (
            "Neither 'freeipa-client' nor 'ipa-client' is installed"
        )

    def test_ipalib_importable(self, ipaclient):
        r = ipaclient.run("python3 -c 'import ipalib'")
        assert r.rc == 0, f"ipalib not importable:\n{r.stderr}"

    def test_ipa_binary_present(self, ipaclient):
        assert ipaclient.file("/usr/bin/ipa").exists, "/usr/bin/ipa not found"


class TestIPAClientServices:

    @pytest.mark.parametrize("svc", ["sssd"])
    def test_service_running(self, ipaclient, svc):
        assert ipaclient.service(svc).is_running, f"Service {svc!r} not running"

    @pytest.mark.parametrize("svc", ["sssd"])
    def test_service_enabled(self, ipaclient, svc):
        assert ipaclient.service(svc).is_enabled, f"Service {svc!r} not enabled"


class TestKerberosEnrollment:

    def test_krb5_keytab_exists(self, ipaclient):
        f = ipaclient.file("/etc/krb5.keytab")
        assert f.exists and f.size > 0, "/etc/krb5.keytab missing or empty"

    def test_krb5_conf_exists(self, ipaclient):
        f = ipaclient.file("/etc/krb5.conf")
        assert f.exists and f.size > 0, "/etc/krb5.conf missing or empty"

    def test_krb5_conf_has_realm(self, ipaclient, ipa_realm):
        if not ipa_realm:
            pytest.skip("ipa_realm not configured")
        content = ipaclient.file("/etc/krb5.conf").content_string
        assert ipa_realm.upper() in content.upper(), (
            f"Realm {ipa_realm!r} not found in /etc/krb5.conf"
        )


class TestIPAConfigFile:

    def test_ipa_default_conf_exists(self, ipaclient):
        f = ipaclient.file("/etc/ipa/default.conf")
        assert f.exists and f.size > 0, "/etc/ipa/default.conf missing or empty"

    def test_ipa_conf_has_realm(self, ipaclient, ipa_realm):
        if not ipa_realm:
            pytest.skip("ipa_realm not configured")
        content = ipaclient.file("/etc/ipa/default.conf").content_string
        assert ipa_realm.upper() in content.upper(), (
            f"Realm {ipa_realm!r} not found in /etc/ipa/default.conf"
        )

    def test_ipa_conf_has_domain(self, ipaclient, ipa_domain):
        if not ipa_domain:
            pytest.skip("ipa_domain not configured")
        content = ipaclient.file("/etc/ipa/default.conf").content_string
        assert ipa_domain.lower() in content.lower(), (
            f"Domain {ipa_domain!r} not found in /etc/ipa/default.conf"
        )


class TestIPAConnectivity:

    def test_ipa_ping(self, ipaclient):
        r = ipaclient.run(
            "kinit -k -t /etc/krb5.keytab $(hostname -f) 2>/dev/null; ipa ping"
        )
        assert r.rc == 0, f"'ipa ping' failed:\n{r.stderr}"

    def test_ipa_getcert_list(self, ipaclient):
        r = ipaclient.run("ipa-getcert list")
        assert r.rc == 0, f"'ipa-getcert list' failed:\n{r.stderr}"

    def test_dns_srv_resolves(self, ipaclient, ipa_domain):
        if not ipa_domain:
            pytest.skip("ipa_domain not configured")
        r = ipaclient.run(
            f"dig +short _kerberos._tcp.{ipa_domain} SRV 2>/dev/null || "
            f"nslookup _kerberos._tcp.{ipa_domain} 2>/dev/null"
        )
        assert r.rc == 0 and r.stdout.strip(), (
            f"SRV record for {ipa_domain!r} did not resolve"
        )
