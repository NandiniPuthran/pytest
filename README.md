# IPA Certificate Workflow — Testinfra Test Suite

## Directory layout

```
.
├── pytest.ini
├── requirements.txt
│
├── inventories/
│   ├── infra1/
│   │   ├── hosts.ini                        ← Ansible INI inventory
│   │   ├── infra_vars.yml                   ← optional infra-level overrides
│   │   ├── group_vars/
│   │   │   ├── all.yml                      ← global vars (lowest in group layer)
│   │   │   └── certificate_group.yml        ← group-specific vars
│   │   └── host_vars/
│   │       ├── host1.example.com.yml
│   │       └── host2.example.com.yml
│   ├── infra2/
│   │   └── ...
│   └── infra3/
│       └── ...
│
├── roles/
│   ├── ipa_cert/defaults/main.yml
│   ├── ipa_client/defaults/main.yml
│   ├── ipa_server/defaults/main.yml
│   └── common_tls/defaults/main.yml
│
└── tests/
    ├── conftest.py                          ← variable loading + all fixtures
    ├── test_csr_and_key_generation.py
    ├── test_certificate_signed.py
    ├── test_copy_to_ipaclient.py
    └── test_ipaclient.py
```

---

## Variable merge order (lowest → highest priority)

```
roles/*/defaults/main.yml   (all roles, equal weight)
  └─▶ group_vars/all.yml
        └─▶ group_vars/certificate_group.yml
              └─▶ inventories/<infra>/infra_vars.yml
                    └─▶ host_vars/<hostname>.yml   (applied per-test, not session)
```

This mirrors Ansible's own precedence. group_vars always beats role defaults.

---

## Running the tests

### Basic — single infra, single role

```bash
pytest tests/ \
  --infra=infra1 \
  --inventories=inventories \
  --role-roots=roles/ipa_cert \
  --connection=ssh
```

### Multiple roles (all defaults merged, equal weight)

```bash
pytest tests/ \
  --infra=infra1 \
  --role-roots=roles/ipa_cert,roles/ipa_client,roles/ipa_server,roles/common_tls \
  --connection=ssh
```

### Different infra

```bash
pytest tests/ --infra=infra3 --role-roots=roles/ipa_cert,roles/ipa_client
```

### Run only security checks

```bash
pytest tests/ --infra=infra1 -m security
```

### Override hosts without editing inventory

```bash
CERTIFICATE_HOSTS="host1.example.com,host2.example.com" \
  pytest tests/ --infra=infra1
```

### Override IPAclient host

```bash
IPACLIENT_HOST="ipaclient.infra1.example.com" \
  pytest tests/ --infra=infra1
```

---

## Environment variable reference

| Env var              | Equivalent CLI flag  | Purpose                                      |
|----------------------|----------------------|----------------------------------------------|
| `INFRA`              | `--infra`            | Which infra directory to use                 |
| `INVENTORIES_ROOT`   | `--inventories`      | Root folder containing infra subdirs         |
| `ROLE_ROOTS`         | `--role-roots`       | Comma-separated role paths                   |
| `CERT_GROUP`         | `--cert-group`       | Ansible group name (default: certificate_group) |
| `CERTIFICATE_HOSTS`  | _(none)_             | Override host list (skip INI parsing)        |
| `IPACLIENT_HOST`     | _(none)_             | Override IPAclient hostname                  |

---

## hosts.ini format expected

```ini
[certificate_group]
host1.example.com
host2.example.com
host3.example.com

[ipaclient_server]
ipaclient.example.com

; child groups are also resolved
[certificate_group:children]
webapp_hosts
db_hosts

[webapp_hosts]
web1.example.com
web2.example.com
```

---

## group_vars/certificate_group.yml reference

```yaml
cert_base_dir: /data/certificates
cert_types: [client, server]

ipa_realm: EXAMPLE.COM
ipa_domain: example.com
ipa_ca_subject: "Certificate Authority"
ipaclient_host: ipaclient.example.com

cert_owner: root
cert_group: root
cert_file_mode: "0644"
key_file_mode:  "0600"
cert_validity_days: 365
```

---

## Test coverage summary

| Module                         | Scope          | Key assertions                                                                 |
|-------------------------------|----------------|--------------------------------------------------------------------------------|
| `test_csr_and_key_generation` | Each cert host | File existence, perms, PEM valid, Subject CN, RSA key valid, CSR↔key modulus  |
| `test_certificate_signed`     | Each cert host | CRT perms, IPA issuer, Subject CN, CRT↔key modulus, not expired, SAN, not self-signed |
| `test_copy_to_ipaclient`      | IPAclient host | CSR md5 matches source, **key NOT copied**, signed CRT present, CRT back on origin |
| `test_ipaclient`              | IPAclient host | Package installed, sssd running/enabled, keytab, krb5.conf, ipa ping, DNS SRV |

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `--infra is required` | Pass `--infra=infra1` or set `INFRA=infra1` |
| `Inventory directory not found` | Check `inventories/<infra>/` exists |
| `No hosts found under [certificate_group]` | Check `hosts.ini` group name or set `CERTIFICATE_HOSTS` |
| `ipaclient_host not set` | Add `ipaclient_host:` to `group_vars/certificate_group.yml` |
| `openssl: command not found` | `apt install openssl` on target hosts |
| `ipalib not importable` | `apt install freeipa-client` on IPAclient host |
