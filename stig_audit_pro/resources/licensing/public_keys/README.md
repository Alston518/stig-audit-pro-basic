# Production public keys

Copy each publisher-generated Ed25519 public key into this directory as:

```text
<key_id>.pem
```

For the first production key, the exact path is:

```text
stig_audit_pro/resources/licensing/public_keys/stig-audit-prod-2026-01.pem
```

Only public keys belong here. Never place an Ed25519 private key in this
directory or anywhere else in the customer application source tree.
