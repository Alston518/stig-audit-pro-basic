from stig_audit_pro.infrastructure.security.at_rest import AtRestVault


def test_basic_vault_does_not_derive_unused_database_key(tmp_path):
    vault = AtRestVault.open(tmp_path / "vault.json", "test", create=True)
    assert not hasattr(vault, "database_key")
