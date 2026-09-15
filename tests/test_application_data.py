from stig_audit_pro.storage.application_data import bootstrap_writable_data


def test_bootstrap_adds_defaults_without_overwriting_customer_data(tmp_path):
    bundled = tmp_path / "bundled"
    destination = tmp_path / "application-data"
    (bundled / "checks").mkdir(parents=True)
    (bundled / "profiles").mkdir()
    (bundled / "checks" / "iosxe_l2.yaml").write_text(
        "library_version: bundled\n", encoding="utf-8"
    )
    (bundled / "profiles" / "new-site.yaml").write_text(
        "profile_name: new-site\n", encoding="utf-8"
    )
    (destination / "checks").mkdir(parents=True)
    (destination / "checks" / "iosxe_l2.yaml").write_text(
        "library_version: customer-edited\n", encoding="utf-8"
    )

    result = bootstrap_writable_data(bundled, destination=destination)

    assert result == destination.resolve()
    assert (destination / "checks" / "iosxe_l2.yaml").read_text(
        encoding="utf-8"
    ) == "library_version: customer-edited\n"
    assert (destination / "profiles" / "new-site.yaml").read_text(
        encoding="utf-8"
    ) == "profile_name: new-site\n"


def test_bootstrap_ignores_symlinks_when_supported(tmp_path):
    bundled = tmp_path / "bundled"
    destination = tmp_path / "application-data"
    bundled.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("sensitive", encoding="utf-8")
    link = bundled / "linked.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        return

    bootstrap_writable_data(bundled, destination=destination)

    assert not (destination / "linked.txt").exists()
