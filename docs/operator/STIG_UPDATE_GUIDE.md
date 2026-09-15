# STIG Update Guide

Use this deliberate workflow for every new DISA release:

1. Import the new DISA STIG ZIP or XCCDF XML in **STIG Library**.
2. Confirm the application selected the previous release from the same family and benchmark. A first import is a baseline (`NO_PREVIOUS_RELEASE`).
3. Compare normalized releases, not raw XML.
4. Review Added, Removed, Changed, and Unchanged rules and each changed field.
5. Review **YAML Impact** for the exact local file/check affected and the recommended action.
6. Generate missing `manual_review` starter checks for added rules. Never overwrite an existing mapping.
7. Deliberately modify affected YAML metadata or automation and run validation/sample tests.
8. Run `python -m pytest` and the documentation/check validation commands.
9. Explicitly mark updated automation reviewed against the new rule fingerprint and release.
10. Confirm coverage has no unintended missing, retired, or stale/unreviewed automation.

STIG Audit Pro never rewrites existing automated logic merely because DISA prose changed. A changed check procedure requires engineering judgment; fix text is guidance only and is never executed.

See [STIG Difference Guide](STIG_DIFF_GUIDE.md) for classifications.
