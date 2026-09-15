# Check Authoring Guide

Check libraries are strict YAML documents:

```yaml
schema_version: 1
library_name: iosxe_l2
library_version: "2026.09"
checks:
  - vuln_id: V-000000
    rule_id: SV-000000r1_rule
    stig_id: CISC-L2-000000
    source_benchmark: example
    source_version: "3"
    source_release: "1"
    automated: false
    check_type: manual_review
    commands:
      - show running-config
```

Unknown keys, malformed types, partial schema metadata, and unsupported schema versions are rejected. Legacy libraries without schema metadata pass only through the controlled compatibility path; new files must declare both schema and library version.

## Commands

A command appearing in YAML is not trusted. It must be an exact normalized entry from `CommandPolicy`; pipelines are approved as complete fixed commands. Embedded newlines, controls, chaining, substitutions, redirects, and unknown parameters fail closed. Add a new read-only command only by updating the central registry, tests, generated command reference, and any dedicated parameter validator.

## Automation

Use the narrowest existing check type. `manual_review` is correct when the current parsers cannot confidently evaluate the DISA procedure. Profile placeholders may provide site values, but missing/invalid values must produce an explicit error or review outcome rather than a false pass.

After modifying logic for a new STIG release, validate samples/tests and explicitly mark its mapping reviewed against the current rule fingerprint. Saving YAML alone does not mark it reviewed.
