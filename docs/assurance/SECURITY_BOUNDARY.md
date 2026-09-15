# Security Boundary

STIG Audit Pro is strictly read-only with respect to managed devices.

It may connect with SSH, enter privileged EXEC when necessary, disable terminal pagination for that session, execute fixed approved read-only commands, collect/parse evidence, evaluate checks, show DISA guidance, and export reports/checklists.

It does not enter configuration mode, execute `configure terminal`, apply fix/remediation text, change or save configuration, run `write memory`, copy running configuration to startup configuration, reload, erase, or implement an automatic remediation engine.

## Enforcement

- One authoritative `CommandPolicy` normalizes whitespace and exact-matches a minimal registry.
- Newline, carriage return, NUL/control input, command chaining, redirects/substitution, and unknown commands are rejected.
- YAML load and runtime Netmiko execution call the same policy.
- All commands are validated before a connection begins.
- The sole session operation `terminal length 0` is fixed and policy-registered; it is not general permission for terminal/configuration commands.
- One worker owns one SSH connection; no connection is shared between devices.

The architecture deliberately contains no configuration/remediation adapter. Adding such a component would cross the product boundary and requires a different product/security review.
