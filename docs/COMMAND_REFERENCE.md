# Command Reference (v0.2)

The executable command inventory is generated from the authoritative
`CommandPolicy`; see [assurance/COMMAND_REFERENCE.md](assurance/COMMAND_REFERENCE.md).
Do not edit the generated file by hand.

STIG Audit Pro accepts only exact registered commands after ordinary whitespace
normalization. It rejects unknown commands, multiline/control input, chaining,
redirection, configuration, save, erase, reload, and remediation operations
before SSH connection. `terminal length 0` is the only session-only operation.
