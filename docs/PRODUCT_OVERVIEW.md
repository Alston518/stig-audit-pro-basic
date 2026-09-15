# STIG Audit Pro v0.2.0 Product Overview

STIG Audit Pro is a Windows desktop application for authorized, read-only
Cisco IOS-XE L2 and NDM evidence collection and STIG assessment. It supports
sample, live SSH, and clearly labeled offline-imported evidence workflows.

The application uses exact approved commands, may enter privileged EXEC mode,
and may disable pagination for its session. It never enters configuration mode,
applies remediation, saves configuration, reloads a device, or stores device
credentials in audit history, manifests, presets, or normal logs.

v0.2 adds concurrent bounded scans, UUID audit runs, SQLite history, immutable
evidence paths and SHA-256 verification, run comparison, CKLB/JSON/XLSX
reporting, and a versioned STIG Library with normalized release differences,
YAML impact, review state, and coverage.

For current details see the [documentation index](INDEX.md),
[architecture](architecture/ARCHITECTURE.md),
[operator guide](operator/ADMINISTRATOR_GUIDE.md), and generated
[command reference](assurance/COMMAND_REFERENCE.md).

Results assist an assessor; they are not certification, remediation direction,
or authorization to change a system. Official source material should be
obtained from the [DoD Cyber Exchange STIG library](https://www.cyber.mil/stigs/downloads/).
