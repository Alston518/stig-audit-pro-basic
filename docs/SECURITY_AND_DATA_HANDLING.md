# Security and Data Handling (v0.2)

Current v0.2 assurance documentation:

- [Security boundary](assurance/SECURITY_BOUNDARY.md)
- [Evidence handling](assurance/EVIDENCE_HANDLING.md)
- [Threat model](assurance/THREAT_MODEL.md)
- [Generated command reference](assurance/COMMAND_REFERENCE.md)

v0.2 stores raw evidence per UUID audit run, hashes exact UTF-8 bytes, and
supports integrity verification. Evidence may still contain sensitive device
data and is not automatically redacted. Hashes establish post-collection
integrity only; they do not authenticate the collector, device, or chain of
custody.
