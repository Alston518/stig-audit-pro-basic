# Testing Guide

Run the complete suite with `python -m pytest`. Critical coverage includes:

- strict command-policy injection/chaining rejection;
- Pydantic/YAML schema and unknown-key validation;
- parser and check-engine behavior;
- bounded concurrency, failure isolation, cancellation, events, and connection ownership;
- SQLite foreign keys, CRUD, history, delete, and purge using temporary databases;
- cross-run evidence separation, exact-byte hashes, modified/missing detection, and secret-free manifests;
- normalized STIG release comparison, ambiguous matching, YAML impact, review state, and coverage;
- JSON schema, XLSX workbook structure/counts, CKL, and representative CKLB round trips.

Generated documentation is part of CI:

```powershell
python scripts/generate_command_reference.py --check
python scripts/generate_stig_traceability.py --check
python scripts/validate_docs.py
```

Tests must not initiate real SSH, use the user application database, write into installed STIG/check data unexpectedly, or depend on Internet access.
