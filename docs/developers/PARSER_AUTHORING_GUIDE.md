# Parser Authoring Guide

Parsers transform immutable command output into small domain structures consumed by checks. They must not connect to devices, issue commands, mutate evidence, write configuration, or depend on GUI state.

Guidelines:

1. Accept raw text and explicit profile/context inputs.
2. Normalize line endings conservatively and preserve IOS syntax where semantically important.
3. Return deterministic structures and surface warnings for incomplete or surprising output.
4. Avoid treating absent/truncated output as compliant.
5. Add representative compliant, noncompliant, empty, and malformed fixtures.
6. Test parsing separately from check evaluation.

Register new parser-backed check types through the existing check engine dispatch without introducing a second command allowlist. The check definition declares evidence commands; collection remains centralized and policy-validated.
