# Parser authoring guide

Parsers convert bounded provider output into typed `Fact` values. Parsing is a
deterministic evidence boundary: it may extract what the output states, but it
must not promote an observation to verified truth.

## Add or extend a parser family

1. Choose the narrowest existing family in `core/ai/parsers/`. Create a new
   family only when tool ownership and fact semantics do not fit an existing
   one.
2. Subclass `BaseParser` and implement
   `parse(tool_name, raw_output, session_id) -> list[Fact]`.
3. Gate on explicit tool names, structured markers, or unambiguous syntax.
4. Return canonical fact types and bounded values. Preserve host/session and
   source provenance supplied by the parsing pipeline.
5. Register the family in `ParserFamilyPipeline` before generic legacy/LLM
   fallback.

Structured output is preferred over text regexes. Negative results, timeouts,
partial output, malformed records, and duplicate lines need explicit fixtures.
Do not parse error prose as a positive finding. Do not store raw secrets;
credential material must cross the secret-store boundary and facts retain a
reference or redacted value.

## Evidence and assessment

A parser emits an observation. Verification or contradiction is recorded by
`FactAssessmentStore` with an assessment reason, evidence fact IDs, and source
execution IDs. CVE text, an exploit name, successful authentication, and root
access each have distinct fact/report semantics.

## Quality bar

For every parser branch include:

- one representative positive fixture;
- a clean negative control;
- truncated/partial and malformed input;
- repeated input proving deduplication at ingestion;
- a secret/redaction case when applicable;
- replay assertions for exact fact type/value/provenance.

Avoid network access, installed binaries, live services, wall-clock dependence,
and unseeded randomness. Keep fixtures small enough to review.

Run:

```bash
venv/bin/python -m pytest -q tests/test_parser_family_contracts.py -m contract
venv/bin/python -m pytest -q -m replay
```
