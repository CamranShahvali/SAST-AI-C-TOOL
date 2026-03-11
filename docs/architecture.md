# Architecture

## Goals

- deterministic static analysis core
- low false positives through explicit validation
- clear `candidate -> validation -> decision` pipeline
- LLM review only for ambiguous or high-value findings
- C++ first, Rust-compatible architecture later

## Core Pipeline

1. `ingest` discovers files, cache state, and changed-file filters.
2. `build` locates or captures `compile_commands.json`.
3. `frontend_cpp` parses translation units with Clang LibTooling and emits normalized summaries.
4. `index` and `graph` build symbol and call relationships.
5. `rules` converts source/sink matches into candidates.
6. `validators` evaluates positive, negative, and ambiguous conditions for each candidate.
7. `triage` turns validated candidates into final decisions.
8. `report` emits text, JSON, and SARIF.
9. `llm_gateway` is only invoked for ambiguous or high-value findings.

## Fast Scan Strategy

- translation units are fingerprinted from file metadata and compile arguments
- unchanged summaries are loaded from cache
- changed-files mode narrows frontend work while cached summaries preserve context
- interprocedural expansion is bounded by `--max-depth`
- only functions that touch sources, sinks, wrappers, or predicates are escalated

Current milestone hooks:

- scan orchestration records parse time, candidate generation time, validation time, and full scan time
- changed-files-only mode records selected vs skipped translation units and effective skip rate
- Linux builds sample process RSS from `/proc/self/status`
- `cache_hit_rate` is present as a stable metric field, but persistent summary caching is not yet active
- optional smoke benchmarks can measure gateway latency separately when the FastAPI sidecar is running

## Safety Model

Each rule family is modeled with:

- positive conditions
- negative conditions
- ambiguous conditions

The validator reasons about:

- explicit sanitizers
- strict allowlisting predicates
- canonicalization under a fixed root
- trusted wrappers
- bounded memory operations
- simple guard feasibility
- compile-time constants
- dead paths such as `if (false)`
- test-only paths
- inline or config-based suppression

Current implemented deterministic checks:

- strict allowlist guards for command execution sinks
- canonicalized path under a fixed literal root for file sinks
- bounded `snprintf`-style writes for string and buffer sinks
- configured trusted wrappers
- dead and test-only path dismissal where there is direct local proof

Current decision outcomes:

- `confirmed_issue`
- `likely_issue`
- `needs_review`
- `likely_safe`
- `safe_suppressed`

## LLM Boundary

Only compact structured context is sent to the model:

- rule type
- source summary
- sink summary
- path summary
- guard and sanitizer summary
- at most two small code windows

The gateway performs:

- schema validation
- retry and fallback logic
- provider abstraction
- hosted or local model compatibility through an OpenAI-style HTTP contract
- mock-provider operation by default
- hosted-provider review only for `needs_review`, `likely_issue`, and `likely_safe`

## Benchmark And Regression Harness

The benchmark fixture sets are grouped by expected analysis shape:

- `benchmarks/fixtures/vulnerable_examples`
- `benchmarks/fixtures/safe_lookalikes`
- `benchmarks/fixtures/ambiguous_cases`
- `benchmarks/fixtures/cross_function`
- `benchmarks/fixtures/mixed_repo`

The regression suite protects both directions:

- `tests/regression/false_positives` must stay `safe_suppressed` or `likely_safe`
- `tests/regression/false_negatives` must stay detected as `confirmed_issue` or `likely_issue`

`benchmarks/run_smoke.py` is the lightweight benchmark entrypoint. It exercises the benchmark binary, the CLI validated scan path, changed-files-only mode, and optional LLM gateway latency measurement without changing deterministic scan behavior.
