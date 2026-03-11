# ai_sast

`ai_sast` is a C++-first AI-assisted SAST project. The current milestone implements the C++ frontend, candidate detection, and a deterministic validator/decision layer:

- compile database discovery via `compile_commands.json`
- Clang LibTooling parsing
- minimal normalized IR for extracted facts
- config-backed source/sink registry loading
- candidate generation for initial rule families
- validator-backed final classification
- JSON output for facts and validated findings

Important: a source or sink match is never treated as a vulnerability by itself. The detection philosophy is:

```text
candidate -> validate -> prove vulnerable or dismiss
```

`scan` emits validated findings. Each finding still preserves the original candidate evidence, but the final output always includes a deterministic judgment and the reasoning that made it safe, ambiguous, or escalated.

The current milestone also adds:

- a benchmark harness for vulnerable, safe-looking, ambiguous, and cross-function fixtures
- regression suites for previously fixed false positives and false negatives
- scan metrics for parse time, candidate generation time, validation time, full scan time, skip rate, RSS on Linux, and optional LLM review latency
- changed-files-only scan support for CI and incremental smoke runs

## Prerequisites

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y build-essential git cmake ninja-build clang-18 clang-tools-18 libclang-18-dev llvm-18-dev llvm-18-tools pkg-config bear ccache jq python3 python3-venv python3-pip
```

Python gateway test environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r llm_gateway/requirements.txt -r llm_gateway/requirements-dev.txt
```

## Build

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++-18 \
  -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm \
  -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang

cmake --build build
```

## Test

```bash
ctest --test-dir build --output-on-failure
source .venv/bin/activate
python -m pytest llm_gateway/tests
```

## Reproducible Demo

The repo includes a built-in deterministic demo mode for three curated cases:

- a real confirmed vulnerability
- a dismissed lookalike that is proven safe
- a helper-boundary case that still reaches a deterministic decision

Copy-paste walkthrough:

```bash
cmake --build build

./build/sast-cli demo

./build/sast-cli demo --format json --out build/demo.json

jq '.' build/demo.json
```

What the demo does:

- scans the curated sources in `tests/demo/curated`
- uses the same deterministic pipeline as `scan`
- does not call the LLM gateway
- keeps the wording intentionally conservative for investor or stakeholder walkthroughs

Important honesty note:

- this is a small curated demo
- it shows how the engine confirms and dismisses representative cases
- it is not a claim of complete whole-program proof on arbitrary repositories

## LLM Gateway

The deterministic scanner remains the primary engine. The FastAPI gateway is a narrow sidecar contract for ambiguous or high-value findings only.

Compact request payload fields:

- `candidate_id`
- `rule_id`
- `source_summary`
- `sink_summary`
- `path_summary`
- `guard_summary`
- up to two small `code_windows`

Compact response fields:

- `judgment`
- `confidence`
- `cwe`
- `exploitability`
- `reasoning_summary`
- `remediation`
- `safe_reasoning`

Hard boundaries enforced by the schema:

- no whole repositories
- no whole files
- at most two code windows
- each code window is capped to 12 lines

Python setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r llm_gateway/requirements.txt -r llm_gateway/requirements-dev.txt
```

Run the gateway with the default mock provider:

```bash
source .venv/bin/activate
export SAST_LLM_PROVIDER=mock
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081
```

Health and schema endpoints:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/schema/request
curl http://127.0.0.1:8081/schema/response
```

What is mocked vs provider-backed:

- default behavior is `mock`; this is what the test suite exercises
- `openai_responses` is the supported hosted provider adapter in this milestone
- the deterministic scanner is not yet auto-calling the gateway; enablement is currently at the sidecar boundary only

Required environment variables and switches:

- `SAST_LLM_ENABLED=1` enables provider calls inside the gateway
- `SAST_LLM_ENABLED=0` disables provider calls and forces deterministic fallback
- `SAST_LLM_PROVIDER=mock|openai_responses`
- `OPENAI_API_KEY=...` is required only for `openai_responses`
- `SAST_LLM_MODEL=gpt-5-mini`
- `SAST_LLM_BASE_URL=https://api.openai.com`
- `SAST_LLM_TIMEOUT=20`
- `SAST_LLM_MAX_RETRIES=2`

Enable mock review locally:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=1
export SAST_LLM_PROVIDER=mock
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081
```

Disable all LLM review but keep the gateway running:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=0
export SAST_LLM_PROVIDER=mock
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081
```

Enable hosted OpenAI-compatible review:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=1
export SAST_LLM_PROVIDER=openai_responses
export OPENAI_API_KEY=...
export SAST_LLM_MODEL=gpt-5-mini
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081
```

## Compile Database Discovery

`sast-cli facts` prefers `compile_commands.json`.
`sast-cli scan` uses the same discovery order and falls back to synthetic compile commands for standalone source trees when no compile database is present.

Discovery order:

1. `--compdb <path>`
2. `<repo>/compile_commands.json`
3. `<repo>/build/**/compile_commands.json`
4. `<repo>/build-*/**/compile_commands.json`

Generate a compile database for a CMake project:

```bash
cmake -S <repo> -B <repo>/build -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

Capture a non-CMake build if needed:

```bash
bear -- make -j"$(nproc)"
```

## Config Files

The default rule configuration lives under `config/` and is versioned with `"version": 1`:

- `config/rules.json`
- `config/sources.json`
- `config/sinks.json`
- `config/sanitizers.json`
- `config/wrappers.json`

Repo-local config overrides are loaded from `<repo>/config/` when present. Otherwise the built-in repo config is used.

## Fact Extraction Mode

CLI:

```text
sast-cli facts --repo <path> [--compdb <path>|--auto-compdb] [--jobs N] [--out <file>]
```

Facts are emitted only for source locations under the requested `--repo` root. The CLI
normalizes relative and absolute repo paths before compile database discovery and parsing.

Example on the included fixture:

```bash
cmake -S tests/fixtures/cmake_cpp_sample -B tests/fixtures/cmake_cpp_sample/build -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

./build/sast-cli facts --repo tests/fixtures/cmake_cpp_sample --auto-compdb
```

Example JSON shape:

```json
{
  "compilation_database_path": ".../compile_commands.json",
  "translation_units": [
    {
      "file_path": ".../src/main.cpp",
      "functions": [
        {
          "qualified_name": "main",
          "return_type": "int",
          "location": {
            "file": ".../src/main.cpp",
            "line": 5,
            "column": 5
          },
          "call_sites": [
            {
              "callee": "sample::make_message",
              "argument_texts": ["name"]
            }
          ],
          "variable_refs": [
            {
              "name": "argc",
              "referenced_kind": "parameter"
            }
          ]
        }
      ]
    }
  ]
}
```

## Candidate And Validation Scan Mode

CLI:

```text
sast-cli scan --repo <path> [--compdb <path>|--auto-compdb] [--changed-files <file>] [--candidates-only] [--jobs N] [--format json|sarif|text] [--out <file>]
```

Implemented rule families:

- `command_injection.system`: command execution misuse via configured process execution sinks such as `system`, `popen`, and `exec*`
- `path_traversal.file_open`: user-controlled path flow into configured file open sinks such as `fopen`, `open`, and stream `open`
- `dangerous_string.unbounded_copy`: dangerous buffer/string handling via configured sinks such as `strcpy`, `strcat`, `sprintf`, `memcpy`, `memmove`, and `snprintf`

Implemented validator checks:

- strict allowlist guards for command execution
- canonicalized path under a fixed root for file access
- bounded `snprintf`-style writes for string and buffer handling
- known safe wrappers loaded from config
- simple dead-path dismissal for `if (false)`, `if constexpr (false)`, and `#if 0`
- simple test-only path dismissal and inline/config suppressions

Final decision outcomes:

- `confirmed_issue`
- `likely_issue`
- `needs_review`
- `likely_safe`
- `safe_suppressed`

Validated finding JSON fields:

- `candidate.id`
- `candidate.rule_id`
- `candidate.file`
- `candidate.line`
- `candidate.source_summary`
- `candidate.sink_summary`
- `candidate.trace_steps`
- `candidate.provisional_severity`
- `candidate.evidence_locations`
- `validation.final_decision`
- `validation.confidence`
- `validation.explanation`
- `validation.safe_reasoning`
- `validation.ambiguous_reasoning`
- `validation.matched_positive_conditions`
- `validation.matched_negative_conditions`
- `validation.matched_ambiguous_conditions`

Example on the included case corpus:

```bash
./build/sast-cli scan --repo tests/cases/demo --format json
```

The output is explicitly marked with `"candidate_only": false` and includes:

- the original candidate evidence
- the final deterministic judgment
- why the finding was considered safe, ambiguous, or escalated

Stable schemas:

- validated JSON: `report.schema.json` -> `docs/report.schema.json`
- candidate-only JSON: `candidate-report.schema.json` -> `docs/candidate-report.schema.json`

Format examples:

```bash
./build/sast-cli scan --repo tests/cases/demo --format json

./build/sast-cli scan --repo tests/cases/demo --format sarif --out build/demo.sarif

./build/sast-cli scan --repo tests/cases/demo --format text
```

Investor demo output:

```bash
./build/sast-cli demo
./build/sast-cli demo --format json --out build/demo.json
```

Candidate-only debug output remains available in JSON:

```bash
./build/sast-cli scan --repo tests/cases/demo --candidates-only --format json
```

Changed-files-only mode narrows the scan to the listed source files:

```bash
printf 'needs_review_string.cpp\n' > build/demo.changed
./build/sast-cli scan --repo tests/cases/demo --changed-files build/demo.changed --format json
```

The changed-file list may contain repo-relative or absolute paths. The scanner normalizes them against `--repo` before filtering translation units.

## Benchmarks And Regression Harness

Build the benchmark binary with the main project:

```bash
cmake --build build --target sast-benchmarks
```

Run the benchmark smoke suite:

```bash
python3 benchmarks/run_smoke.py \
  --benchmark-binary ./build/sast-benchmarks \
  --cli-binary ./build/sast-cli
```

Optional: measure gateway round-trip latency for one eligible ambiguous or incomplete finding:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=1
export SAST_LLM_PROVIDER=mock
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081

python3 benchmarks/run_smoke.py \
  --benchmark-binary ./build/sast-benchmarks \
  --cli-binary ./build/sast-cli \
  --gateway-url http://127.0.0.1:8081
```

The smoke suite exercises:

- `benchmarks/fixtures/vulnerable_examples`
- `benchmarks/fixtures/safe_lookalikes`
- `benchmarks/fixtures/ambiguous_cases`
- `benchmarks/fixtures/cross_function`
- `benchmarks/fixtures/mixed_repo`

Regression coverage lives in:

- `tests/regression/false_positives`
- `tests/regression/false_negatives`

Reported scan metrics currently include:

- `parse_time_ms`
- `candidate_generation_time_ms`
- `validation_time_ms`
- `full_scan_time_ms`
- `translation_units_total`
- `translation_units_selected`
- `translation_units_skipped`
- `effective_skip_rate`
- `cache_hit_rate`
- `memory_rss_bytes`
- `llm_latency_ms`

Notes:

- `memory_rss_bytes` is populated on Linux through `/proc/self/status`
- `cache_hit_rate` is present as a stable field, but the active pipeline does not yet persist summary cache entries, so it remains `0.0`
- `llm_latency_ms` remains `null` in core scan output until engine-side LLM invocation is wired; the smoke harness can still measure gateway latency separately when `--gateway-url` is provided

## Current Limitations

- source resolution is intentionally shallow and limited to local initializers, parameters, configured source functions, and simple wrapper/accessor patterns
- validator reasoning is intentionally local and heuristic; it does not yet prove complex interprocedural invariants
- wrapper and sanitizer semantics are only as strong as the configured names and the local trace evidence
- changed-files-only filtering is implemented, but persistent summary caching remains a later milestone
- the C++ scanner does not yet automatically call the gateway
- the hosted adapter is verified through mocked HTTP responses, not live network calls

## Current Layout

- `include/sast/build`: compile database discovery
- `include/sast/frontend_cpp`: LibTooling runner
- `include/sast/ir`: normalized fact IR
- `include/sast/report`: JSON fact and validated finding rendering
- `include/sast/rules`: rule specs, source/sink registries, and candidate detection
- `include/sast/validators`: validator registry, safety checks, and decision engine
- `include/sast/triage`: shared scan orchestration and metrics
- `src/cli`: CLI entrypoint
- `benchmarks`: benchmark binary, smoke runner, and categorized fixture repos
- `tests/fixtures/cmake_cpp_sample`: tiny CMake-based sample project used for extraction tests
- `tests/cases`: standalone validated-scan corpus for command execution, path traversal, and string handling
- `tests/regression`: fixed false-positive and false-negative fixtures that must remain stable
- `llm_gateway`: FastAPI sidecar with strict schemas, retry/fallback behavior, and mock/provider adapters

## Current Milestone Output

The active build verifies:

- the project configures and builds against LLVM/Clang 18
- compile database discovery works on a small CMake fixture
- fact extraction returns functions, call sites, variable references, and source locations
- versioned source/sink config loading works
- candidate generation runs for the initial rule families
- validator evidence produces `confirmed_issue`, `likely_issue`, `needs_review`, `likely_safe`, and `safe_suppressed`
- safe and likely-safe outcomes are first-class expected results in the test corpus
- changed-files-only scans report selected vs skipped translation units and skip rate
- benchmark fixtures cover vulnerable, safe-looking, ambiguous, and cross-function propagation scenarios
- regression suites lock in fixed false positives and false negatives
- the gateway exposes strict request/response schemas plus retry and fallback behavior for ambiguous or high-value findings
