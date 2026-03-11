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

Recommended local configure for both the CLI and VS Code CMake Tools:

```bash
cmake --preset clang18-debug
cmake --build --preset clang18-debug
```

VS Code note:

- the repo includes `CMakePresets.json` to force `clang-18`, `clang++-18`, `Ninja`, `LLVM_DIR`, and `Clang_DIR`
- `.vscode/settings.json` tells CMake Tools to use presets instead of guessing a GCC/G++ toolchain
- the workspace also points VS Code C/C++ IntelliSense at `build/compile_commands.json` and `clang++-18`

If VS Code was previously configured with GCC/G++, do this once after pulling the repo changes:

1. `Ctrl+Shift+P` -> `CMake: Delete Cache and Reconfigure`
2. `Ctrl+Shift+P` -> `CMake: Select Configure Preset`
3. choose `Clang 18 Debug`
4. wait for configure to finish

Manual equivalent:

```bash
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_C_COMPILER=clang-18 \
  -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm \
  -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang

cmake --build build
```

## Test

```bash
ctest --preset clang18-debug
source .venv/bin/activate
python -m pytest llm_gateway/tests
```

## Reproducible Demo

The repo includes a built-in deterministic demo mode for five curated cases, one for each current deterministic outcome:

- `confirmed_issue`
- `likely_issue`
- `needs_review`
- `likely_safe`
- `safe_suppressed`

Copy-paste walkthrough:

```bash
cmake --build build

./build/sast-cli demo

./build/sast-cli demo --format json --out build/demo.json

jq '.' build/demo.json
```

Optional local LLM enrichment for eligible demo cases:

```bash
./build/sast-cli demo \
  --llm-review \
  --llm-gateway http://127.0.0.1:8081
```

What the demo does:

- scans the curated sources in `tests/demo/curated`
- uses the same deterministic pipeline as `scan`
- keeps deterministic findings as the source of truth
- can optionally attach advisory LLM review only for `likely_issue`, `needs_review`, and `likely_safe`
- keeps the wording intentionally conservative for investor or stakeholder walkthroughs

Important honesty note:

- this is a small curated demo
- it shows the full five-outcome deterministic story on representative cases
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

`needs_review` policy:

- the gateway keeps `needs_review` explicitly uncertain
- normalized `reasoning_summary` avoids confirmed-vulnerability wording and explains that safety could not be proven and still requires review
- `safe_reasoning` is omitted for `needs_review` unless real safety evidence exists
- remediation stays concrete and sink-specific, but remains cautious

Python setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r llm_gateway/requirements.txt -r llm_gateway/requirements-dev.txt
```

Run the gateway with the default local Ollama provider:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=1
export SAST_LLM_PROVIDER=ollama
export SAST_LLM_BASE_URL=http://127.0.0.1:11434
export SAST_LLM_MODEL=deepseek-coder:6.7b
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081
```

Health and schema endpoints:

```bash
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8081/schema/request
curl http://127.0.0.1:8081/schema/response
```

What is mocked vs provider-backed:

- default behavior is local `ollama`; no paid API key is required for that path
- `mock` remains available for tests and dry-run gateway validation
- `openai_responses` remains available as an optional hosted adapter
- the scanner stays deterministic-first and only calls the gateway when you pass `--llm-review`
- only findings already classified as `needs_review`, `likely_issue`, or `likely_safe` are sent to the gateway
- `confirmed_issue` and `safe_suppressed` findings are never sent

Required environment variables and switches:

- `SAST_LLM_ENABLED=1` enables provider calls inside the gateway
- `SAST_LLM_ENABLED=0` disables provider calls and forces deterministic fallback
- `SAST_LLM_PROVIDER=ollama|mock|openai_responses`
- `SAST_LLM_BASE_URL=http://127.0.0.1:11434` for local Ollama
- `SAST_LLM_MODEL=deepseek-coder:6.7b` for the local DeepSeek model
- `OPENAI_API_KEY=...` is required only for `openai_responses`
- `SAST_LLM_TIMEOUT=20`
- `SAST_LLM_MAX_RETRIES=2`
- `SAST_LLM_GATEWAY_URL=http://127.0.0.1:8081` configures the C++ scanner-to-gateway URL
- `SAST_LLM_GATEWAY_TIMEOUT=25` configures the C++ scanner-to-gateway timeout in seconds

Enable local Ollama + DeepSeek review:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=1
export SAST_LLM_PROVIDER=ollama
export SAST_LLM_BASE_URL=http://127.0.0.1:11434
export SAST_LLM_MODEL=deepseek-coder:6.7b
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081
```

Disable all LLM review but keep the gateway running:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=0
export SAST_LLM_PROVIDER=mock
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081
```

Enable mock review locally for tests or schema debugging:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=1
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
sast-cli scan --repo <path> [--compdb <path>|--auto-compdb] [--changed-files <file>] [--candidates-only] [--llm-review] [--llm-gateway <url>] [--jobs N] [--format json|sarif|text] [--out <file>]
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
- `validation.llm_review` when `--llm-review` is enabled and the gateway returns a review or deterministic fallback

Example on the included case corpus:

```bash
./build/sast-cli scan --repo tests/cases/demo --format json
```

Local Ollama-backed review example:

```bash
source .venv/bin/activate
export SAST_LLM_ENABLED=1
export SAST_LLM_PROVIDER=ollama
export SAST_LLM_BASE_URL=http://127.0.0.1:11434
export SAST_LLM_MODEL=deepseek-coder:6.7b
uvicorn llm_gateway.app.main:app --host 127.0.0.1 --port 8081

./build/sast-cli scan \
  --repo tests/cases/demo \
  --format text \
  --llm-review \
  --llm-gateway http://127.0.0.1:8081
```

The output is explicitly marked with `"candidate_only": false` and includes:

- the original candidate evidence
- the final deterministic judgment
- why the finding was considered safe, ambiguous, or escalated
- optional `validation.llm_review` enrichment for eligible findings only

Stable schemas:

- validated JSON: `report.schema.json` -> `docs/report.schema.json`
- candidate-only JSON: `candidate-report.schema.json` -> `docs/candidate-report.schema.json`

Format examples:

```bash
./build/sast-cli scan --repo tests/cases/demo --format json

./build/sast-cli scan --repo tests/cases/demo --format sarif --out build/demo.sarif

./build/sast-cli scan --repo tests/cases/demo --format text

./build/sast-cli scan \
  --repo tests/cases/demo \
  --format json \
  --llm-review \
  --llm-gateway http://127.0.0.1:8081
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
export SAST_LLM_PROVIDER=ollama
export SAST_LLM_BASE_URL=http://127.0.0.1:11434
export SAST_LLM_MODEL=deepseek-coder:6.7b
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
- `llm_latency_ms` is populated when `--llm-review` is enabled on the scanner and at least one eligible finding is reviewed

## Current Limitations

- source resolution is intentionally shallow and limited to local initializers, parameters, configured source functions, and simple wrapper/accessor patterns
- validator reasoning is intentionally local and heuristic; it does not yet prove complex interprocedural invariants
- wrapper and sanitizer semantics are only as strong as the configured names and the local trace evidence
- changed-files-only filtering is implemented, but persistent summary caching remains a later milestone
- the scanner only enriches findings through the gateway when `--llm-review` is explicitly enabled
- deterministic judgments remain the source of truth; LLM output is advisory metadata only
- the hosted OpenAI-compatible adapter is verified through mocked HTTP responses, not live paid API calls
- the local Ollama path is schema-constrained, but model quality still depends on the installed local model

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
- local Ollama + DeepSeek review works through `llm_gateway`
- `sast-cli scan --llm-review` enriches eligible findings without changing deterministic decisions
# SAST-AI-C-TOOL
