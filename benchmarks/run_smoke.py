#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_json(command: list[str]) -> dict:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def small_code_window(file_path: Path, line: int) -> dict:
    lines = file_path.read_text(encoding="utf-8").splitlines()
    start = max(1, line - 2)
    end = min(len(lines), start + 11)
    snippet = "\n".join(lines[start - 1 : end])
    return {
        "file_path": str(file_path),
        "start_line": start,
        "end_line": end,
        "snippet": snippet,
    }


def build_gateway_payload(report: dict) -> dict | None:
    for finding in report.get("findings", []):
        validation = finding["validation"]
        if validation["final_decision"] not in {"needs_review", "likely_issue", "likely_safe"}:
            continue

        candidate = finding["candidate"]
        file_path = Path(candidate["file"])
        return {
            "candidate_id": candidate["id"],
            "rule_id": candidate["rule_id"],
            "current_judgment": validation["final_decision"],
            "provisional_severity": candidate["provisional_severity"],
            "confidence": validation["confidence"],
            "source_summary": candidate["source_summary"],
            "sink_summary": candidate["sink_summary"],
            "path_summary": " -> ".join(candidate["trace_steps"])[:1000],
            "guard_summary": (
                "; ".join(validation["safe_reasoning"] + validation["ambiguous_reasoning"])
                or validation["explanation"]
            )[:1000],
            "code_windows": [small_code_window(file_path, candidate["line"])],
        }
    return None


def maybe_measure_llm_latency(gateway_url: str | None, report: dict) -> dict | None:
    if not gateway_url:
        return None

    payload = build_gateway_payload(report)
    if payload is None:
        return None

    request = urllib.request.Request(
        f"{gateway_url.rstrip('/')}/review",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        return {
            "status": "unavailable",
            "error": str(exc),
        }

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return {
        "status": "ok",
        "latency_ms": elapsed_ms,
        "response": body,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ai_sast benchmark smoke suite")
    parser.add_argument("--cli-binary", default="./build/sast-cli")
    parser.add_argument("--benchmark-binary", default="./build/sast-benchmarks")
    parser.add_argument("--gateway-url", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    benchmark_binary = str((ROOT / args.benchmark_binary).resolve()) if args.benchmark_binary.startswith(".") else args.benchmark_binary
    cli_binary = str((ROOT / args.cli_binary).resolve()) if args.cli_binary.startswith(".") else args.cli_binary

    fixtures = {
        "vulnerable_examples": ROOT / "benchmarks" / "fixtures" / "vulnerable_examples",
        "safe_lookalikes": ROOT / "benchmarks" / "fixtures" / "safe_lookalikes",
        "ambiguous_cases": ROOT / "benchmarks" / "fixtures" / "ambiguous_cases",
        "cross_function": ROOT / "benchmarks" / "fixtures" / "cross_function",
        "mixed_repo": ROOT / "benchmarks" / "fixtures" / "mixed_repo",
    }

    suite: dict[str, object] = {"fixtures": {}}
    for name, repo in fixtures.items():
        suite["fixtures"][name] = run_json([benchmark_binary, "--repo", str(repo)])

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as changed_file:
        changed_file.write("ambiguous_memcpy.cpp\n")
        changed_file_path = changed_file.name

    suite["changed_files_run"] = run_json(
        [
            benchmark_binary,
            "--repo",
            str(fixtures["mixed_repo"]),
            "--changed-files",
            changed_file_path,
        ]
    )

    validated_report = run_json(
        [
            cli_binary,
            "scan",
            "--repo",
            str(fixtures["mixed_repo"]),
            "--format",
            "json",
        ]
    )
    suite["llm_review"] = maybe_measure_llm_latency(args.gateway_url, validated_report)

    output = json.dumps(suite, indent=2)
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
