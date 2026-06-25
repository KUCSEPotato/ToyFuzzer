# ToyFuzzer

ToyFuzzer is a small mutation-based fuzzer for learning, experiments, and
research prototyping. It starts from seed files, mutates them, executes a target
program, and stores crashes, hangs, corpus entries, and run statistics.

The current implementation is intentionally compact, but it already includes
several features that are useful for controlled fuzzing experiments:

- Seed corpus loading from files
- Optional dictionary tokens, including a small subset of AFL-style syntax
- Stacked byte-level mutations
- Dictionary insertion and overwrite mutations
- Input splicing between corpus entries
- Reproducible runs with `--random-seed`
- Target command templates with `@@`
- Per-execution timeout handling
- Basic behavior feedback from exit status, stdout, stderr, or trace markers
- Rare-style corpus scheduling
- Crash and hang deduplication by signature
- Optional crash input minimization
- JSONL progress logs and JSON summary files

This project is not meant to replace AFL++, libFuzzer, Honggfuzz, or other
production fuzzers. It is a readable toy implementation for understanding the
moving parts and for testing research ideas before implementing them in a larger
fuzzing framework.

## Repository Layout

```text
toyFuzzer/
  toy_fuzzer.py        Main fuzzer implementation
  target/
    target1.c          Simple demo target with a FUZZ + CRASH condition
    target2.c          Demo target with a deeper multi-condition path
  seeds/
    seed1.txt          Example seed input
  dictionary/          Local dictionary files; ignored by git
  runs/                Fuzzing outputs; ignored by git
```

Other directories in this repository contain separate AFL and fuzzing study
experiments.

## Requirements

- Python 3.10 or newer
- `clang` or another C compiler for the example targets

ToyFuzzer itself only uses the Python standard library.

## Quick Start

From the repository root:

```bash
cd toyFuzzer
clang -g -O0 target/target1.c -o target/target1
mkdir -p seeds dictionary
printf "A" > seeds/seed1.txt
printf "FUZZ\nCRASH\nFUZZ_CRASH\n" > dictionary/target1.dict
python3 toy_fuzzer.py --iterations 1000 --random-seed 1 --minimize-crashes
```

Expected output includes the run directory and, for `target1`, a saved SIGSEGV
crash input once the fuzzer generates an input containing both `FUZZ` and
`CRASH`.

## Basic Usage

```bash
python3 toy_fuzzer.py
```

By default, the fuzzer uses:

- Target: `./target/target1`
- Seeds: `seeds/`
- Dictionary: `dictionary/`
- Output directory: `runs/`
- Iterations: `10000`

Use a fixed random seed for reproducible experiments:

```bash
python3 toy_fuzzer.py --iterations 10000 --random-seed 1337
```

Use an explicit target command:

```bash
python3 toy_fuzzer.py --target "./target/target1 @@"
```

If `@@` appears in the target command, it is replaced with the generated input
file path. If `@@` is not present, the input path is appended as the final
argument.

## Dictionary Format

Dictionary files are optional. Each non-empty line is loaded as a token.

```text
FUZZ
CRASH
FUZZ_CRASH
```

A small subset of AFL-style dictionary syntax is also supported:

```text
kw1="FUZZ"
kw2="CRASH"
```

The `toyFuzzer/dictionary/` directory is ignored by git because it is often
target-specific experiment data. Recreate it locally with the commands in
Quick Start, or point `--dict-dir` at another directory.

## Important CLI Options

```text
--target CMD              Target executable or command template
--seed-dir DIR            Directory containing seed files
--dict-dir DIR            Directory containing dictionary files
--iterations N            Maximum number of generated inputs
--duration SEC            Stop after a wall-clock time limit
--timeout SEC             Per-execution timeout
--random-seed N           Seed the PRNG for reproducible runs
--max-input-len N         Limit generated input size
--min-mutations N         Minimum stacked mutations per input
--max-mutations N         Maximum stacked mutations per input
--schedule rare|uniform   Parent corpus selection strategy
--feedback MODE           status, output, or trace
--minimize-crashes        Shrink unique crashing inputs before saving
--save-duplicates         Save duplicate crash/hang signatures too
```

Show the full CLI:

```bash
python3 toy_fuzzer.py --help
```

## Output Files

Each run creates a timestamped directory under `runs/`:

```text
runs/<timestamp>/
  config.json             CLI configuration for the run
  summary.json            Final aggregate statistics
  stats.jsonl             Periodic progress snapshots
  crashes/                Unique crashing inputs and metadata
  hangs/                  Unique timeout inputs and metadata
  corpus/
    initial_corpus.txt    Human-readable initial corpus report
    final_corpus.txt      Human-readable final corpus report
    queue/                Saved corpus entries
```

Crash and hang inputs are saved as `.bin` files. A matching `.bin.json` metadata
file stores size, SHA-256, exit status, elapsed time, selected features, and
short stdout/stderr previews.

## Reproducing a Crash

Compile the target, then pass the saved crashing input back to it:

```bash
./target/target1 runs/<timestamp>/crashes/crash_000001_<signature>.bin
```

If the target was built with sanitizers, the sanitizer report should make the
root cause easier to inspect:

```bash
clang -g -O1 -fsanitize=address,undefined target/target1.c -o target/target1_asan
./target/target1_asan runs/<timestamp>/crashes/crash_000001_<signature>.bin
```

## Feedback Modes

ToyFuzzer does not yet collect real edge coverage. Instead, it provides three
lightweight feedback modes:

- `status`: keep behavior features based on exit status and timeout status
- `output`: also hash stdout and stderr prefixes
- `trace`: also parse output lines beginning with `TRACE:`, `FEATURE:`, or `COV:`

The `trace` mode is useful for toy targets that print coarse-grained milestones:

```c
puts("TRACE:parsed_header");
puts("TRACE:validated_magic");
```

This gives a simple bridge toward coverage-guided fuzzing without adding a
compiler instrumentation pipeline yet.

## Research Directions

Good first experiments:

- Compare `--schedule uniform` and `--schedule rare`
- Compare runs with and without dictionary tokens
- Measure time-to-first-crash over many fixed random seeds
- Compare feedback modes: `status`, `output`, and `trace`
- Evaluate crash minimization overhead and resulting input size
- Plot corpus size, feature count, and unique crash count from `stats.jsonl`

Natural next implementation steps:

- Add real coverage feedback with SanitizerCoverage, gcov, or LLVM profiling
- Add a persistent mode to reduce process startup overhead
- Add structured mutations for known formats
- Add crash bucketing based on sanitizer stack traces
- Add experiment scripts for repeated trials and statistical summaries

## Safety Notes

Fuzzing executes target programs many times with malformed inputs. Run targets in
an isolated directory or sandbox when testing untrusted software. Avoid fuzzing
programs that may modify important files, use the network, or execute external
commands unless those effects are controlled.
