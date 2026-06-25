# ToyFuzzer

Small mutation-based fuzzer for learning, experiments, and research prototyping.

This README is placed inside `toyFuzzer/` so it is visible when this directory is
opened directly in an editor. The repository root also has a broader README.

## What It Does

- Loads seed inputs from `seeds/`
- Loads optional dictionary tokens from `dictionary/`
- Generates mutated byte inputs
- Executes a target program with each generated input
- Detects crashes, sanitizer failures, and hangs
- Saves unique crashes and hangs
- Keeps a growing corpus of interesting inputs
- Records run configuration and statistics
- Optionally minimizes crashing inputs

## Quick Start

```bash
clang -g -O0 target/target1.c -o target/target1
mkdir -p seeds dictionary
printf "A" > seeds/seed1.txt
printf "FUZZ\nCRASH\nFUZZ_CRASH\n" > dictionary/target1.dict
python3 toy_fuzzer.py --iterations 1000 --random-seed 1 --minimize-crashes
```

The demo target crashes when the generated input contains both `FUZZ` and
`CRASH`.

## Basic Usage

```bash
python3 toy_fuzzer.py
```

Defaults:

- Target: `./target/target1`
- Seeds: `seeds/`
- Dictionary: `dictionary/`
- Output: `runs/`
- Iterations: `10000`

Use a fixed seed for reproducible experiments:

```bash
python3 toy_fuzzer.py --iterations 10000 --random-seed 1337
```

Use a target command template:

```bash
python3 toy_fuzzer.py --target "./target/target1 @@"
```

`@@` is replaced with the generated input file path. If `@@` is omitted, the
input path is appended as the last argument.

## Useful Options

```text
--target CMD              Target executable or command template
--seed-dir DIR            Seed corpus directory
--dict-dir DIR            Dictionary directory
--iterations N            Maximum generated inputs
--duration SEC            Wall-clock time limit
--timeout SEC             Per-execution timeout
--random-seed N           Reproducible PRNG seed
--max-input-len N         Maximum generated input size
--schedule rare|uniform   Parent corpus selection strategy
--feedback MODE           status, output, or trace
--minimize-crashes        Shrink unique crashing inputs
--save-duplicates         Save duplicate crash/hang signatures too
```

Full help:

```bash
python3 toy_fuzzer.py --help
```

## Output Layout

Each run creates a timestamped directory under `runs/`:

```text
runs/<timestamp>/
  config.json
  summary.json
  stats.jsonl
  crashes/
  hangs/
  corpus/
    initial_corpus.txt
    final_corpus.txt
    queue/
```

## Research Ideas

- Compare `--schedule uniform` and `--schedule rare`
- Compare dictionary vs no-dictionary runs
- Measure time-to-first-crash over many random seeds
- Compare `status`, `output`, and `trace` feedback modes
- Measure minimization overhead and minimized crash size
- Add real coverage feedback with SanitizerCoverage, gcov, or LLVM profiling
