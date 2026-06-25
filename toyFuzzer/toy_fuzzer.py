# toy_fuzzer.py
#
# Usage examples:
#
# 1. 기본 실행
#    기본으로 ./target/target1, seeds/, dictionary/를 사용한다.
#    python3 toy_fuzzer.py
#
# 2. 반복 횟수와 random seed를 고정해서 재현 가능한 실험 실행
#    python3 toy_fuzzer.py --iterations 10000 --random-seed 1337
#
# 3. dictionary를 사용해서 의미 있는 토큰을 mutation에 섞기
#    mkdir -p dictionary
#    printf "FUZZ\nCRASH\nFUZZ_CRASH\n" > dictionary/target1.dict
#    python3 toy_fuzzer.py --dict-dir dictionary
#
# 4. target command 안에서 @@를 입력 파일 경로 자리로 사용
#    python3 toy_fuzzer.py --target "./target/target1 @@"
#
# 5. crash 입력을 자동으로 줄여서 저장
#    python3 toy_fuzzer.py --minimize-crashes
#
# 6. 예시 target1.c 컴파일 후 실행
#    clang -g -O0 target/target1.c -o target/target1
#    mkdir -p seeds
#    printf "A" > seeds/seed1.txt
#    python3 toy_fuzzer.py --target ./target/target1 --seed-dir seeds --iterations 10

import argparse
import ast
import hashlib
import json
import os
import random
import shlex
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


DEFAULT_TARGET = "./target/target1"

INTERESTING_BYTES = [
    0x00,
    0x01,
    0x02,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0D,
    0x1F,
    0x20,
    0x22,
    0x27,
    0x2F,
    0x3A,
    0x40,
    0x7F,
    0x80,
    0xFE,
    0xFF,
]


@dataclass
class RunResult:
    code: object
    stdout: bytes
    stderr: bytes
    elapsed: float
    timed_out: bool = False


@dataclass
class CorpusEntry:
    data: bytes
    features: tuple[str, ...]
    depth: int = 0
    executions: int = 0
    finds: int = 0
    source: str = "generated"


@dataclass
class FuzzStats:
    start_time: float = field(default_factory=time.time)
    executions: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    hangs: int = 0
    unique_hangs: int = 0
    corpus_size: int = 0
    feature_count: int = 0
    minimization_executions: int = 0
    last_new_feature_at: Optional[int] = None

    def elapsed(self) -> float:
        return max(time.time() - self.start_time, 0.000001)

    def execs_per_second(self) -> float:
        return self.executions / self.elapsed()


def stable_digest(data: bytes, size: int = 12) -> str:
    return hashlib.sha256(data).hexdigest()[:size]


def load_seed_corpus(seed_dir: Path, max_input_len: int) -> list[bytes]:
    """seed 디렉터리의 파일들을 읽어 초기 corpus로 만든다."""
    corpus = []

    if not seed_dir.exists():
        return corpus

    for path in sorted(seed_dir.rglob("*")):
        if not path.is_file():
            continue

        data = path.read_bytes()
        if max_input_len > 0 and len(data) > max_input_len:
            data = data[:max_input_len]
        corpus.append(data)

    return corpus


def parse_dictionary_line(line: bytes) -> Optional[bytes]:
    """
    dictionary 한 줄을 token bytes로 변환한다.

    다음 두 형식을 모두 지원한다.
      FUZZ
      keyword="FUZZ"
    """
    line = line.strip()
    if not line or line.startswith(b"#"):
        return None

    if b"=" in line:
        _, rhs = line.split(b"=", 1)
        rhs = rhs.strip()
        if rhs.startswith(b'"'):
            line = rhs

    if line.startswith(b'"') and line.endswith(b'"'):
        text = line.decode("utf-8", errors="surrogateescape")
        try:
            token = ast.literal_eval("b" + text)
        except (SyntaxError, ValueError):
            token = line[1:-1]
        if isinstance(token, bytes):
            return token
        return None

    return line


def load_dictionary(dict_dir: Path) -> list[bytes]:
    """
    dictionary 디렉터리에서 mutation에 삽입할 토큰들을 읽는다.

    빈 줄과 '#'로 시작하는 줄은 무시한다. AFL 스타일의 name="value" 형식도
    최소한으로 지원해서 나중에 AFL dictionary와 비교 실험하기 쉽게 했다.
    """
    tokens = []
    seen = set()

    if not dict_dir.exists():
        return tokens

    for path in sorted(dict_dir.rglob("*")):
        if not path.is_file():
            continue

        for line in path.read_bytes().splitlines():
            token = parse_dictionary_line(line)
            if token and token not in seen:
                seen.add(token)
                tokens.append(token)

    return tokens


def clamp_input(data: bytes, max_input_len: int, rng: random.Random) -> bytes:
    if max_input_len <= 0 or len(data) <= max_input_len:
        return data

    if max_input_len == 1:
        return data[:1]

    start = rng.randrange(0, len(data) - max_input_len + 1)
    return data[start : start + max_input_len]


def random_chunk(rng: random.Random, max_size: int) -> bytes:
    size = rng.randint(1, max_size)
    return bytes(rng.randrange(256) for _ in range(size))


def mutate_once(
    data: bytes,
    dictionary: list[bytes],
    corpus: list[CorpusEntry],
    max_input_len: int,
    rng: random.Random,
) -> bytes:
    """입력 바이트에 작은 변이 하나를 적용한다."""
    buf = bytearray(data)

    choices = [
        "flip_bit",
        "set_interesting_byte",
        "add_sub_byte",
        "insert_bytes",
        "overwrite_bytes",
        "delete_range",
        "clone_range",
    ]
    if dictionary:
        choices.extend(["insert_token", "overwrite_token"])
    if len(corpus) > 1:
        choices.append("splice")

    choice = rng.choice(choices)

    if choice == "flip_bit" and buf:
        idx = rng.randrange(len(buf))
        buf[idx] ^= 1 << rng.randrange(8)

    elif choice == "set_interesting_byte" and buf:
        idx = rng.randrange(len(buf))
        buf[idx] = rng.choice(INTERESTING_BYTES)

    elif choice == "add_sub_byte" and buf:
        idx = rng.randrange(len(buf))
        delta = rng.choice([-16, -8, -4, -1, 1, 4, 8, 16])
        buf[idx] = (buf[idx] + delta) & 0xFF

    elif choice == "insert_bytes" and len(buf) < max_input_len:
        idx = rng.randrange(len(buf) + 1)
        buf[idx:idx] = random_chunk(rng, min(8, max_input_len - len(buf)))

    elif choice == "overwrite_bytes" and buf:
        idx = rng.randrange(len(buf))
        size = min(rng.randint(1, 8), len(buf) - idx)
        buf[idx : idx + size] = random_chunk(rng, size)

    elif choice == "delete_range" and buf:
        idx = rng.randrange(len(buf))
        size = rng.randint(1, min(16, len(buf) - idx))
        del buf[idx : idx + size]

    elif choice == "clone_range" and buf and len(buf) < max_input_len:
        src = rng.randrange(len(buf))
        size = rng.randint(1, min(16, len(buf) - src, max_input_len - len(buf)))
        dst = rng.randrange(len(buf) + 1)
        buf[dst:dst] = buf[src : src + size]

    elif choice == "insert_token" and len(buf) < max_input_len:
        token = rng.choice(dictionary)
        token = token[: max_input_len - len(buf)]
        idx = rng.randrange(len(buf) + 1)
        buf[idx:idx] = token

    elif choice == "overwrite_token" and buf:
        token = rng.choice(dictionary)
        idx = rng.randrange(len(buf))
        end = min(max_input_len, idx + len(token))
        buf[idx:end] = token[: end - idx]

    elif choice == "splice":
        other = rng.choice(corpus).data
        if other:
            left_cut = rng.randrange(len(buf) + 1)
            right_cut = rng.randrange(len(other) + 1)
            buf = bytearray(bytes(buf[:left_cut]) + other[right_cut:])

    return clamp_input(bytes(buf), max_input_len, rng)


def mutate(
    data: bytes,
    dictionary: list[bytes],
    corpus: list[CorpusEntry],
    min_mutations: int,
    max_mutations: int,
    max_input_len: int,
    rng: random.Random,
) -> bytes:
    """입력 바이트를 여러 번 변형한다."""
    mutation_count = rng.randint(min_mutations, max_mutations)

    for _ in range(mutation_count):
        data = mutate_once(data, dictionary, corpus, max_input_len, rng)

    return data


def build_target_command(target: str, input_path: str) -> list[str]:
    """
    target command를 argv list로 만든다.

    @@ placeholder가 있으면 그 자리에 입력 파일 경로를 넣고, 없으면 마지막 인자로
    입력 파일 경로를 붙인다.
    """
    argv = shlex.split(target)
    if not argv:
        raise ValueError("target command is empty")

    replaced = False
    command = []
    for part in argv:
        if "@@" in part:
            command.append(part.replace("@@", input_path))
            replaced = True
        else:
            command.append(part)

    if not replaced:
        command.append(input_path)

    return command


def run_target(target: str, inp: bytes, timeout: float) -> RunResult:
    """입력을 임시 파일에 쓰고 타깃 프로그램을 실행한 뒤 결과를 반환한다."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(inp)
        filename = f.name

    started = time.perf_counter()
    try:
        result = subprocess.run(
            build_target_command(target, filename),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - started
        return RunResult(result.returncode, result.stdout, result.stderr, elapsed)

    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - started
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        return RunResult("TIMEOUT", stdout, stderr, elapsed, timed_out=True)

    finally:
        os.unlink(filename)


def trace_features(output: bytes) -> list[str]:
    features = []

    for line in output.splitlines():
        line = line.strip()
        if line.startswith((b"TRACE:", b"FEATURE:", b"COV:")):
            features.append("trace:" + line.decode(errors="replace")[:120])

    return features


def behavior_features(result: RunResult, mode: str) -> tuple[str, ...]:
    """타깃 실행 결과를 corpus feedback으로 쓸 feature set으로 변환한다."""
    if result.timed_out:
        features = ["status:timeout"]
    else:
        features = [f"status:{result.code}"]

    combined_output = result.stdout + b"\n" + result.stderr

    if mode in {"output", "trace"}:
        if result.stdout:
            features.append("stdout:" + stable_digest(result.stdout[:4096]))
        if result.stderr:
            features.append("stderr:" + stable_digest(result.stderr[:4096]))

    if mode == "trace":
        features.extend(trace_features(combined_output))

    return tuple(sorted(set(features)))


def signal_name(code: object) -> str:
    if isinstance(code, int) and code < 0:
        signum = -code
        try:
            return signal.Signals(signum).name
        except ValueError:
            return f"SIGNAL_{signum}"
    return str(code)


def is_failure(result: RunResult, ignore_nonzero_exit: bool) -> bool:
    if result.timed_out:
        return False

    sanitizer_error = (
        b"AddressSanitizer" in result.stderr
        or b"UndefinedBehaviorSanitizer" in result.stderr
        or b"MemorySanitizer" in result.stderr
        or b"LeakSanitizer" in result.stderr
    )
    if sanitizer_error:
        return True

    if isinstance(result.code, int) and result.code < 0:
        return True

    if isinstance(result.code, int) and result.code != 0 and not ignore_nonzero_exit:
        return True

    return False


def failure_signature(kind: str, result: RunResult) -> str:
    material = b"\n".join(
        [
            kind.encode(),
            str(result.code).encode(),
            result.stderr[:4096],
            result.stdout[:1024],
        ]
    )
    return stable_digest(material, size=16)


def choose_parent(
    corpus: list[CorpusEntry],
    schedule: str,
    rng: random.Random,
) -> CorpusEntry:
    if schedule == "uniform" or len(corpus) == 1:
        return rng.choice(corpus)

    weights = []
    for entry in corpus:
        rarity_weight = 1.0 / ((entry.executions + 1) ** 0.5)
        size_weight = 1.0 / (1.0 + (len(entry.data) / 1024.0))
        discovery_bonus = 1.0 + min(entry.finds, 8) * 0.15
        weights.append(rarity_weight * size_weight * discovery_bonus)

    return rng.choices(corpus, weights=weights, k=1)[0]


def add_to_corpus(
    corpus: list[CorpusEntry],
    entry: CorpusEntry,
    max_corpus_size: int,
) -> bool:
    if max_corpus_size <= 0:
        return False

    if len(corpus) < max_corpus_size:
        corpus.append(entry)
        return True

    victim_idx = max(
        range(len(corpus)),
        key=lambda idx: (corpus[idx].executions, len(corpus[idx].data)),
    )
    corpus[victim_idx] = entry
    return True


def write_bytes_artifact(
    directory: Path,
    prefix: str,
    index: int,
    inp: bytes,
    result: RunResult,
    signature: str,
    features: tuple[str, ...],
) -> Path:
    path = directory / f"{prefix}_{index:06d}_{signature}.bin"
    path.write_bytes(inp)

    metadata = {
        "path": str(path),
        "size": len(inp),
        "sha256": hashlib.sha256(inp).hexdigest(),
        "exit_status": signal_name(result.code),
        "elapsed_seconds": result.elapsed,
        "features": list(features),
        "stdout_preview": result.stdout[:300].decode(errors="replace"),
        "stderr_preview": result.stderr[:300].decode(errors="replace"),
    }
    path.with_suffix(path.suffix + ".json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def write_corpus_entry(directory: Path, index: int, entry: CorpusEntry) -> Path:
    path = directory / f"id_{index:06d}_{stable_digest(entry.data)}.bin"
    path.write_bytes(entry.data)
    return path


def write_corpus_report(path: Path, corpus: list[CorpusEntry]) -> None:
    """
    corpus 내용을 사람이 읽기 쉬운 텍스트 파일로 저장한다.

    퍼저 입력은 임의의 bytes라 UTF-8 텍스트가 아닐 수 있다. 그래서 repr은 눈으로
    확인하는 용도, hex는 바이트 재현 용도로 함께 남긴다.
    """
    lines = [f"total_entries={len(corpus)}", ""]

    for idx, entry in enumerate(corpus):
        lines.append(
            f"[{idx:06d}] len={len(entry.data)} depth={entry.depth} "
            f"execs={entry.executions} finds={entry.finds} source={entry.source}"
        )
        lines.append(f"features={','.join(entry.features)}")
        lines.append(f"repr={entry.data!r}")
        lines.append(f"hex={entry.data.hex()}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def append_jsonl(path: Path, item: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(item, sort_keys=True) + "\n")


def stats_snapshot(stats: FuzzStats) -> dict:
    return {
        "elapsed_seconds": round(stats.elapsed(), 6),
        "executions": stats.executions,
        "execs_per_second": round(stats.execs_per_second(), 3),
        "corpus_size": stats.corpus_size,
        "feature_count": stats.feature_count,
        "minimization_executions": stats.minimization_executions,
        "crashes": stats.crashes,
        "unique_crashes": stats.unique_crashes,
        "hangs": stats.hangs,
        "unique_hangs": stats.unique_hangs,
        "last_new_feature_at": stats.last_new_feature_at,
    }


def minimize_failure(
    inp: bytes,
    target: str,
    timeout: float,
    ignore_nonzero_exit: bool,
    limit: int,
) -> tuple[bytes, int]:
    """
    매우 작은 delta-debugging식 crash minimizer.

    같은 종류의 crash인지까지 엄밀히 보지는 않고, 여전히 failure가 나는지만 본다.
    toy fuzzer에서는 이 정도만으로도 논문용 artifact를 읽기 쉽게 만드는 데 도움이 된다.
    """
    if limit <= 0:
        return inp, 0

    best = inp
    attempts = 0
    chunk = max(1, len(best) // 2)

    while chunk >= 1 and attempts < limit:
        changed = False
        idx = 0

        while idx < len(best) and attempts < limit:
            candidate = best[:idx] + best[idx + chunk :]
            attempts += 1
            result = run_target(target, candidate, timeout)

            if is_failure(result, ignore_nonzero_exit):
                best = candidate
                changed = True
            else:
                idx += chunk

        if not changed:
            chunk //= 2
        else:
            chunk = min(chunk, max(1, len(best)))

    return best, attempts


def create_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Tiny mutation-based fuzzer for experiments",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--seed-dir",
        type=Path,
        default=Path("seeds"),
        help="seed files directory",
    )
    parser.add_argument(
        "--dict-dir",
        type=Path,
        default=Path("dictionary"),
        help="dictionary files directory",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=DEFAULT_TARGET,
        help="target executable or command template; @@ is replaced with input path",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="maximum number of fuzzing iterations",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="maximum fuzzing time in seconds; 0 disables the time limit",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="per-execution timeout in seconds",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("runs"),
        help="directory to store fuzzing results",
    )
    parser.add_argument(
        "--max-corpus-size",
        type=int,
        default=1000,
        help="maximum number of inputs kept for future mutations",
    )
    parser.add_argument(
        "--keep-corpus-prob",
        type=float,
        default=0.02,
        help="probability of keeping a non-interesting input",
    )
    parser.add_argument(
        "--max-input-len",
        type=int,
        default=4096,
        help="maximum generated input length in bytes",
    )
    parser.add_argument(
        "--min-mutations",
        type=int,
        default=1,
        help="minimum stacked mutations per generated input",
    )
    parser.add_argument(
        "--max-mutations",
        type=int,
        default=16,
        help="maximum stacked mutations per generated input",
    )
    parser.add_argument(
        "--schedule",
        choices=["rare", "uniform"],
        default="rare",
        help="parent input selection strategy",
    )
    parser.add_argument(
        "--feedback",
        choices=["status", "output", "trace"],
        default="output",
        help="signal used to decide whether an input is interesting",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=None,
        help="PRNG seed for reproducible fuzzing",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=1000,
        help="print and record progress every N executions; 0 disables periodic progress",
    )
    parser.add_argument(
        "--ignore-nonzero-exit",
        action="store_true",
        help="do not classify ordinary non-zero exits as crashes",
    )
    parser.add_argument(
        "--save-duplicates",
        action="store_true",
        help="save duplicate crashes and hangs, not only unique signatures",
    )
    parser.add_argument(
        "--minimize-crashes",
        action="store_true",
        help="try to shrink unique crashing inputs before saving them",
    )
    parser.add_argument(
        "--minimize-limit",
        type=int,
        default=250,
        help="maximum target executions used per crash minimization",
    )

    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.iterations < 0:
        parser.error("--iterations must be non-negative")
    if args.duration < 0:
        parser.error("--duration must be non-negative")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.max_input_len <= 0:
        parser.error("--max-input-len must be positive")
    if args.min_mutations <= 0:
        parser.error("--min-mutations must be positive")
    if args.max_mutations < args.min_mutations:
        parser.error("--max-mutations must be greater than or equal to --min-mutations")
    if not 0.0 <= args.keep_corpus_prob <= 1.0:
        parser.error("--keep-corpus-prob must be between 0.0 and 1.0")


def main() -> int:
    parser = create_arg_parser()
    args = parser.parse_args()
    validate_args(parser, args)

    rng = random.Random(args.random_seed)
    seed_inputs = load_seed_corpus(args.seed_dir, args.max_input_len)

    if not seed_inputs:
        print(f"[!] no seed files found in: {args.seed_dir}")
        print("[!] add at least one seed file before fuzzing")
        return 1

    dictionary = load_dictionary(args.dict_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    run_dir = args.out_dir / timestamp
    crash_dir = run_dir / "crashes"
    hang_dir = run_dir / "hangs"
    corpus_dir = run_dir / "corpus"
    queue_dir = corpus_dir / "queue"

    for directory in [crash_dir, hang_dir, queue_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    stats_path = run_dir / "stats.jsonl"
    summary_path = run_dir / "summary.json"
    config_path = run_dir / "config.json"
    initial_corpus_path = corpus_dir / "initial_corpus.txt"
    final_corpus_path = corpus_dir / "final_corpus.txt"

    config = vars(args).copy()
    config["seed_dir"] = str(args.seed_dir)
    config["dict_dir"] = str(args.dict_dir)
    config["out_dir"] = str(args.out_dir)
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")

    corpus = [
        CorpusEntry(data=data, features=("seed",), depth=0, source="seed")
        for data in seed_inputs
    ]
    all_features = set()
    seen_crashes = set()
    seen_hangs = set()
    stats = FuzzStats(corpus_size=len(corpus), feature_count=0)

    for idx, entry in enumerate(corpus):
        write_corpus_entry(queue_dir, idx, entry)
    write_corpus_report(initial_corpus_path, corpus)

    print(f"[*] output directory: {run_dir}")
    print(f"[*] crash directory: {crash_dir}")
    print(f"[*] hang directory: {hang_dir}")
    print(f"[*] corpus directory: {corpus_dir}")
    print(f"[*] loaded {len(corpus)} seed files from {args.seed_dir}")
    print(f"[*] loaded {len(dictionary)} dictionary tokens from {args.dict_dir}")
    print(f"[*] target: {args.target}")
    print(f"[*] iterations: {args.iterations}")
    print(f"[*] timeout: {args.timeout}s")
    print(f"[*] random seed: {args.random_seed}")
    print(f"[*] feedback: {args.feedback}")
    print(f"[*] schedule: {args.schedule}")

    deadline = time.time() + args.duration if args.duration > 0 else None
    queue_index = len(corpus)

    for iteration in range(args.iterations):
        if deadline is not None and time.time() >= deadline:
            print("[*] duration limit reached")
            break

        parent = choose_parent(corpus, args.schedule, rng)
        parent.executions += 1

        inp = mutate(
            parent.data,
            dictionary,
            corpus,
            args.min_mutations,
            args.max_mutations,
            args.max_input_len,
            rng,
        )
        result = run_target(args.target, inp, args.timeout)
        stats.executions += 1

        features = behavior_features(result, args.feedback)
        new_features = [feature for feature in features if feature not in all_features]
        if new_features:
            all_features.update(new_features)
            stats.feature_count = len(all_features)
            stats.last_new_feature_at = iteration

        if result.timed_out:
            stats.hangs += 1
            signature = failure_signature("hang", result)
            is_unique = signature not in seen_hangs

            if is_unique:
                seen_hangs.add(signature)
                stats.unique_hangs += 1

            if is_unique or args.save_duplicates:
                path = write_bytes_artifact(
                    hang_dir,
                    "hang",
                    stats.unique_hangs if is_unique else stats.hangs,
                    inp,
                    result,
                    signature,
                    features,
                )
                print(f"[!] hang found: {path}")

        elif is_failure(result, args.ignore_nonzero_exit):
            stats.crashes += 1
            signature = failure_signature("crash", result)
            is_unique = signature not in seen_crashes

            if is_unique:
                seen_crashes.add(signature)
                stats.unique_crashes += 1

            if is_unique or args.save_duplicates:
                artifact_input = inp
                artifact_result = result
                minimization_execs = 0
                if args.minimize_crashes and is_unique:
                    artifact_input, minimization_execs = minimize_failure(
                        inp,
                        args.target,
                        args.timeout,
                        args.ignore_nonzero_exit,
                        args.minimize_limit,
                    )
                    stats.minimization_executions += minimization_execs
                    artifact_result = run_target(
                        args.target,
                        artifact_input,
                        args.timeout,
                    )
                    stats.minimization_executions += 1

                path = write_bytes_artifact(
                    crash_dir,
                    "crash",
                    stats.unique_crashes if is_unique else stats.crashes,
                    artifact_input,
                    artifact_result,
                    signature,
                    behavior_features(artifact_result, args.feedback),
                )
                print(
                    f"[!] crash found: {path} "
                    f"status={signal_name(result.code)} "
                    f"size={len(artifact_input)}"
                )
                if minimization_execs:
                    print(f"    minimized with {minimization_execs} extra executions")
                if result.stderr:
                    print(result.stderr.decode(errors="ignore")[:500])

        else:
            keep_for_feedback = bool(new_features)
            keep_randomly = rng.random() < args.keep_corpus_prob

            if keep_for_feedback or keep_randomly:
                entry = CorpusEntry(
                    data=inp,
                    features=features,
                    depth=parent.depth + 1,
                    source="feedback" if keep_for_feedback else "random",
                )
                if add_to_corpus(corpus, entry, args.max_corpus_size):
                    if keep_for_feedback:
                        parent.finds += 1
                    write_corpus_entry(queue_dir, queue_index, entry)
                    queue_index += 1

        stats.corpus_size = len(corpus)

        if args.progress_every and stats.executions % args.progress_every == 0:
            snapshot = stats_snapshot(stats)
            append_jsonl(stats_path, snapshot)
            print(
                "execs={executions} eps={execs_per_second} "
                "corpus={corpus_size} features={feature_count} "
                "crashes={crashes}/{unique_crashes} hangs={hangs}/{unique_hangs}".format(
                    **snapshot
                )
            )

    print("[*] fuzzing finished")
    write_corpus_report(final_corpus_path, corpus)

    summary = stats_snapshot(stats)
    summary["run_dir"] = str(run_dir)
    summary["initial_corpus"] = str(initial_corpus_path)
    summary["final_corpus"] = str(final_corpus_path)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    append_jsonl(stats_path, {"final": True, **summary})

    print(f"[*] total executions: {stats.executions}")
    print(f"[*] execs/sec: {stats.execs_per_second():.2f}")
    print(f"[*] total crashes: {stats.crashes} ({stats.unique_crashes} unique)")
    print(f"[*] total hangs: {stats.hangs} ({stats.unique_hangs} unique)")
    print(f"[*] discovered features: {stats.feature_count}")
    print(f"[*] initial corpus: {initial_corpus_path}")
    print(f"[*] final corpus: {final_corpus_path}")
    print(f"[*] stats: {stats_path}")
    print(f"[*] summary: {summary_path}")
    print(f"[*] results saved in: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
