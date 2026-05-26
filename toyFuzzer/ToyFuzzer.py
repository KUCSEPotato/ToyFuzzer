# toy_fuzzer.py
#
# Usage examples:
#
# 1. 기본 실행
#    python3 toy_fuzzer.py
#
# 2. seed 디렉터리를 지정해서 실행
#    python3 toy_fuzzer.py --seed-dir seeds
#
# 3. 타깃 실행 파일을 지정해서 실행
#    python3 toy_fuzzer.py --target ./target
#
# 4. 반복 횟수를 지정해서 실행
#    python3 toy_fuzzer.py --target ./target --seed-dir seeds --iterations 10000
#
# 5. 예시 target.c 컴파일 후 실행
#    clang -g -O1 -fsanitize=address,undefined target.c -o target
#    mkdir -p seeds
#    printf "FUZZ" > seeds/seed1
#    printf "CRASH" > seeds/seed2
#    python3 toy_fuzzer.py --target ./target --seed-dir seeds --iterations 10000

import os
import argparse
import random
import subprocess
import tempfile
from pathlib import Path


# 기본 타깃 실행 파일 경로
DEFAULT_TARGET = "./target"

# 기본 크래시 저장 디렉터리
CRASH_DIR = Path("crashes")
CRASH_DIR.mkdir(exist_ok=True)

DEFAULT_SEED_CORPUS = [
    b"",
    b"hello",
    b"FUZZ",
    b"CRASH",
    b"FUZZ_CRASH",
]

interesting_tokens = [
    b"FUZZ",
    b"CRASH",
    b"\x00",
    b"\xff",
    b"A" * 100,
]


def load_seed_corpus(seed_dir: Path) -> list[bytes]:
    """시드 디렉터리에서 파일을 읽어 바이트 코퍼스로 만든다."""
    corpus = []

    if seed_dir.exists():
        for path in sorted(seed_dir.iterdir()):
            if path.is_file():
                corpus.append(path.read_bytes())

    return corpus


def mutate(data: bytes) -> bytes:
    """
    입력 바이트를 받아서 변형한 바이트를 반환한다.
    """
    data = bytearray(data)

    choice = random.choice(["flip", "insert", "delete", "token"])

    if choice == "flip" and data:
        idx = random.randrange(len(data))
        data[idx] ^= 1 << random.randrange(8)

    elif choice == "insert":
        idx = random.randrange(len(data) + 1)
        data.insert(idx, random.randrange(256))

    elif choice == "delete" and data:
        idx = random.randrange(len(data))
        del data[idx]

    elif choice == "token":
        idx = random.randrange(len(data) + 1)
        token = random.choice(interesting_tokens)
        data[idx:idx] = token

    return bytes(data)


def run_target(target: str, inp: bytes):
    """
    입력을 임시 파일에 쓰고 타깃 프로그램을 실행한 뒤 결과를 반환한다.

    반환값:
        (returncode, stdout_bytes, stderr_bytes)

    타임아웃 발생 시 returncode 자리에 문자열 "TIMEOUT"을 넣는다.
    """
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(inp)
        filename = f.name

    try:
        result = subprocess.run(
            [target, filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1,
        )
        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        return "TIMEOUT", b"", b""

    finally:
        os.unlink(filename)


def main():
    parser = argparse.ArgumentParser(description="Tiny mutation-based fuzzer")

    parser.add_argument(
        "--seed-dir",
        type=Path,
        default=Path("seeds"),
        help="seed files directory",
    )

    parser.add_argument(
        "--target",
        type=str,
        default=DEFAULT_TARGET,
        help="target executable path",
    )

    parser.add_argument(
        "--iterations",
        type=int,
        default=10000,
        help="number of fuzzing iterations",
    )

    args = parser.parse_args()

    corpus = load_seed_corpus(args.seed_dir)

    if not corpus:
        print("[*] no seed files found; using default seed corpus")
        corpus = DEFAULT_SEED_CORPUS[:]
    else:
        print(f"[*] loaded {len(corpus)} seed files from {args.seed_dir}")

    print(f"[*] target: {args.target}")
    print(f"[*] iterations: {args.iterations}")

    for i in range(args.iterations):
        parent = random.choice(corpus)
        inp = mutate(parent)

        code, out, err = run_target(args.target, inp)

        is_timeout = code == "TIMEOUT"
        has_sanitizer_error = b"AddressSanitizer" in err or b"UndefinedBehaviorSanitizer" in err
        has_nonzero_exit = isinstance(code, int) and code != 0

        if is_timeout or has_sanitizer_error or has_nonzero_exit:
            crash_path = CRASH_DIR / f"crash_{i}.bin"
            crash_path.write_bytes(inp)

            print(f"[!] crash found: {crash_path}")
            print(f"    exit status: {code}")

            if err:
                print(err.decode(errors="ignore")[:500])

        if i % 1000 == 0:
            print(f"iteration={i}, corpus_size={len(corpus)}")


if __name__ == "__main__":
    main()