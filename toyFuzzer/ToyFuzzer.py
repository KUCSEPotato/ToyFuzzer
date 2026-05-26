# toy_fuzzer.py
import os
import random
import subprocess
import tempfile
from pathlib import Path

# 퍼저가 실행할 타깃 실행 파일 경로 (로컬 또는 절대 경로)
TARGET = "./target"

# 크래시를 저장할 디렉터리 객체 생성
CRASH_DIR = Path("crashes")
# exist_ok=True: 이미 디렉터리가 있어도 예외를 내지 않음
CRASH_DIR.mkdir(exist_ok=True)

# 초기 시드(시작 입력) 목록 — 바이트 문자열 목록
seed_corpus = [
    b"",            # 빈 입력
    b"hello",       # 일반 텍스트
    b"FUZZ",        # 토큰 포함
    b"CRASH",
    b"FUZZ_CRASH",
]

# 퍼징에 자주 쓰이는 흥미로운 토큰들
interesting_tokens = [
    b"FUZZ",
    b"CRASH",
    b"\x00",       # 널 바이트
    b"\xff",       # 0xFF 바이트
    b"A" * 100,     # 긴 반복 바이트
]


def mutate(data: bytes) -> bytes:
    """
    입력 바이트를 받아서 변형한 바이트를 반환한다.

    타입 힌트: 입력은 `bytes`, 반환도 `bytes`이다.
    내부적으로는 `bytearray`로 바꿔서 가변 수정한다.
    """
    # 불변인 `bytes`를 변경하려면 가변인 `bytearray`로 변환
    data = bytearray(data)

    # 변형 전략을 무작위로 선택
    choice = random.choice(["flip", "insert", "delete", "token"])

    # 비트 뒤집기: 임의 위치의 비트 하나를 토글
    if choice == "flip" and data:
        # random.randrange(len(data))는 0..len(data)-1 범위의 인덱스
        idx = random.randrange(len(data))
        # 1 << random.randrange(8)은 0~7 비트 중 하나를 선택
        data[idx] ^= 1 << random.randrange(8)

    # 삽입: 임의 위치에 임의 바이트 삽입
    elif choice == "insert":
        idx = random.randrange(len(data) + 1)  # 끝도 포함
        data.insert(idx, random.randrange(256))  # 0..255

    # 삭제: 임의 위치의 바이트 제거
    elif choice == "delete" and data:
        idx = random.randrange(len(data))
        del data[idx]

    # 토큰 삽입: 자주 쓰는 토큰을 임의 위치에 삽입
    elif choice == "token":
        idx = random.randrange(len(data) + 1)
        token = random.choice(interesting_tokens)
        # 슬라이스 할당으로 토큰을 삽입
        data[idx:idx] = token

    # 다시 불변인 bytes로 반환
    return bytes(data)


def run_target(inp: bytes):
    """
    입력을 임시 파일에 쓰고 타깃 프로그램을 실행한 뒤 결과를 반환한다.

    반환값: (returncode, stdout_bytes, stderr_bytes)
    타임아웃 발생 시 문자열 "TIMEOUT"을 returncode로 사용한다.
    """
    # NamedTemporaryFile를 delete=False로 만든 이유:
    # 일부 실행기는 파일 경로를 필요로 하고, 윈도우 같은 환경에서
    # 열린 파일을 다른 프로세스가 열 수 없기 때문에 이렇게 만든다.
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(inp)
        filename = f.name

    try:
        # subprocess.run: 외부 프로그램 실행 (동기)
        # stdout/stderr는 PIPE로 받아서 바이트로 획득
        result = subprocess.run(
            [TARGET, filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=1,
        )
        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        # 타깃이 지정한 시간 안에 응답하지 않으면 TIMEOUT으로 처리
        return "TIMEOUT", b"", b""

    finally:
        # 임시 파일은 항상 삭제
        os.unlink(filename)


def main():
    # corpus는 시드 집합에서 시작한다. 이후에는 새 입력을 추가할 수 있음
    corpus = seed_corpus[:]

    # 단순 반복 퍼징: 10000번 변형 시도
    for i in range(10000):
        # 부모 입력을 무작위로 선택
        parent = random.choice(corpus)
        inp = mutate(parent)

        # 타깃 실행
        code, out, err = run_target(inp)

        # 비정상 종료(0이 아닌 코드), ASAN 출력 포함, 또는 타임아웃을 크래시로 간주
        if code != 0 or b"AddressSanitizer" in err or code == "TIMEOUT":
            crash_path = CRASH_DIR / f"crash_{i}.bin"
            # 크래시 입력을 파일로 저장
            crash_path.write_bytes(inp)
            print(f"[!] crash found: {crash_path}")
            # stderr를 디코드하되 오류는 무시
            print(err.decode(errors="ignore")[:500])

        # 진행 상황을 주기적으로 출력
        if i % 1000 == 0:
            print(f"iteration={i}, corpus_size={len(corpus)}")


if __name__ == "__main__":
    main()