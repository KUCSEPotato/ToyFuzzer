# Mini Fuzzer: A Simple Fuzzer for Study and Testing

- This project implements a simple mutation-based fuzzer.
- It starts from seed inputs.
- It mutates inputs using byte-level mutation strategies.
- It executes the target program with each generated input.
- It detects crashes using return codes and sanitizer outputs.
- It saves crashing inputs for later analysis.
- Later, it can be extended with coverage feedback.

## Fuzzing Overview

Fuzzing is an automated software testing technique that finds bugs by repeatedly running a program with many generated or mutated inputs.

Instead of manually writing test cases one by one, a fuzzer automatically creates inputs, executes the target program, observes its behavior, and reports abnormal results such as crashes, hangs, or unexpected outputs.

## Basic Fuzzing Process

The basic fuzzing workflow can be summarized as follows:

```text
Seed Inputs
    ↓
Input Generation / Mutation
    ↓
Program Execution
    ↓
Behavior Monitoring
    ↓
Interesting Input Selection
    ↓
Crash Analysis and Bug Fixing
```

### 1. Select a Target Program

The first step is to choose the program or function to test.

A fuzzing target is usually a component that receives external input, such as:

- File parsers
- Network protocols
- Command-line tools
- Compilers
- Interpreters
- Image, PDF, or media processors
- API input handlers

For example, if a program reads a text file and processes its content, the fuzzer can repeatedly generate different text files and feed them to the program.

### 2. Prepare Seed Inputs

Seed inputs are initial example inputs given to the fuzzer.

They do not need to be perfect, but they should be valid enough to help the fuzzer start exploring meaningful program behavior.

For example:

- A small valid PNG file for an image parser
- A simple JSON file for a JSON parser
- A short text file for a command-line text processor
- A basic HTTP request for a web server

Good seed inputs help the fuzzer reach deeper parts of the program.

### 3. Generate or Mutate Inputs

The fuzzer creates new test inputs from the seed inputs.

There are two common approaches:

- Generation-based fuzzing
  - The fuzzer creates inputs from a predefined format or grammar.
  - This is useful when the input structure is well known.

- Mutation-based fuzzing
  - The fuzzer modifies existing seed inputs.
  - Typical mutations include flipping bits, inserting bytes, deleting bytes, duplicating chunks, or replacing values.

Example mutations:

```text
Original input:
hello world

Mutated inputs:
hello wor1d
hello world!!!
hllo world
hello\x00world
```

The goal is to create many diverse inputs that may trigger unexpected behavior.

### 4. Execute the Target Program

The generated input is given to the target program.

For each input, the fuzzer runs the program and checks whether the program behaves normally.

A simple example:

```text
./target_program generated_input.txt
```

This step is repeated many times, often thousands or millions of times.

### 5. Monitor Program Behavior

While the target program is running, the fuzzer observes its behavior.

The fuzzer usually checks for:

- Crash
  - The program terminates abnormally.
  - Examples: segmentation fault, abort, illegal instruction.

- Hang or timeout
  - The program does not finish within a reasonable time.
  - This may indicate an infinite loop or severe performance bug.

- Memory error
  - The program accesses memory incorrectly.
  - Examples: buffer overflow, use-after-free, double free.

- Unexpected output
  - The program produces an incorrect or inconsistent result.

In coverage-guided fuzzing, the fuzzer also observes which parts of the program were executed.

### 6. Keep Interesting Inputs

Not all generated inputs are useful.

A fuzzer keeps inputs that reveal new behavior.

An input is usually considered interesting if it:

- Executes a new branch
- Reaches a new function
- Increases code coverage
- Triggers a crash
- Causes a timeout
- Produces unusual behavior

These interesting inputs are saved and reused to generate more inputs.

This feedback loop allows the fuzzer to gradually explore more of the program.

### 7. Save Crashes

When the target program crashes, the fuzzer saves the input that caused the crash.

A saved crashing input is important because it allows developers to reproduce the bug.

For example:

```text
crashes/id_000001
crashes/id_000002
crashes/id_000003
```

Each crash input should be tested again to confirm that the crash is reproducible.

### 8. Minimize the Crashing Input

A crashing input is often large and difficult to analyze.

Input minimization reduces the crashing input while preserving the same crash.

For example:

```text
Original crashing input:
AAAAAAAAAAAAAAAAAAAAAAA%p%p%p%pBBBBBBBBBBBBBBBB

Minimized crashing input:
%p%p%p%p
```

A smaller input makes debugging easier.

### 9. Analyze the Root Cause

After reproducing the crash, developers analyze why the program failed.

Common root causes include:

- Buffer overflow
- Out-of-bounds read or write
- Null pointer dereference
- Use-after-free
- Integer overflow
- Assertion failure
- Infinite loop
- Unhandled exception

Debuggers and sanitizers are often used in this step.

Examples:

- gdb
- lldb
- AddressSanitizer
- UndefinedBehaviorSanitizer
- Valgrind

### 10. Fix the Bug and Add Regression Tests

After identifying the cause, the bug should be fixed.

The crashing input should then be added as a regression test.

This ensures that the same bug does not appear again in the future.

A typical regression test checks that:

- The program no longer crashes
- The input is handled safely
- The expected behavior is preserved

## Summary

The basic fuzzing loop is:

1. Prepare seed inputs.
2. Generate or mutate new inputs.
3. Run the target program.
4. Monitor crashes, hangs, and coverage.
5. Save interesting inputs.
6. Reproduce and minimize crashes.
7. Analyze the root cause.
8. Fix the bug and add regression tests.

Fuzzing is powerful because it automates repetitive testing and can discover edge cases that humans may not think of manually.