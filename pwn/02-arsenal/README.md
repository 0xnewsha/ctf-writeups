# Arsenal

## Overview

This challenge contains a stack-based buffer overflow in `vuln()`, where 512 bytes are read into a 64-byte buffer.

The exploit uses a two-stage ROP chain:

1. Call `read(0, armory, 8)` to write `/bin/sh` into writable memory.
2. Call `execve(armory, 0, 0)` using a direct system call.


## Security protections

- Partial RELRO
- NX enabled
- No PIE
- Canary support detected globally, but no canary check is present in `vuln()`

## Vulnerability

```c
char buf[64];
read(STDIN_FILENO, buf, 512);
```

The saved return address is reached after 72 bytes.

## Exploitation strategy

### Stage 1

```text
read(0, armory, 8)
```

Register values:

```text
RAX = 0
RDI = 0
RSI = armory
RDX = 8
```

The exploit then sends `/bin/sh\x00`.

### Stage 2

```text
execve(armory, NULL, NULL)
```

Register values:

```text
RAX = 59
RDI = armory
RSI = 0
RDX = 0
```

## Techniques demonstrated

- Stack-based buffer overflow
- Return-oriented programming
- Direct Linux system calls
- Multi-stage exploitation
- pwntools

## Files

- `main.c` — provided challenge source
- `arsenal` — challenge binary
- `solve.py` — exploit script developed by me

