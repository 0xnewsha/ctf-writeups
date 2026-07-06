# AquaBank Vault

## Overview

This challenge combines a stack-memory disclosure with a stack-based buffer overflow.

The receipt function exposes additional stack data, including a stack canary and a libc address. These leaks are used to calculate the libc base and build a ret2libc chain that executes `system("/bin/sh")`.

> The challenge source and binary were provided during the Offensive Security laboratory.  
> The analysis and exploit scripts are my own work.

## Vulnerabilities

- Stack-memory disclosure
- Stack-based buffer overflow

## Exploitation strategy

1. Trigger the receipt leak.
2. Inspect the output as 8-byte values.
3. Extract the stack canary from bytes `72:80`.
4. Extract a libc pointer from bytes `152:160`.
5. Calculate the libc base:

   ```python
   libc.address = libc_leak - 0x2A1CA
   ```

6. Resolve `system`, `/bin/sh`, and the required ROP gadgets.
7. Preserve the canary and execute a ret2libc chain.

## Offset analysis

`calculation.py` is a local helper that:

- searches the leaked stack data for possible canaries;
- reads `/proc/<pid>/maps`;
- identifies addresses inside libc;
- calculates the corresponding libc offset;
- checks the address with GDB `info symbol`.

It is used locally to discover the fixed values required by the final exploit.

## Techniques demonstrated

- Stack-canary identification and bypass
- Memory-leak analysis
- Libc base calculation
- Process memory-map analysis
- ROP and ret2libc
- pwntools and GDB

## Files

- `main.c` — provided vulnerable source
- `aquabank-vault` — challenge binary
- `libc.so.6` — provided libc version
- `calculation.py` — offset-analysis helper
- `solve.py` — final exploit

Flags and active challenge endpoints have been removed.