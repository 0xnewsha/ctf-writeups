# Space Station

## Overview

This challenge combines a format-string vulnerability with a stack-based buffer overflow.

The format string is used to leak the stack canary and a runtime address from the PIE executable. These values allow the exploit to preserve the canary, calculate the binary base address, and redirect execution to the `win()` function.

> The vulnerable source code and binary were provided during the Offensive Security laboratory.  
> The analysis, write-up, and exploit script are my own work.

## Security protections

- Full RELRO
- Stack canary enabled
- NX enabled
- PIE enabled

## Vulnerabilities

- Uncontrolled format string
- Stack-based buffer overflow

## Exploitation strategy

1. Use positional format specifiers to inspect values on the stack.
2. Identify the stack-canary index.
3. Identify a leaked runtime address of `main`.
4. Leak both values in one request.
5. Calculate the PIE base:

   ```python
   elf.address = main_leak - elf.sym.main
   ```

6. Calculate the runtime addresses of the required gadget and `win()`.
7. Build the overflow payload while preserving the stack canary.
8. Overwrite the saved return address and redirect execution to `win()`.

## Important implementation detail

After setting the PIE base, pwntools automatically rebases ELF symbols:

```python
win = elf.sym.win
```

A raw gadget offset must be rebased manually:

```python
ret = elf.address + RET_OFF
```

## Techniques demonstrated

- Format-string information disclosure
- Stack-canary bypass
- PIE base calculation
- Stack-based buffer overflow
- Return-address control
- Exploit development with pwntools

## Files

- `main.c` — vulnerable challenge source provided during the laboratory
- `space_station` — original challenge binary
- `solve.py` — exploit script developed by me

This write-up is published for educational and portfolio purposes. The flag and active challenge endpoint have been removed.
