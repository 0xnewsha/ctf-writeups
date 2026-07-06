# Space Station

## Overview

This challenge combines a format-string vulnerability with a stack-based buffer overflow.

The format string is used to leak the stack canary and a runtime address from the PIE executable. These values allow the exploit to preserve the canary, calculate the binary base address, and redirect execution to the `win()` function.

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
3. Identify a leaked runtime address associated with `main`.
4. Leak both values in one request.
5. Calculate the PIE base:

   ```python
   elf.address = main_leak - elf.sym.main
