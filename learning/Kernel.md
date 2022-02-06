## Kernel

### Reference



[yuawn 線上講解 2019_TokyoWesterns_CTF_Gnote](https://fb.watch/3ErU8pX3Jy/)

- [yuawn kernel-exploit 教學 repo](https://github.com/yuawn/kernel-exploitation)
- Kernel pwn CTF 入門系列文章
  - https://www.anquanke.com/post/id/255882
  - https://www.anquanke.com/post/id/255883
  - https://www.anquanke.com/post/id/25588ˋ
- Learning Linux Kernel Exploitation 系列文章
  - https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/
  - https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/
  - https://lkmidas.github.io/posts/20210205-linux-kernel-pwn-part-3/




[bsauce 一系列的文章](https://github.com/bsauce/kernel-security-learning)

## kernel 環境

先去 [linux kernel 首頁](https://www.kernel.org/)，下載[最新的 linux kernel](https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.10.16.tar.xz)，解壓縮 linux kernel：
``` bash
tar -Jxvf linux-5.10.16.tar.xz
```

之後要對 linux kernel 做 config，這邊有兩種選擇，一種是重新選，一種則是拿現有的 config：
``` bash
cd linux-5.10.16

make menuconfig # option 1
cp -v /boot/config-$(uname -r) .config # option 2
```

若使用 option 1，會提醒你有些需要的 package 沒有安裝，此時就可以逐一安裝：
``` bash
sudo apt install -yq libncurses-dev flex bison # for make menuconfig
sudo apt install -yq libelf-dev # for make kernel
```

當做完 configuration，在編入 kernel 前，可以來新增自己的 syscall，而寫 syscall 的過程有點長，所以放在下面寫。

假設我們已經寫完 syscall，可以準備開始 compile 了。compile 可以選擇只 compile module
``` bash
make clean # 清除舊的資料

make modules # 只有 compile module
make -j 4 # j4 for 4 threads
make -j $(nproc) # match your thread number

make vmlinux
# 在 ./Makefile 中有 all: vmlinux，所以 make vmlinux == make
# 但其實好像是 make all == make vmlinux && make modules, 不確定新舊版本是否有差

make bzImage # 或是想要壓縮過的 linux kernel
```

安裝 compiled module 與 linux kernel
``` bash
make modules_install # modules in  /lib/modules/`uname -r`
make install # 
```



### Add syscall

首先在 linux kernel 資料夾下新增一個 hello dir，存放我們的 syscall file
``` bash
mkdir hello
```

hello/Makefile
``` Makefile
# 將 hello.o 編到 kernel 中
obj-y := hello.o
```

hello/hello.c
``` c
#include <linux/kernel.h>

// 因為 syscall handler 會把要傳給 syscall routine 的 parameter 從 register push 到 stack 中
// asmlinkage attribute 為用 stack 來讀取 parameter，而非 register

// syscall only print hello world
asmlinkage long sys_helloworld(void) {
	printk("hello, world!\n");
    return 0;
}
```

更改 `include/linux/syscalls.h` 檔案，將 `helloworld` 寫進去：
``` c
#if
// ...
asmlinkage long sys_helloworld(void);
#endif
```

更改 syscall table，在 `arch/x86/entry/syscalls/syscall_64.tbl`：
```
# <number> <abi> <name> <entry point>
# ...
# common for both x32 and 64
441 common  helloworld      sys_helloworld
```

這邊有一個地方需要注意，如果直接從 547 之後開始新增 syscall number 會報錯，可以大概看一下 Makefile，大概是指之前歷史性的錯誤導致 548 之後都不能用 x32 syscall (包含 common)，而 441 ~ 511 的 syscall number 是空的，因此我決定從 441 開始 assign。

最後修改 Makefile：
``` Makefile 
ifeq ($(KBUILD_EXTMOD),)
	core-y      += kernel/ certs/ mm/ fs/ ipc/ security/ crypto/ block/ hello/
	# 加上 hello/
	...
endif
```



### Debug kernel

#### Kernel

1. 到 [linux kernel 官方](https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/) 下載你要的版本的 source code
2. 解壓縮後執行 `make menuconfig`
3. 調整你 需要/不要 的設定，並且勾選 `Kernel hacking ---> Kernel debugging`
   - 每個版本都不一樣 (至少 4 跟 5 有差)
   - 4 要開啟 `Debug low-level entry code`
   - 5 要開啟 `miscellaneous debug code`
4. 執行 `make -j4 ARCH=x86_64` 編譯 kernel
5. 完成後目錄下會有 `./vmlinux`，這是帶有 debug info 的 linux kenrel；並且在 `./arch/x86/boot/bzImage` 有壓縮過的 linux kernel，是待會 `qemu` 用來執行模擬環境的 kernel

Others

- 編譯時如果需要 bpf，必須 enable network，並且到 `network options` 之類的子菜單勾選需要的功能，如 `enable JIT`
- 如果要從 patch file 來更新檔案，可以執行 `patch -p<ignore_path> < fn.patch`



#### File system

1. 到 [busybox 官方](https://www.busybox.net/) 下載你要的版本的 source code

2. 解壓縮後執行 `make menuconfig`

3. 調整你 需要/不要 的設定，並且勾選 `Settings --> Build static binary (no shared libs)`

4. 執行 `make install`，會產生 `_install`

5. 進入 `_install`，執行以下指令

   ```bash
   mkdir -p proc sys tmp etc/init.d
   touch etc/init.d/rcS && chmod +x etc/init.d/rcS
   touch init && chmod +x init
   touch pack.sh && chmod +x pack.sh
   ```

6. 修改 `etc/init.d/rcS`

   ```bash
   #!/bin/sh
   
   # create pseudo fs
   mount -t proc none /proc
   mount -t tmpfs none /tmp
   mount -t devtmpfs none /dev
   mount -t sysfs  none /sys
   /sbin/mdev -s
   
   # uncomment if need
   # insmod /test.ko
   # echo 0 > /proc/sys/kernel/dmesg_restrict
   # echo 0 > /proc/sys/kernel/kptr_restrict
   # cd /home/pwn
   # chown -R 1000:1000 .
   
   setsid cttyhack setuidgid 0 /bin/sh
   poweroff -f
   ```

7. 寫 `pack.sh` 並執行

   ```bash
   #!/bin/bash
   find . -print0 | cpio --null -ov --format=newc > ../rootfs.cpio
   ```

8. 將打包完的 `rootfs.cpio` 丟到與 `vmlinux` 相同的目錄

9. 執行 `qemu` 載入 `rootfs.cpio` 以及 `bzImage`

   ```bash
   #!/bin/bash                                                                                                                                       
   qemu-system-x86_64 \
       -m 256M \
       -nographic -kernel ./arch/x86/boot/bzImage \
       -append 'root=/dev/ram rw console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr' \
       -initrd rootfs.cpio \
       -monitor /dev/null \
       -smp cores=2,threads=2  \
       -cpu kvm64,+smep,+smap -s
   ```

   

#### Debug

1. 進入編譯時的目錄

2. 執行 `gdb ./vmlinux`，讓 `gdb` 能夠載入 linux kernel 的 symbol

3. 在 `gdb` 中執行

   ```
   add-auto-load-safe-path ./scripts/gdb/vmlinux-gdb.py
   target remote 0:1234
   ```

P.S. 也能將指令寫入 `script` 檔，並透過 `gdb ./vmlinux -x script` 來執行



參考資料: [kernel pwn 環境建置](https://n0va-scy.github.io/2020/06/21/kernel%20pwn%20%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA/)



### Memory layout

From `Documentation/x86/x86_64/mm.txt`:

```
<previous description obsolete, deleted>

Virtual memory map with 4 level page tables:

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

The direct mapping covers all memory in the system up to the highest
memory address (this means in some cases it can also include PCI memory
holes).

vmalloc space is lazily synchronized into the different PML4 pages of
the processes using the page fault handler, with init_level4_pgt as
reference.

Current X86-64 implementations support up to 46 bits of address space (64 TB),
which is our current limit. This expands into MBZ space in the page tables.

We map EFI runtime services in the 'efi_pgd' PGD in a 64Gb large virtual
memory window (this size is arbitrary, it can be raised later if needed).
The mappings are not part of any other kernel PGD and are only available
during EFI runtime calls.

-Andi Kleen, Jul 2004
```



### 背景知識：initrd & initramfs

這邊會大概講解一下關於 linux 的 initrd 與 initramfs 機制，更詳細的部分請看 [jserv 老師的 blog](http://blog.linux.org.tw/~jserv/archives/001954.html)，與[靴子的文章](https://sites.google.com/site/gyozapriate/Home/linux-island/boot/embedded-system/kernel-initrd#TOC-initrd-)，以下的介紹大部分都參考此兩篇文章與 wiki。

initrd (initialized ram disk) 為一塊特殊的 ram disk，在 linux kernel 載入前，由 boot loader 載入 initrd image 到 ram 中，而後載入 kernel 完畢並執行時，會優先處理放 initrd image 的 memory space。image 本身含有 filesystem，通常也包含 `init` 檔案，而 `init` 做的事情像是會掛載一些 driver modules。可以把 initrd 當作是一個小型的 disk (in RAM)，內部存放小型的 root file system (rootfs)。

initrd 為兩階段式開機：
1. 在 kernel 完成一些初始化後，會讀取與掛載 initrd 所在 memory space 的 filesystem，並執行 `init` program
2. 結束後 initrd 會被 release，而 kernel 在完成更多操作後掛載真正的 rootfs，並執行 `/sbin/init` program

從開機到 user space：
1. [boot loader] 將 kernel 與 initrd 這兩個 image 載入 RAM
2. [boot loader -> kernel] 結束一些必要的操作後，會把執行權交給 linux kernel
3. [kernel] 進行一連串初始化後，initrd 所在的 memory space 會被 kernel 對應為 `/dev/initrd` device，並由 kernel 來 decompressor (gzip) decompress 內容並複製到 `/dev/ram0`
4. [kernel] kernel 以 R/W mode 將 `/dev/ram0` **掛載成暫時的 rootfs** (file system 的 block device)
5. [kernel space -> user space] kernel 準備 run `/dev/ram0` 上的 /linuxrc
6. [user space] /linuxrc 處理特定的操作，如**準備**掛載真正 rootfs
7. [user space -> kernel space] /linuxrc 跑完後，將執行權還給 kernel
8. [kernel] kernel **掛載真正的 rootfs**，並執行 /sbin/init
	- /sbin/init 為第一個執行的 userspace process，可以用 `ps aux` 查看 pid = 1，kernel 會保存 pid=1 給 `/sbin/init` process
9. [user space] 開始執行各種 program

而 initrd 的機制有一些缺點：
1. `/dev/ram0` 為真的 block device，為了建構檔案 (e.g. `/linuxrc`)，需要掛載成一個 file system (e.g. ext2)，但此階段並不需要一個完整的 file system
2. `/dev/initrd` block device 建構時即有空間限制，維護繁瑣
3. 關於檔案操作，實際是將 `/dev/initrd` (某塊 memory region) map 到可以存取到 file system 的 memory region，會有不必要的資源使用
4. 由於 Linux 核心的快取機制 (page/dentry cache)，其中的內容還會被快取到記憶體上，造成 memory overhead

基於以上缺點，initrd 有著資源使用率不佳以及效能不好的缺陷。

然而缺點 4. 提到，Linux 快取機制會想辦法把讀出/寫入 block device 的檔案/目錄做 cache (分別為 page cache / dentry cache)，而 initrd 會被 kernel 當作是 block device (`/dev/initrd`)，但是 initrd 的資料又不會重複使用，所以 cache 機制反而會造成資源使用的浪費，我們也能推得一切問題的根源：**initrd 被當作 block device 來使用**。

Linus Torvalds 實作了 **ramfs**，核心為在 cache 中保存這些檔案，直到被刪除或是重啟；而其他開發者以此為基礎，實作了 **tmpfs**，支援 swap 與 memory restriction 的 feature；最後以 tmpfs 為基礎，initramfs 讓 fs 可以自己調整 space 使用量，而整個 initramfs 機制就只是在 cache 機制做延伸，並沒有太多程式碼需要維護。

使用 initramfs 開機，會執行 `/init` 作為 pid = 1 的 process，作為第一個執行的 process。



## 背景知識：vmlinux + 檔案：bzImage

**vmlinux** 為 statically linked 的 kernel binary file

**vmlinux.bin** 為 symbol 與 relocation info 都被拔掉的 bootable raw binary file，使用 `objcopy` 可以從 vmlinux extrace 出 vmlinux.bin
``` bash
objcopy -O binary vmlinux vmlinux.bin
```

**vmlinuz** 為使用 zlib 壓縮過的 **vmlinux**，2.6.30 後 LZMA and bzip2 也支援，此檔案包含 boot and decompression capabilities，因此能用來 boot。在 boot 時使用 [decompress_kernel()](https://elixir.bootlin.com/linux/latest/source/arch/alpha/boot/misc.c#L152) 來 decompress vmlinuz。

vmlinuz 的 type 大致可以分成兩種：
- **zImage**：舊格式，壓縮完 < 512 KB，開機時 image 被 load 進 first 640 KB of RAM
- **bzImage** (big zImage)：壓縮完 > 512 KB，開機時 image 被 load 進 first 1 MB of RAM

查看自己 linux 的 vmlinuz file
``` bash
file /boot/vmlinuz-$(uname -r)
```

另外，官方有[提供一個腳本](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)，能夠從被壓縮的 vmlinux (vmlinuz) 中 extrace 出 vmlinux，不過沒有 debug symbol：
``` bash
./extrace-vmlinux vmlinuz > vmlinux
```

[這個工具](https://github.com/marin-m/vmlinux-to-elf)可以 extract 出有 symbol 的 kernel binary



## 檔案：XXX.ko

Loadable kernel modules (LKM) 被用來 extend the kernel of the Linux Distribution，簡單來說就是擴充 module，而 LKM 檔案的副檔名通常為 .ko (kernel object)。

LKM 附加於 linux kernel，用途非常多，最常看到的是 device driver。LKM 可以動態載入的特色，讓開發者不必每次改動程式碼後，都必須重新編譯整個 kernel，只需要單獨 compile LKM，並使用 `insmod` 等 command 來 insert module。

而在打 kernel pwn 題時，你所要打得並不會是 kernel 本身，而是出題者提供的 `XXX.ko` kernel object。跟 binary 不太一樣，`XXX.ko` 通常都是 no-stripped (不確定)，所以丟進 IDA decompile 可以看得很清楚。



### 檔案：XXX.cpio

出題者提供的 `XXX.cpio`，檔案雖然副檔名是 cipo，但是檔案格式卻是 gzip，必須先 `gunzip` 一下拿到被壓縮的檔案，這樣做其實是有理由的，等等介紹 cpio 時會提到。不過 `gunzip` 又只能解壓縮副檔名為 `.gz` 的檔案，因此要多做一層處理：
``` bash
mkdir rootfs
cp XXX.cpio rootfs/XXX.cpio.gz # gunzip 不會保留原檔案
cd rootfs && gunzip XXX.cpio.gz # 會得到 XXX.cpio
```

linux kernel 2.6 之後都包含一個 **cpio** 的壓縮包，當 boot 時，就會把檔案解壓縮到 rootfs 資料夾下 (有點像是 fs 的壓縮檔？)，而 decompress 後會執行 /rootfs/init 進行初始化

init 會跑一些 mount 的工作，如果 rootfs 中找不到的話，就會從其他 fs 找，最後跑如 /sbin/init 的 binary 作為 pid 1

cpio 為 unix OS 中用來備份檔案與程式的檔案格式，cpio 與 tar 同屬於**歸檔包**的檔案，能夠包含檔名、timestamp、access permission 等等。

cpio 存放在 `/boot/initrd.img-$(uname -r)`

copy-input cpio：
``` bash
cpio -i -vd < XXX.cpio
```

copy-out cpio：
```bash
find . -print0 | cpio --null -ov --format=newc > XXX.cpio
```



### 檔案：XXX.img

如果出題者直接給你一個 file system data image，即是使用 `initrd` 機制，將 XXX.img 作為暫時的 rootfs。可以用 mount 的方式來看 image 內部的檔案：

``` bash
mount -o loop XXX.img rootfs
# 讓 XXX.img 掛載到 loop device
# -o：options
# loop：pseudo-device，此 device 可以讓檔案如 block device 一樣被存取
```

而 qemu 會 mount XXX.img 作為 rootfs，並且設定通常會加上 `-append "root=/dev/sda"`，指定此 image 為 root device。

kernel 在啟動後會執行 `/linuxrc`，而通常 `/linuxrc` 會指向 `busybox`，`busybox` 的初始行為中的第二項即是執行 `/etc/init.d/rcS`，因此若要查看 init 所做的事，可以在 `/etc/init.d/rcS` 看到。



### 檔案：boot.sh / run.sh

啟動 qemu 的 shell script，裡面包含一些 kernel 的環境設置：
``` bash
qemu-system-x86_64 \
  -kernel ./bzImage \
  -initrd ./XXX.cpio \ # 指定 init fs
  # -hda ./rootfs.img
  # -append "root=/dev/sda" # 指定 root device
  -append "console=ttyS0 kaslr panic=-1" \
  -monitor none \
  -nographic \
  -no-reboot \
  -cpu qemu64,+smep,+smap\
  -m 256M \
  -s \
  init='/init'

# init: 指定 init 程式路徑
# -kernel bzImage：use 'bzImage' as kernel image
# -initrd XXX.cpio：use 'XXX.cpio' as initial ram disk
# -hda：Set a virtual hard drive and use the specified image file for it
# -append cmdline use 'cmdline' as kernel command line
	# nokaslr：可以關掉 aslr
	# kaslr：打開 aslr
	# console=ttyS0：指定 console，將資料導向 ttyS0 (ttyS0 即 COM1)
	# /dev/pts (pseudo-terminal slave) 底下 存放 tty
	# panic=-1：makes Linux try to reboot immediately after a panic
# -monitor dev：redirect the monitor to char device 'dev'
# -nographic：disable graphical output so that QEMU is a simple command line application
# -no-reboot：exit instead of rebooting
# -cpu cpu：select CPU
    # qemu64 and FLAGS：smep,smap
	# smep：Supervisor Mode Execution Protection 
	# smap：Supervisor Mode Access Protection 
# -m [size=]megs[,slots=n,maxmem=size] (RAM size)
# -s：shorthand for -gdb tcp::1234
# -S：可以停在 CPU 的起點
```



## Exploit



- [Learning Linux Kernel Exploitation 系列文章](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/#preface)



## kernel 保護機制

`cat /proc/cpuinfo`

- kernel 的 canary
  - 由 `.config --> CONFIG_HAVE_STACKPROTECTOR` 所控制
- Smep (Supervisor Mode Execution Protection)
  - 以 supervisor mode 執行 userspace 的 code 時 (E)，會造成 trap。(在 ARM 叫做 PXN (privileged execution never))
- Smap (Supervisor Mode Access Protection)
  - 以 supervisor mode 存取 userspace memory 時 (R/W)，會造成 trap。(在 ARM 叫做 PAN (privileged access never))
- kaslr
  - kernel address space layout randomization
- kpti
  - Kernel PageTable Isolation
- `dmesg`
- `/proc/kallsyms`



#### modprobe_path





## eBPF

寫 assembly-like instruction set，就可以存取特定的 kernel functionalities

-  perform a command on an extended BPF map or program

- 10 registers

- ```c
  #include <linux/bpf.h>
  int bpf(int cmd, union bpf_attr *attr, unsigned int size);
  ```

eBPF IR like:

```c
BPF_MOV64_IMM(BPF_REG_3, 1); // mov reg_3, 1
BPF_ALU64_REG(BPF_ARSH, BPF_REG_7, BPF_REG_5); // shr reg_7, reg_5
BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_9, 24); // movq reg_3, [reg_9 + 24]
BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, 0); // movq [reg_8 + 0], reg_6
```

- suffix:
  - `_REG` - register as parameter
  - `_IMM` - take an imm value

[all bpf insn](https://elixir.bootlin.com/linux/latest/source/samples/bpf/bpf_insn.h)

To store data or communicate with user **space programs** (or each other), eBPF programs can use a feature **called maps**. All maps represent **key-value-mappings** of some kind

- queue / stack
- exploit about
  - `--key_size` - size in bytes of **each index** used to access an element. Always use `sizeof(int)` == `4`
  - `--value_size` - size of **each array element**
  - `--max_entries` - length of the array, Always set `value_size` **as high as we need**, and set `max_entries` to `1`
- maps are created by the `BPF_MAP_CREATE` command of the **bpf syscall**
  - `--inmap` -  small map containing all parameters the exploit needs to run 
    - although there will be multiple parameters, they will all be stored inside a **single larger array entry**
  - `--outmap` - very small map containing any output from the exploit program
  - `--explmap` - larger map that will be used for the exploit itself

JIP - all eBPF programs are **JIT compiled** into native machine code when they are loaded

- except `CONFIG_BPF_JIT_ALWAYS_ON`
- running arbitrary JIT-compiled eBPF instructions would trivially allow **arbitrary memory access**, because the **load and store instructions are translated into indirect movs**, but...
- verifier - make sure **no OOB memory access** can be performed, and also that **no kernel pointers can be leaked**
  - **No pointer arithmetic or comparisons** can be performed, except for the **addition or subtraction of a pointer and a scalar value**
  - No pointer arithmetic that **leaves the bounds of known-safe memory regions** (i.e. maps) can be performed
  - No pointer values **can be returned from maps**, nor can they **be stored in maps**, where they **would be readable from user space**
  - No instruction is **reachable from itself**, meaning that the program may **not contain any loops**
  - verifier must track each program instruction and register value
    - `umin and umax` - **track the minimum and maximum value that the register can contain** when interpreted as an **unsigned** integer
    - `smin and smax` - track the minimum and maximum value that the register can contain when interpreted as a **signed** integer
    - `var_off` (`tnum`) - contains information about **certain bits that are known to be 0 or 1**
      - `value` - all bits set that are known **to be 1** in the register under consideration
        - 1 代表該 bit 為 1, 0 代表該 bit 為 0
      - `mask` - all bits set where the corresponding bit in the register **is unknown**
        - 1 代表該 bit unknown
- e.g. `BPF_JMP_IMM(BPF_JGE, BPF_REG_5, 8, 3); // cmp reg_5, 8 ; jge 3`
  - set umax of register 5 to 7, because any higher unsigned value would have **resulted in taking the other branch**

ALU Sanitation - in response to a large number of **security vulnerabilities** that were due to **bugs in the verifier**

- supplement the verifier’s **static range checks** with **runtime checks** on the **actual values** being processed by the program (動態更新 verifier range check)
- `alu_limit` - **maximal absolute value** that can safely be added to or subtracted from to the pointer **without exceeding the allowable range**
- Pointer arithmetic where the sign of the scalar operand is unknown **is disallowed**
- Assume that each scalar is **treated as positive**; the negative case is analogous

Before each arithmetic instruction that has an `alu_limit`, the following sequence of instructions is added:

```
BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit - 1); // mov reg_ax, alu_limit - 1
BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg); // sub reg_ax, off_reg (reg_ax < off_reg) --> reg_ax < 0
BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg); // or reg_ax, off_reg (if off_reg < 0) --> reg_ax < 0
BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0); // neg reg_ax
BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63); // shr reg_ax, 63
BPF_ALU64_REG(BPF_AND, off_reg, BPF_REG_AX); // and off_reg, reg_rax
```

- `off_reg` is the register containing the **scalar value**
- `BPF_REG_AX` is an **auxiliary register**

If the scalar exceeds `alu_limit`, then the first subtraction will **be negative**, so that the **MSB of BPF_REG_AX will be set**. If the scalar that is supposed to **be positive is in fact negative**, the BPF_OR instruction will **set the leftmost bit of BPF_REG_AX**. The negation followed by the **arithmetic shift** will then **fill BPF_REG_AX with all 0s**, so that the **BPF_AND will force off_reg to zero**, replacing the offending scalar. On the other hand, if the scalar falls within the appropriate range **0 <= off_reg <= alu_limit**, the arithmetic shift will **fill BPF_REG_AX with all 1s**, so that **the BPF_AND will leave the scalar register unchanged**.

此為 `alu_limit` 的檢查機制，能確保 `off_reg` 在 `0 <= off_reg <= alu_limit`。



#### eBPF userland

eBPF

- 會在 proc 執行時期 loaded，並在 process exit 時自動 unloaded
- 使用特定的 insn set 做執行，並且因為 kernel 有 verifier，因此是 safe (沒意外的話)
- 為 event-driven，會在指定的 event handler function 前加上 hook，如 system calls, function entry/exit, kernel tracepoints, network events 等等
  - 如果 predefined hook 找不到，就會建立 kprobe (kernel probe) or uprobe (user probe) 去 attach 上eBPF program



ebpf program 可以透過多種方式撰寫:

- high level
  - Cilium
  - bcc - python program
  - bpftrace 
    - uses **LLVM as a backend** to compile scripts to **eBPF bytecode**
- low level
  - C source，透過 `llvm` 轉成 bytecode



ebpf 不能任意執行 kernel function，必須要透過 ebpf 提供的 API 來執行，API 有 insn & function 的形式

為什麼要用 ebpf ? 其原因與 JS 的使用雷同，以下為使用 JS 的優點:

- **Safety:** Untrusted code runs in the browser of the user. This was solved by sandboxing JavaScript programs and abstracting access to browser data.
- **Continuous Delivery:** Evolution of program logic must be possible without requiring to constantly ship new browser versions. This was solved by providing the right low-level building blocks sufficient to build arbitrary logic.
- **Performance:** Programmability must be provided with minimal overhead. This was solved with the introduction of a Just-in-Time (JIT) compiler

VS. kernel module

- kernel module 的 function call 很有可能因為版本的不同而不能使用 <---> ebpf 的 API 通常只會增加不會減少
- kernel module 寫爛了可能會有安全的疑慮



C library 使用方式為 `#include <linux/bpf.h> bpf(int cmd, union bpf_attr *attr, unsigned int size)`，其中 `bpf_attr` 為:

```c
union bpf_attr {
               struct {    /* Used by BPF_MAP_CREATE */
                   __u32         map_type;
                   __u32         key_size;    /* size of key in bytes */
                   __u32         value_size;  /* size of value in bytes */
                   __u32         max_entries; /* maximum number of entries
                                                 in a map */
               };

               struct {    /* Used by BPF_MAP_*_ELEM and BPF_MAP_GET_NEXT_KEY
                              commands */
                   __u32         map_fd;
                   __aligned_u64 key;
                   union {
                       __aligned_u64 value;
                       __aligned_u64 next_key;
                   };
                   __u64         flags;
               };

               struct {    /* Used by BPF_PROG_LOAD */
                   __u32         prog_type;
                   __u32         insn_cnt;
                   __aligned_u64 insns;      /* 'const struct bpf_insn *' */
                   __aligned_u64 license;    /* 'const char *' */
                   __u32         log_level;  /* verbosity level of verifier */
                   __u32         log_size;   /* size of user buffer */
                   __aligned_u64 log_buf;    /* user supplied 'char *'
                                                buffer */
                   __u32         kern_version;
                                             /* checked when prog_type=kprobe
                                                (since Linux 4.1) */
               };
           } __attribute__((aligned(8)));
```



eBPF maps - 用來儲存不同種類的資料，有以下 attr:

- type
- maximum number of elements
- key size in bytes
- value size in bytes
- 用途: **keep state** between invocations of the eBPF program, and allows **sharing data between eBPF kernel programs**, and also between **kernel and user-space applications**
- a **key/value** store with arbitrary structure

透過 `socket()` attach 上 hook

- 為什麼是 `socket()` ? 我猜是因為過去 bpf 只用來處理封包的關係



#### tools

`bpftool` - 落於 `./tools/bpf/bpftool`



#### dynamic tracing

`__x86_indirect_thunk_rax` --> `__x64_sys_bpf` --> `__do_sys_bpf` ([src](https://elixir.bootlin.com/linux/v5.4.9/source/kernel/bpf/syscall.c#L2837))

```c
	if (sysctl_unprivileged_bpf_disabled && !capable(CAP_SYS_ADMIN)) // 檢查權限
		return -EPERM;

	err = bpf_check_uarg_tail_zero(uattr, sizeof(attr), size); // argu 是否合法
	if (err)
		return err;
	size = min_t(u32, size, sizeof(attr));

	/* copy attributes from user space, may be less than sizeof(bpf_attr) */
	if (copy_from_user(&attr, uattr, size) != 0)
		return -EFAULT;
	err = security_bpf(cmd, &attr, size);
```

一開始會做一些基本的判斷，並執行 `security_bpf()` 來檢查是否可以執行 ebpf:

- `security_bpf` --> `selinux_bpf()` (這邊應該是檢查 selinux 是否允許 ebpf) --> `avc_has_perm()` --> ...

緊接著是:

```c
	...
	switch (cmd) {
	case BPF_MAP_CREATE:
		err = map_create(&attr);
		break;
	case BPF_MAP_LOOKUP_ELEM:
		err = map_lookup_elem(&attr);
		break;
	case BPF_MAP_UPDATE_ELEM:
		err = map_update_elem(&attr);
    ...
```

之後會從 `cmd` 來判斷要執行哪個 function，像是:

- `BPF_MAP_CREATE` --> `map_create(&attr)`
- `BPF_PROG_LOAD` --> `bpf_prog_load(&attr, uattr)`
- `BPF_MAP_LOOKUP_ELEM` --> `map_lookup_elem(&attr)`
- `BPF_MAP_UPDATE_ELEM` --> `map_update_elem(&attr)`
- ...



bpf 在驗證時使用到的 struct `bpf_verifier_env`:

```c
/* single container for all structs
 * one verifier_env per bpf_check() call
 */
struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;		/* eBPF program being verified */
	const struct bpf_verifier_ops *ops;
	struct bpf_verifier_stack_elem *head; /* stack of verifier states to be processed */
	int stack_size;			/* number of states to be processed */
	bool strict_alignment;		/* perform strict pointer alignment checks */
	bool test_state_freq;		/* test verifier with different pruning frequency */
	struct bpf_verifier_state *cur_state; /* current verifier state */
	struct bpf_verifier_state_list **explored_states; /* search pruning optimization */
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[MAX_USED_MAPS]; /* array of map's used by eBPF program */
	u32 used_map_cnt;		/* number of used maps */
	u32 id_gen;			/* used to generate unique reg IDs */
	bool allow_ptr_leaks;
	bool seen_direct_write;
	struct bpf_insn_aux_data *insn_aux_data; /* array of per-insn state */
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[BPF_MAX_SUBPROGS + 1];
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	...
```

印出來會像是:

```
pwndbg> p *(struct bpf_verifier_env *) 0xffff88801ea46000
$3 = {
  insn_idx = 0,
  prev_insn_idx = 0,
  prog = 0xffffc9000002d000,
  ops = 0xffffffff820f32a0 <sk_filter_verifier_ops>,
  head = 0x0 <fixed_percpu_data>,
  stack_size = 0,
  strict_alignment = false,
  test_state_freq = false,
  cur_state = 0xffff88801f9e3680,
  explored_states = 0xffff88801fa1de00,
  free_list = 0x0 <fixed_percpu_data>,
  used_maps = {0xffff88801fb9d400, 0xffff88801d168000, 0x0 <fixed_percpu_data> <repeats 62 times>},
  used_map_cnt = 2,
  id_gen = 0,
  allow_ptr_leaks = false,
  seen_direct_write = false,
  insn_aux_data = 0xffffc90000035000,
  prev_linfo = 0x0 <fixed_percpu_data>,
  log = {
    level = 1,
    kbuf = '\000' <repeats 1023 times>,
    ubuf = 0x4c5420 "",
    len_used = 0,
    len_total = 65535
  },
  subprog_info = {{
      start = 0,
      linfo_idx = 0,
      stack_depth = 0
    }, {
      start = 52,
      linfo_idx = 0,
      stack_depth = 0
    }, {
      start = 0,
      linfo_idx = 0,
      stack_depth = 0
    } <repeats 255 times>},
  cfg = {
    insn_state = 0x0 <fixed_percpu_data>,
    insn_stack = 0x0 <fixed_percpu_data>,
    cur_stack = 0
  },
  pass_cnt = 1,
  subprog_cnt = 1,
  prev_insn_processed = 0,
  insn_processed = 0,
  prev_jmps_processed = 0,
  jmps_processed = 0,
  verification_time = 0,
  max_states_per_insn = 0,
  total_states = 0,
  peak_states = 0,
  longest_mark_read_walk = 0
}
```



用來描述 register 狀態的 struct `bpf_reg_state`:

```c
struct bpf_reg_state {
	/* Ordering of fields matters.  See states_equal() */
	enum bpf_reg_type type;
	union {
		u16 range;
		struct bpf_map *map_ptr;
		unsigned long raw;
	};
	u32 id;
	u32 ref_obj_id;
	struct tnum var_off;
	s64 smin_value; /* minimum possible (s64)value */
	s64 smax_value; /* maximum possible (s64)value */
	u64 umin_value; /* minimum possible (u64)value */
	u64 umax_value; /* maximum possible (u64)value */
	/* parentage chain for liveness checking */
	struct bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
};
```

初始狀態:

```
pwndbg> p *(struct bpf_reg_state*) 0xffff88801d120000
$6 = {
  type = NOT_INIT,
  {
    range = 0,
    map_ptr = 0x0 <fixed_percpu_data>,
    btf_id = 0,
    raw = 0
  },
  off = 0,
  id = 0,
  ref_obj_id = 0,
  var_off = {
    value = 0,
    mask = 18446744073709551615 // 0xffffffffffffffff
  },
  smin_value = -9223372036854775808, // 0x8000000000000000
  smax_value = 9223372036854775807, // 0x7fffffffffffffff
  umin_value = 0,
  umax_value = 18446744073709551615, // 0xffffffffffffffff
  parent = 0x0 <fixed_percpu_data>,
  frameno = 0,
  subreg_def = 0,
  live = REG_LIVE_NONE,
  precise = true
}
```

過程中:

```
$13 = {
  type = SCALAR_VALUE,
  {
    range = 54272,
    map_ptr = 0xffff88801fb9d400,
    btf_id = 532272128,
    raw = 18446612682602304512
  },
  off = 0,
  id = 0,
  ref_obj_id = 0,
  var_off = {
    value = 0,
    mask = 0
  },
  smin_value = 0,
  smax_value = 0,
  umin_value = 0,
  umax_value = 0,
  parent = 0x0 <fixed_percpu_data>,
  frameno = 0,
  subreg_def = 0,
  live = REG_LIVE_WRITTEN,
  precise = true
}
```

刪除了大量註釋，如果要看 member 的行為請參考 [src](https://elixir.bootlin.com/linux/v5.6/source/include/linux/bpf_verifier.h#L43)。



真正儲存 register value 的 struct `bpf_func_state`:

```c
 /**
 * All registers are 64-bit.
 * R0 - return register
 * R1-R5 argument passing registers
 * R6-R9 callee saved registers
 * R10 - frame pointer read-only
 */
struct bpf_func_state {
	struct bpf_reg_state regs[MAX_BPF_REG]; // == __MAX_BPF_REG == 10
	/* index of call instruction that called into this func */
	int callsite;
	/* stack frame number of this function state from pov of
	 * enclosing bpf_verifier_state.
	 * 0 = main function, 1 = first callee.
	 */
	u32 frameno;
	/* subprog number == index within subprog_stack_depth
	 * zero == main subprog
	 */
	u32 subprogno;

	/* The following fields should be last. See copy_func_state() */
	int acquired_refs;
	struct bpf_reference_state *refs;
	int allocated_stack;
	struct bpf_stack_state *stack;
};
```



ebpf map 是用來儲存 userland 與 kernel 共同使用的資料，而儲存 **metadata** 相關的 struct 是 `bpf_map`:

```c
struct bpf_map {
	/* The first two cachelines with read-mostly members of which some
	 * are also accessed in fast-path (e.g. ops, max_entries).
	 */
    /* depend on map type, e.g. array --> array_map_ops */
	const struct bpf_map_ops *ops ____cacheline_aligned; 
	struct bpf_map *inner_map_meta;
#ifdef CONFIG_SECURITY
	void *security;
#endif
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	int spin_lock_off; /* >=0 valid offset, <0 error */
	u32 id;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	struct btf *btf;
	struct bpf_map_memory memory;
	char name[BPF_OBJ_NAME_LEN];
	u32 btf_vmlinux_value_type_id;
	bool unpriv_array;
	bool frozen; /* write-once; write-protected by freeze_mutex */
	/* 22 bytes hole */

	/* The 3rd and 4th cacheline with misc members to avoid false sharing
	 * particularly with refcounting.
	 */
	atomic64_t refcnt ____cacheline_aligned;
	atomic64_t usercnt;
	struct work_struct work;
	struct mutex freeze_mutex;
	u64 writecnt; /* writable mmap cnt; protected by freeze_mutex */
};
```

`bpf_array` 則包含 `bpf_map` 作為 member 以及 data pointer:

```c
struct bpf_array {
	struct bpf_map map; // metadata
	u32 elem_size;
	u32 index_mask;
	struct bpf_array_aux *aux;
	union {
		char value[0] __aligned(8); // 存放 map data pointer
		void *ptrs[0] __aligned(8);
		void __percpu *pptrs[0] __aligned(8);
	};
};
```

在執行 bpf program 時，很常會看到類似的 insn:

```
   0xffffffffc0002e1f    movabs rdi, 0xffff88801e157800 <--- 取得 bpf_array
   0xffffffffc0002e29    mov    rsi, rbp
   0xffffffffc0002e2c    add    rsi, -8
   0xffffffffc0002e30    mov    qword ptr [rsi], rbx
   0xffffffffc0002e34    add    rdi, 0x110 <-- 取得 map data pointer
 ► 0xffffffffc0002e3b    mov    eax, dword ptr [rsi]
   0xffffffffc0002e3e    cmp    rax, 1
   0xffffffffc0002e42    jae    0xffffffffc0002e50 <0xffffffffc0002e50>
```

基本上就是對應到 `BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem)`，而找 data 的方式就是先取出 `bpf_array`，再 `add  0x110` 取得 map data pointer，之後做對應的操作如 deference、compare 等等。





用來描述整個 bpf program 的 struct `bpf_prog`:

```c
struct bpf_prog {
	u16			pages;		/* Number of allocated pages */
	u16			jited:1,	/* Is our filter JIT'ed? */
				jit_requested:1,/* archs need to JIT the prog */
				gpl_compatible:1, /* Is filter GPL compatible? */
				cb_access:1,	/* Is control block accessed? */
				dst_needed:1,	/* Do we need dst entry? */
				blinded:1,	/* Was blinded */
				is_func:1,	/* program is a bpf function */
				kprobe_override:1, /* Do we override a kprobe? */
				has_callchain_buf:1, /* callchain buffer allocated? */
				enforce_expected_attach_type:1; /* Enforce expected_attach_type checking at attach time */
	enum bpf_prog_type	type;		/* Type of BPF program */
	enum bpf_attach_type	expected_attach_type; /* For some prog types */
	u32			len;		/* Number of filter blocks */
	u32			jited_len;	/* Size of jited insns in bytes */
	u8			tag[BPF_TAG_SIZE];
	struct bpf_prog_aux	*aux;		/* Auxiliary fields */
	struct sock_fprog_kern	*orig_prog;	/* Original BPF program */
	unsigned int		(*bpf_func)(const void *ctx,
					    const struct bpf_insn *insn);
	/* Instructions for interpreter */
	union {
		struct sock_filter	insns[0];
		struct bpf_insn		insnsi[0];
	};
};
```

其中 `bpf_insn insnsi[0]` 會在 `do_jit` 時被使用到 ([src](https://elixir.bootlin.com/linux/v5.6.19/source/arch/x86/net/bpf_jit_comp.c#L658)):

```c
static int do_jit(struct bpf_prog *bpf_prog, int *addrs, u8 *image,
		  int oldproglen, struct jit_context *ctx)
{
	struct bpf_insn *insn = bpf_prog->insnsi;
	int insn_cnt = bpf_prog->len;
	bool seen_exit = false;
	u8 temp[BPF_MAX_INSN_SIZE + BPF_INSN_SAFETY];
	int i, cnt = 0, excnt = 0;
	int proglen = 0;
	u8 *prog = temp;
	...
```



`do_jit` 是 kernel 在對 bpf program 做 just-in-time compile，產生的 native code 會在指定的 event 發生時被呼叫。 可以看一下 `do_jit` 會是怎樣被層層呼叫到的:

```
 ► f 0 0xffffffff81062d50 do_jit.isra
   f 1 0xffffffff81064fae bpf_int_jit_compile+206
   f 2 0xffffffff81152a20 bpf_prog_select_runtime+224
   f 3 0xffffffff81155cf9 bpf_prog_load+1033
   f 4 0xffffffff81156cf9 __do_sys_bpf+3337
   f 5 0xffffffff810028d3 do_syscall_64+67
   f 6 0xffffffff81c0008c entry_SYSCALL_64+124
```

- 參數 `u8 *image` 存放 JIT 產生的 code，可以**在此下斷點**



如果對某個 socket attach ebpf program (e.g. `setsockopt(socks[1], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)`)，則 trigger ebpf program 時的 call stack 可以參考下方:

```
#0  0xffffffffc0002d48 in ?? ()
#1  0xffffffff818cccff in bpf_dispatcher_nopfunc (bpf_func=<optimized out>, insnsi=<optimized out>, ctx=<optimized out>) at ./include/linux/bpf.h:522
#2  __bpf_prog_run_save_cb (skb=<optimized out>, prog=<optimized out>) at ./include/linux/filter.h:670
#3  bpf_prog_run_save_cb (skb=<optimized out>, prog=<optimized out>) at ./include/linux/filter.h:684
#4  sk_filter_trim_cap (sk=<optimized out>, skb=0xffff88801eb98000, cap=1) at net/core/filter.c:119
#5  0xffffffff819b6ddc in sk_filter (skb=<optimized out>, sk=<optimized out>) at ./include/linux/filter.h:813
#6  unix_dgram_sendmsg (sock=<optimized out>, msg=<optimized out>, len=<optimized out>) at net/unix/af_unix.c:1712
#7  0xffffffff8188d4a9 in sock_sendmsg_nosec (msg=<optimized out>, sock=<optimized out>) at ./include/linux/uio.h:235
#8  sock_sendmsg (sock=0xffff88801e45ed00, msg=0xffffc90000263dd8) at net/socket.c:672
#9  0xffffffff8188d542 in sock_write_iter (iocb=<optimized out>, from=0xffffc90000263e58) at net/socket.c:1004
#10 0xffffffff81207dc3 in call_write_iter (file=<optimized out>, iter=<optimized out>, kio=<optimized out>) at ./include/linux/fs.h:1902
#11 new_sync_write (filp=0xffff88801fb21c00, buf=<optimized out>, len=<optimized out>, ppos=0x0 <fixed_percpu_data>) at fs/read_write.c:483
#12 0xffffffff8120a941 in vfs_write (pos=<optimized out>, count=64, buf=<optimized out>, file=<optimized out>) at fs/read_write.c:558
#13 vfs_write (file=0xffff88801fb21c00, buf=0x7fff794a87a0 "", count=64, pos=0x0 <fixed_percpu_data>) at fs/read_write.c:542
#14 0xffffffff8120ac02 in ksys_write (fd=<optimized out>, buf=0x7fff794a87a0 "", count=64) at fs/read_write.c:611
#15 0xffffffff810028d3 in do_syscall_64 (nr=<optimized out>, regs=0xffffc90000263f58) at arch/x86/entry/common.c:294
#16 0xffffffff81c0008c in entry_SYSCALL_64 () at arch/x86/entry/entry_64.S:175
#17 0x0000000000000000 in ?? ()
```

一層一層往回追，首先會先 return 回 `bpf_dispatcher_nopfunc`:

```c
static __always_inline unsigned int bpf_dispatcher_nopfunc(
	const void *ctx,
	const struct bpf_insn *insnsi,
	unsigned int (*bpf_func)(const void *,
				 const struct bpf_insn *))
{
	return bpf_func(ctx, insnsi);
}
```

再來是 `__bpf_prog_run_save_cb`:

```c
static inline u32 __bpf_prog_run_save_cb(const struct bpf_prog *prog,
					 struct sk_buff *skb)
{
	u8 *cb_data = bpf_skb_cb(skb);
	u8 cb_saved[BPF_SKB_CB_LEN];
	u32 res;

	if (unlikely(prog->cb_access)) {
		memcpy(cb_saved, cb_data, sizeof(cb_saved));
		memset(cb_data, 0, sizeof(cb_saved));
	}

	res = BPF_PROG_RUN(prog, skb);

	if (unlikely(prog->cb_access))
		memcpy(cb_data, cb_saved, sizeof(cb_saved));

	return res;
}
```

- 其中 `BPF_PROG_RUN(prog, skb)` 為呼叫 bpf hook，prog 的資料可以參考一下:

  ```
  pwndbg> p *(struct bpf_prog *)0xffffc9000002d000
  $21 = {
    pages = 1,
    jited = 1,
    jit_requested = 1,
    gpl_compatible = 1,
    cb_access = 0,
    dst_needed = 0,
    blinded = 0,
    is_func = 0,
    kprobe_override = 0,
    has_callchain_buf = 0,
    enforce_expected_attach_type = 0,
    type = BPF_PROG_TYPE_SOCKET_FILTER,
    expected_attach_type = BPF_CGROUP_INET_INGRESS,
    len = 72,
    jited_len = 336,
    tag = "eֈ\032O\026\071n",
    aux = 0xffff88801fa1dc00,
    orig_prog = 0x0 <fixed_percpu_data>,
    bpf_func = 0xffffffffc0002d48, // 存放 jit 產完的 code 的地方
    {
      insns = 0xffffc9000002d038, // original insn
      insnsi = 0xffffc9000002d038
    }
  }
  ```

- `BPF_PROG_RUN()` macro 為:

  ```c
  #define BPF_PROG_RUN(prog, ctx) __BPF_PROG_RUN(prog, ctx,		\
  					       bpf_dispatcher_nopfunc)
  
  #define __BPF_PROG_RUN(prog, ctx, dfunc)	({			\
  	u32 ret;							\
  	cant_sleep();							\
  	if (static_branch_unlikely(&bpf_stats_enabled_key)) {		\
  		struct bpf_prog_stats *stats;				\
  		u64 start = sched_clock();				\
  		ret = dfunc(ctx, (prog)->insnsi, (prog)->bpf_func);	\
  		stats = this_cpu_ptr(prog->aux->stats);			\
  		u64_stats_update_begin(&stats->syncp);			\
  		stats->cnt++;						\
  		stats->nsecs += sched_clock() - start;			\
  		u64_stats_update_end(&stats->syncp);			\
  	} else {							\
  		ret = dfunc(ctx, (prog)->insnsi, (prog)->bpf_func);	\
  	}								\
  	ret; })
  ```

  - `BPF_PROG_RUN(prog, skb)` 的 prog 為 bpf 的 struct，而 skb 為 socket buffer 的縮寫，也就是要處理的資料
    - 而 `BPF_PROG_RUN` 的 macro 第二參數為 ctx，為 context 的縮寫

再往上看一層，為 `sk_filter_trim_cap()`:

```c
/**
 *	sk_filter_trim_cap - run a packet through a socket filter
 *	@sk: sock associated with &sk_buff
 *	@skb: buffer to filter
 *	@cap: limit on how short the eBPF program may trim the packet
 *
 * Run the eBPF program and then cut skb->data to correct size returned by
 * the program. If pkt_len is 0 we toss packet. If skb->len is smaller
 * than pkt_len we keep whole skb->data. This is the socket level
 * wrapper to BPF_PROG_RUN. It returns 0 if the packet should
 * be accepted or -EPERM if the packet should be tossed.
 *
 */
int sk_filter_trim_cap(struct sock *sk, struct sk_buff *skb, unsigned int cap)
{
    struct sk_filter *filter;
	...
    filter = rcu_dereference(sk->sk_filter);
	if (filter) {
		struct sock *save_sk = skb->sk;
		unsigned int pkt_len;

		skb->sk = sk;
		pkt_len = bpf_prog_run_save_cb(filter->prog, skb);
		skb->sk = save_sk;
		err = pkt_len ? pskb_trim(skb, max(cap, pkt_len)) : -EPERM;
	}
	...
}
```

- 查看其註解能清楚知道此 function 可能會執行到 eBPF program

- `struct sk_filter` 能夠處理特定封包:

  ```c
  struct sk_filter {
  	refcount_t	refcnt;
  	struct rcu_head	rcu;
  	struct bpf_prog	*prog;
  };
  ```

- 該狀態的 `sk_filter` 為:

  ```c
  $30 = {
    refcnt = {
      refs = {
        counter = 1
      }
    },
    rcu = {
      next = 0x0 <fixed_percpu_data>,
      func = 0x0 <fixed_percpu_data>
    },
    prog = 0xffffc9000002d000
  }
  ```

  - prog 指到的就是 ebpf program struct

上一層 `sk_filter()`:

```c
static inline int sk_filter(struct sock *sk, struct sk_buff *skb)
{
	return sk_filter_trim_cap(sk, skb, 1);
}
```

再上層 `sock_sendmsg()`:

```c
int sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
	int err = security_socket_sendmsg(sock, msg,
					  msg_data_left(msg));

	return err ?: sock_sendmsg_nosec(sock, msg);
}

static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
	int ret = INDIRECT_CALL_INET(sock->ops->sendmsg, inet6_sendmsg,
				     inet_sendmsg, sock, msg,
				     msg_data_left(msg));
	BUG_ON(ret == -EIOCBQUEUED);
	return ret;
}
```

原來是透過 `sock_write_iter()` 呼叫到 `sock_sendmsg(sock, &msg)`:

```c
static ssize_t sock_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	...
	res = sock_sendmsg(sock, &msg);
	...
	return res;
}
```

- 再上去就是 `sys_write` 的部分 `new_sync_write`

**Trigger hook 總結**

- `entry_SYSCALL_64` --> `do_syscall_64` --> `__x86_indirect_thunk_rax` --> `__x64_sys_write` --> `ksys_write` --> ` __vfs_write` --> `new_sync_write` --> `call_write_iter` --> `sock_write_iter` --> `sock_sendmsg` --> `sk_filter` --> `sk_filter_trip_cap` --> `__bpf_prog_run_save_cb` --> `bpf_dispatcher_nopfunc` (`BPF_PROG_RUN`) --> our ebpf program



`map_create()`:

- `map = find_and_alloc_map(attr)` - 根據 user 傳入的 attr 來建立 map



`bpf_prog_load()`:

- `err = bpf_check(&prog, attr, uattr)` - 執行 eBPF verifier
- `bpf_check()` ([src](https://elixir.bootlin.com/linux/v5.6.19/source/kernel/bpf/verifier.c#L10053))



`false_reg` vs. `true_reg` - 代表對應 opcode 產生的兩個 branch

```c
	case BPF_JGE:
	case BPF_JGT:
	{
		u64 false_umax = opcode == BPF_JGT ? val    : val - 1;
		u64 true_umin = opcode == BPF_JGT ? val + 1 : val; // 條件成立時 umin == val == 1

		if (is_jmp32) {
			false_umax += gen_hi_max(false_reg->var_off);
			true_umin += gen_hi_min(true_reg->var_off);
		}
		false_reg->umax_value = min(false_reg->umax_value, false_umax);
		true_reg->umin_value = max(true_reg->umin_value, true_umin);
		break;
	}

	case BPF_JLE:
	case BPF_JLT:
	{
		u64 false_umin = opcode == BPF_JLT ? val    : val + 1;
		u64 true_umax = opcode == BPF_JLT ? val - 1 : val; // 條件成立時 umax == val == r8

		if (is_jmp32) {
			false_umin += gen_hi_min(false_reg->var_off);
			true_umax += gen_hi_max(true_reg->var_off);
		}
		false_reg->umin_value = max(false_reg->umin_value, false_umin);
		true_reg->umax_value = min(true_reg->umax_value, true_umax);
		break;
	}
```



在 update element 時，會執行 ` bpf_map_update_value` ([src](https://elixir.bootlin.com/linux/v5.6/source/kernel/bpf/syscall.c#L156))，透過 `map->type` 來決定使用什麼 function 來 update element:

```c
static int bpf_map_update_value(struct bpf_map *map, struct fd f, void *key,
				void *value, __u64 flags)
{
	int err;

	/* Need to create a kthread, thus must support schedule */
	if (bpf_map_is_dev_bound(map)) {
		return bpf_map_offload_update_elem(map, key, value, flags);
	} else if (map->map_type == BPF_MAP_TYPE_CPUMAP ||
		   map->map_type == BPF_MAP_TYPE_SOCKHASH ||
		   map->map_type == BPF_MAP_TYPE_SOCKMAP ||
		   map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
		return map->ops->map_update_elem(map, key, value, flags);
	}
	...
	} else if (map->map_type == BPF_MAP_TYPE_QUEUE ||
		   map->map_type == BPF_MAP_TYPE_STACK) {
		err = map->ops->map_push_elem(map, value, flags);
	}
	...
```



##### 參考資源

- [ebpf.io](https://ebpf.io/what-is-ebpf/)
- [BPF 进阶笔记](http://arthurchiao.art/blog/bpf-advanced-notes-1-zh/)
- https://blog.csdn.net/pwl999/article/details/82884882

