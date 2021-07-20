## Kernel Pwn

### Reference

[bsauce 一系列的文章](https://github.com/bsauce/kernel-security-learning)
[yuawn 線上講解 2019_TokyoWesterns_CTF_Gnote](https://fb.watch/3ErU8pX3Jy/)
[yuawn kernel-exploit 教學 repo](https://github.com/yuawn/kernel-exploitation)



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