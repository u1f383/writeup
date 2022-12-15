## Teedium-wallet

首先解這題之前，要先補充關於 ARM 的 Trust-Zone 知識。



### Introduction

> 參考文章： https://harmonyhu.com/2018/06/23/Arm-trusted-firmware/

ARM 的 exception level 分成 EL3 - EL0，能透過 `eret` 從高 level 降為低 level，反之觸發 exception 即可。以下為各個 EL 介紹：

- Normal world (untrusted)
  - **Non-secure EL0**: Unprivileged applications, such as applications downloaded from an App Store
  - **Non-secure EL1**: Rich **OS kernels** from, for example, Linux, Microsoft Windows, iOS
  - **Non-secure EL2**: **Hypervisors**, from vendors such as Citrix, VMWare, or OK-Labs
- Secure world (trusted)
  - **Secure EL0**: Trusted OS applications
  - **Secure EL1**: Trusted OS kernels from Trusted OS vendors such as Trustonic
  - **Secure EL3:** Secure Monitor, executing secure platform firmware provided by Silicon vendors and OEMs **ARM Trusted Firmware**

BL 為 boot loader 的縮寫，而以下是 ARM 開機的執行流程：

- BL1
  - reset vector 後在 ROM 內執行
  - **mode 為 EL3**，起始執行位址為 `BL1_RO_BASE`
  - BL1 的 data 會被複製到 trusted SRAM 的上層，位址為 `BL1_RW_BASE`
  - 做初始化
    - 架構
      - 判斷 cold reset 或是 warm reset
      - 建立 exception vectors
      - 初始化 CPU
      - 設定暫存器，像是 `SCTLR_EL3`、`SCR_EL3`、`CPTR_EL3`、`DAIF`、`MDCR_EL3`
    - 平台
      - 開啟 Trusted Watchdog (reset the system in case of an authentication or loading error)
      - 初始化 console
      - 開啟 MMU
  - 配置 BL2
    - 設置 BL2 的儲存設備
    - 載入 BL2 到 Trusted SRAM
    - 執行 BL2
- BL2
  - 在 trusted SRAM 上執行，為 EL1
  - 為 ATF (ARM Trusted Firmware) 做初始化
  - reset CPACR.FPEN 使得在 EL1 與 EL0 可以存取 Floating Point 與 Advanced SIMD
  - 平台初始化：
    - 初始化 console
    - 設置 BL3 的儲存設備
    - 開啟 MMU
    - 保留 memory 給 EL3 Runtime Software
  - 載入 BL31 (EL3 Runtime Software) image 到 trusted SRAM
  - 載入 BL32 (Secure-EL1 Payload) image (optional)
  - 載入 BL33 (Non-trusted Firmware) image 到 non-secure memory
- BL31/BL32/BL33



總覽圖：

![img](https://harmonyhu.github.io/img/atf_boot_flow.jpg)



更簡單的流程：

![img](https://i.imgur.com/kv9yKGr.png)



---

題目提供了以下檔案：

```
# trusted application
7dc089d2-883b-4f7b-8154-ea1db9f1e7c3.ta

# bootloader
bl1.bin
bl2.bin
bl32.bin
bl32_extra1.bin
bl32_extra2.bin
bl33.bin

# docker environment
Dockerfile
docker_run.sh

# qemu environment
qemu_run.sh
qemu-system-arm

# kernel & fs
rootfs.cpio.gz
zImage

# description
README
```



目標是 .ta file (trusted application)，具體來講整個格式可以參考 [Security threat level estimation for untrusted software based on TrustZone technology](https://ispranproceedings.elpub.ru/jour/article/download/1495/1325) 這篇論文的介紹，但其實就是 ELF 前加上一個 header，可以直接用 binwalk 取出來。取出後用一些工具看一下作業系統環境：

```
# file
ta.elf: ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV), static-pie linked, stripped

# checksec
Arch:     arm-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
RWX:      Has RWX segment

# uname -a
Linux (none) 5.17.0 #5 SMP Sun May 22 00:26:58 PDT 2022 armv7l GNU/Linux
```

執行檔因為 strip + PIE 的關係，decompile 後看不出來程式行為，有許多字串包含 `TEE_XXX` 系列的 log message，以及 `[outstring]`、`[instring]` 等讀資料或寫資料時會印出的資訊。

以下為執行 QEMU 之後取得的一些互動資訊：

```
~ $ id
uid=1001(test) gid=1003(test) groups=1003(test)

~ $ ls -al /dev/
total 0
...
crw-rw----    1 root     test      250,   0 Dec  6 02:15 tee0
crw-rw----    1 root     tee       250,  16 Dec  6 02:15 teepriv0

~ $ ps -ef
PID   USER     COMMAND
    1 root     {init} /bin/sh /init
	...
   36 root     [irq/28-optee_no]
   54 tee      /usr/sbin/tee-supplicant /dev/teepriv0
   56 root     [optee_bus_scan]
   ...
```

從使用的 tool-chain 名稱可以知道題目使用 OP-TEE (Open Portable Trusted Execution Environment) 作為執行環境，OP-TEE 是一個實作 ARM TrustZone 的開源專案，相關 tool-chain 的原始碼與使用說明可以在[官方 github ](https://github.com/OP-TEE)找到。

首先分析 userspace daemon `tee-supplicant` 的功能是什麼，官方文件說明 "tee-supplicant is a daemon serving the Trusted OS in secure world with miscellaneous features, such as file system access"，而我自己參考了文章 [OP-TEE中TA与CA执行流程-------tee-supplicant（一）](https://blog.csdn.net/shuaifengyun/article/details/72912238) 以及原始碼 [OP-TEE/optee_client](https://github.com/OP-TEE/optee_client) 來分析。

程式執行流程：

- 做環境設置，像是開啟 device、取得 TA 路徑等等，並將自己背景化 (daemon)
- 透過 ioctl `TEE_IOC_SUPPL_RECV` 從 device `"/dev/teepriv0"` 取得請求
  - `read_request()` 接收請求
  - `find_params()` 解析參數
- 不同的 cmd 會執行不同的 handler，像是 `OPTEE_MSG_RPC_CMD_LOAD_TA` 或是 `OPTEE_MSG_RPC_CMD_FS`
- 將執行結果透過 ioctl `TEE_IOC_SUPPL_SEND` 回傳
  - `write_response()` 回傳結果

Request 使用的結構 (union) 為 `tee_rpc_invoke`：

```c
union tee_rpc_invoke {
	uint64_t buf[(RPC_BUF_SIZE - 1) / sizeof(uint64_t) + 1];
	struct tee_iocl_supp_recv_arg recv;
	struct tee_iocl_supp_send_arg send;
};
```

雖然說 MACRO name 描述是 `MSG_RPC_XXX` 不過並沒有看到程式有呼叫任何 RPC 的 API。



不同執行權限會有獨立的**執行檔**來處理相關請求，而 OPTEE 的 kernel driver 也被整合到 mainline linux：

- Normal PL0 (userspace) - `tee-supplicant`
- Normal PL1 (kernel) - `/dev/tee0`
- Secure PL0 - TA binary
- Secure PL1 - `bl32.bin`, `bl32_extra1.bin`, `bl32_extra2.bin`

以下為 linux 的 [TEE document](https://www.kernel.org/doc/Documentation/tee.txt) 整理：

- TEE - a trusted OS running in some secure environment, for example, TrustZone on ARM CPUs
- Linux tee subsystem 做：
  - Registration of TEE drivers
  - Managing shared memory between Linux and the TEE

  - Providing a generic API to the TEE

- TEE interface
  - 透過開啟 `/dev/tee[0-9]*` or `/dev/teepriv[0-9]*` 來與 TEE driver 互動，較特別的 cmd 有：
    - `TEE_IOC_SHM_ALLOC` - allocates shared memory and returns a file descriptor which user space can mmap
    - `TEE_IOC_OPEN_SESSION` - opens a new session to a Trusted Application
    - `TEE_IOC_INVOKE` - invokes a function in a Trusted Application
  - Two classes of clients
    - normal clients
      - open `/dev/tee[0-9]*`
    - supplicants - a helper process for the TEE to access resources in Linux
      - open `/dev/teepriv[0-9]`
  - Tee driver 最主要的工作是從 client 接收資料，並幫忙 forward 給 TEE，最後將執行結果回傳
- OP-TEE driver
  - Handles OP-TEE **based TEEs**. Currently it only support the ARM TrustZone
  - 與 OP-TEE 最底層的溝通方式建立在 ARM 的 SMC Calling Convention (SMCCC)，也就是 OP-TEE 的 SMC interface
  - 一些有趣的 cmd：
    - `OPTEE_SMC_CALL_WITH_ARG` - drives the OP-TEE message protocol

下方為執行流程：

```

      User space                  Kernel                   Secure world
      ~~~~~~~~~~                  ~~~~~~                   ~~~~~~~~~~~~
   +--------+                                             +-------------+
   | Client |                                             | Trusted     |
   +--------+                                             | Application |
      /\                                                  +-------------+
      || +----------+                                           /\
      || |tee-      |                                           ||
      || |supplicant|                                           \/
      || +----------+                                     +-------------+
      \/      /\                                          | TEE Internal|
   +-------+  ||                                          | API         |
   + TEE   |  ||            +--------+--------+           +-------------+
   | Client|  ||            | TEE    | OP-TEE |           | OP-TEE      |
   | API   |  \/            | subsys | driver |           | Trusted OS  |
   +-------+----------------+----+-------+----+-----------+-------------+
   |      Generic TEE API        |       |     OP-TEE MSG               |
   |      IOCTL (TEE_IOC_*)      |       |     SMCCC (OPTEE_SMC_CALL_*) |
   +-----------------------------+       +------------------------------+
```

從 secure world 到 kernel driver / tee-supplicant 會以 RPC (Remote Procedure Call) 格式來傳送請求，不過我想這邊的格式跟一般 RPC 格式應該不一樣。



---

OPTEE 的 qemu 有兩個 serial output，一個為 secure world、一個為 normal world，而 `qemu_run.sh` 定義了第二個 output 為 /dev/null (security)，如果更改成其他輸出位置，就能幫助 debug，所以把 `/dev/null` 的部分換成 `telnet::4444,server,nowait`，在透過 `telnet localhost 4444` 連線，就可以讀到 secure world 的輸出。



而 debug secure world 時，可能會遇到下面的問題：

1. 在 normal world 執行時不能存取 secure world 的記憶體
2. 在 normal world 執行時不能設置斷點在 secure world (ASLR)
3. Secure world 的 TA 不能 debug (?)



在 secure world 中有自己的 ASLR，分別由 OP-TEE OS 的 `CFG_CORE_ASLR` 與 `CFG_TA_ASLR` 設置：

- `CFG_CORE_ASLR` - 可以視為 Trusted OS 的 kASLR
- `CFG_TA_ASLR` - 就是 userspace 的 ASLR
  - TA 雖然是 PIE，不過也受到 ASLR 的影響 (?)
  - stack 位址是固定的 (?)

並且 OP-TEE 是否開啟 ASLR 是在編譯期間就決定好，所以沒有辦法透過參數調整，實際上可以將 seed patch 成固定的值，也就能確保每次隨機的位址都相同。而 Trust OS 的實作方式也是跟 normal world 相同，生成一個隨機位址，建立一個 page table，並註冊到MMU中，唯一不同的地方在於，pagewalk 的 page table 本身也在 secure memory 當中。

TTBR 為 Translation table base registers，也就是儲存 page table base 的暫存器，而 QEMU 使用的 CPU 為 cortex-a15，該 CPU 使用 ARM v7-A 指令集：

```
TTBR1_S        0xe1ac06a           236634218
TTBR0          0x4183806a          1099137130
TTBR1          0x4000406a          1073758314
TTBR0_S        0xe1ac06a           236634218
TTBR0_EL1      0x4183806a          1099137130
TTBR1_EL1      0x4000406a          1073758314
```

根據下方擷取自 ARMv7 文件的描數，`_S` 應該指的就是不同版本的對應暫存器：

> As described in *Access to the Secure or Non-secure physical address map* on page B3-1319, for Secure and Non-secure PL1&0 stage 1 translations, the Translation table base registers, TTBR0, TTBR1, and TTBCR are Banked between Secure and Non-secure versions, and the Security state of the processor when it performs a memory access selects the corresponding version of the registers.

但是 TTBR0_EL1 則是在 ARMv8 才有的暫存器：

- TTBR0_EL1 – banked
- TTBR1_EL1 – banked
- TTBR1_EL2
- TTBR1_EL3

什麼是 banked register

- Banked Register
  - Give rapid context switching for dealing with processor exceptions and privileged operations
  - 分成儲存 system 與儲存 general register 的 bank
- When the processor enters an exception, the **banked** registers are **switched automatically** with another set of these registers

這邊推薦文章 [一文搞懂 | ARM MMU](https://cloud.tencent.com/developer/article/1950803)，內文有對 OP-TEE 的 MMU 做一些介紹。MMU 分成兩個部分：TLB maintenance 和 address translation，其功能是翻譯記憶體，當開啟 MMU 後，不論 main-memory (DDR) 或是 IO address 都是使用虛擬位址，並且透過 MMU 轉換成物理位址，轉換後會由 AXI bus 來存取 device / memory。而 ARM 在使用 MMU 時，會使用暫存器 `TTBRx_EL1` 保存 page table 的基位址，而 `TTBR1_EL1` 指向 kernel mode 使用的，`TTBR1_EL0` 指向 userspace 使用的，並且根據不同 process 會有不同的 page table。

TTBRx_EL1 為 banked register，而在 linux 和 optee 兩個系統開啟的環境下，可以同時使用兩個系統的 MMU。在 secure 和 non-secure 中會使用 page table，並且 secure page table 可以 mapping 到 non-secure 的 memory，但 non-secure 不能 mapping 到 secure 的 memory。

EL0/EL1 時，如果 virtual address 落在 00000000 ffffffff ~ 0000ffff ffffffff，MMU 會自動使用 `TTBR0_EL1` 作為 page table base，而如果在 ffff0000 ffffffff ~ ffffffff ffffffff，則就使用 `TTBR1_EL1`。EL2 自動用 `TTBR1_EL2`，EL3 則用 `TTBR1_EL3`。



### From program to TA ep

關於整個執行流程，還可以參考官方 repo 上的 [issue](https://github.com/OP-TEE/optee_os/issues/2168)，內文有許多值得參考的圖片說明。使用者如果要呼叫 TA function，大概會做以下流程：

- normal user space
  - 可以透過 ioctl 直接呼叫 `TEE_IOC_OPEN_SESSION`，但也可以使用包裝好的 library [optee-client](https://github.com/OP-TEE/optee_client)，在此就直接呼叫包好的 function
  - 首先會透過 `TEEC_OpenSession()` 建立一個互動的 session，而後呼叫 `TEEC_RegisterSharedMemory()` 創建傳遞資料的記憶體，這邊都還只是初始化，不必細追
  - 再來呼叫 `TEEC_InvokeCommand()` 嘗試呼叫 TA function，最後會走到 `ioctl(TEE_IOC_INVOKE)`
- normal kernel space (linux)
  - 會由 tee driver 的 ioctl handler `tee_ioctl()` 處理，並轉交給對應 cmd 的 handler `tee_ioctl_invoke()`
    - 文件中有提到，tee driver 只是把使用者的資料做簡單的處理，而後轉交給 secure world，並不會針對 invoke 本身有任何的操作
  - 而後會透過 function pointer `optee_clnt_ops->invoke_func()` 呼叫 `optee_invoke_func()`
    - 底層會由 `optee_smc_do_call_with_arg()` 轉交給 secure world，function 的註解也有說明："Do an SMC to OP-TEE in secure world"
    - 不過最後要使用什麼 instruction，就與 CPU 有關了，一般情況下 `get_invoke_func()` 會回傳 `optee_smccc_smc()` 的位址，而該 function 實際會呼叫 `arm_smccc_smc()` (wrapper of `__arm_smccc_smc()`)
    - `SMCCC smc` 即是最後到 secure world 的進入點 ([source](https://elixir.bootlin.com/linux/latest/source/arch/arm64/kernel/smccc-call.S#L60))
      - SMCCC (SMC CALLING CONVENTION)
      - synchronous control is transferred between the **normal Non-secure** state and the **Secure** state through Secure Monitor Call (SMC) exceptions
      - HVC 則是由 EL1 --> EL2
- secure kernel space (optee)
  - `sm_smc_entry` (core/arch/arm/sm/sm_a32.S) - save CPU context, perform some checks，基本上就是做一些檢查，以及保存暫存器的資訊
  - `tee_entry_std()` - 會處理不同的 cmd，而在 tee driver 會把 `TEE_IOC_INVOKE` 轉成 `OPTEE_MSG_CMD_INVOKE_COMMAND`，在此會由 `entry_invoke_command()` 來處理
  - `tee_ta_invoke_command()` --> `ops->enter_invoke_cmd()` 實際上是 `user_ta_enter_invoke_cmd()` --> `user_ta_enter()`
  - 最後透過 `thread_enter_user_mode()` --> `__thread_enter_user_mode()` 切換到 userspace
- secure user space
  - `__utee_entry()` 為 TA 的進入點，而 cmd 會是 `UTEE_ENTRY_FUNC_INVOKE_COMMAND`，會由 `entry_invoke_command()` 負責處理
  - `TA_InvokeCommandEntryPoint()` 即是對應 TA 的 function 進入點



### Environment

#### 如何解決記憶體問題並 debug Trust OS?



1. 編譯執行檔

```bash
sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
git clone https://github.com/OP-TEE/optee_client.git
cd optee_client/libteec
CC=arm-linux-gnueabihf-gcc make

arm-linux-gnueabihf-gcc exp.c -o exp -I/home/u1f383/ctf/defcon-qual/secure-world-wallet/optee_client/libteec -L/home/u1f383/ctf/defcon-qual/secure-world-wallet/optee_client/out/libteec -lteec -lpthread -static
```

- cross compilation 會發生一些問題，不過我們需要的 library 並不會被影響



2. pack 腳本：

```bash
#!/bin/bash
find . -print0 | cpio -o --null --owner root --format=newc |gzip -c > ../rootfs.cpio.gz
```

- `--owner root` 必須要加
- 把 `init` 中的 `test` 改成 `root` 即可在開機時擁有 root 權限

而為了避免多次重啟造成測試上的困難，可以在 QEMU 執行的參數中啟用 9p fs，其為 QEMU 的虛擬檔案系統，讓主機上特定的目錄可以直接 pass-through 給 guest，並且 host 與 guest 能透過 9P network protocol 做溝通。

```bash
	-fsdev local,security_model=none,id=fsdev0,path=/host/dir \
	-device virtio-9p-device,fsdev=fsdev0,mount_tag=hostshare
```

最後在 VM 中執行下列命令，即可與 host 共享目錄：

```bash
mount hostshare -t 9p /mnt/host
```



3. Debug

在各個 mode 切換時下斷點：

- 0x80112864 - `__arm_smccc_smc` (non-trusted OS --> trusted OS)
- trusted base + 0x8d8 - `__thread_enter_user_mode()`
- 0x100904 - `eret_to_user_mode()`
- 0x1043fe - `ldelf()` 輸出 TA 被載入到的位址前
  - 0x104402 - 印出後




編譯 TEE client program 時會需要 TA 的 UUID，可以從檔案名稱中得知
- TEE_UUID - `{ 0x7dc089d2, 0x883b, 0x4f7b, { 0x81, 0x54, 0xea, 0x1d, 0xb9, 0xf1, 0xe7, 0xc3} }`



### 初步分析

執行開始時會印出許多 debug message，大概可以拆成幾個部分：

- 建立 page table BIOS (`"bl1.bin"`)
  ```
  $ ./qemu_run.sh
  mmap:
   VA:0x0  PA:0x0  size:0x4000  attr:0x2  granularity:0x40000000
   VA:0x4000  PA:0x4000  size:0x2000  attr:0x42  granularity:0x40000000
   VA:0x0  PA:0x0  size:0x4000000  attr:0x2  granularity:0x40000000
   VA:0x4000000  PA:0x4000000  size:0x4000000  attr:0x2  granularity:0x40000000
   VA:0x8000000  PA:0x8000000  size:0x1000000  attr:0x8  granularity:0x40000000
   VA:0x9000000  PA:0x9000000  size:0xc00000  attr:0x8  granularity:0x40000000
   VA:0xe000000  PA:0xe000000  size:0x1000  attr:0x8  granularity:0x40000000
   VA:0xe001000  PA:0xe001000  size:0x5f000  attr:0xa  granularity:0x40000000
  
  VERBOSE: Translation tables state:
  VERBOSE:   Xlat regime:     EL1&0
  VERBOSE:   Max allowed PA:  0xffffffff
  VERBOSE:   Max allowed VA:  0xffffffff
  VERBOSE:   Max mapped PA:   0xe05ffff
  VERBOSE:   Max mapped VA:   0xe05ffff
  VERBOSE:   Initial lookup level: 1
  VERBOSE:   Entries @initial lookup level: 4
  VERBOSE:   Used 3 sub-tables out of 6 (spare: 3)
  ```

- Trusted firmware (BL1) (`"bl1.bin"`)
  ```
  ...
  INFO:    BL1: RAM 0xe04e000 - 0xe056000
  ...
  INFO:    BL1: Loading BL2
  VERBOSE: Using Memmap
  ...
  INFO:    Loading image id=1 at address 0xe01b000
  INFO:    Image id=1 loaded: 0xe01b000 - 0xe0211cd
  VERBOSE: BL1: BL2 memory layout address = 0xe001000
  NOTICE:  BL1: Booting BL2
  INFO:    Entry point address = 0xe01b000
  ...
  VERBOSE: Argument #0 = 0x0
  VERBOSE: Argument #1 = 0xe001000
  VERBOSE: Argument #2 = 0x0
  VERBOSE: Argument #3 = 0x0
  ...
  ```

  - RAM: 0xe04e000 ~ 0xe056000
  - Entry point address: 0xe01b000
  - Load image: 0xe01b000 - 0xe0211cd (25037) 也就是檔案 `"bl2.bin"`

- BL2
  ```
  ...
  INFO:    BL2: Loading image id 4
  ...
  INFO:    Loading image id=4 at address 0xe100000
  INFO:    Image id=4 loaded: 0xe100000 - 0xe10001c
  INFO:    OPTEE ep=0xe100000
  INFO:    OPTEE header info:
  INFO:          magic=0x4554504f
  INFO:          version=0x2
  INFO:          arch=0x0
  INFO:          flags=0x0
  INFO:          nb_images=0x1
  INFO:    BL2: Loading image id 21
  ...
  INFO:    Loading image id=21 at address 0xe100000
  INFO:    Image id=21 loaded: 0xe100000 - 0xe190808
  ...
  INFO:    Loading image id=5 at address 0x60000000
  INFO:    Image id=5 loaded: 0x60000000 - 0x60092504
  NOTICE:  BL1: Booting BL32
  INFO:    Entry point address = 0xe100000
  INFO:    SPSR = 0x1d3
  VERBOSE: Argument #0 = 0xe300000
  VERBOSE: Argument #1 = 0x0
  VERBOSE: Argument #2 = 0x40000000
  VERBOSE: Argument #3 = 0x0
  ```

  - Load image (id=4): 0xe100000 - 0xe10001c (`"bl3.bin"`)
    - 其實 OPTEE header info 就是檔案 `"bl3.bin"` (size 28) 的內容
  - Load image (id=21): 0xe100000 ~ 0xe190808
  - Load image (id=5): 0x60000000 ~ 0x60092504 (`"bl33.bin" `的載入)

- BL3 - 執行 non-trusted firmware，檔案 `"bl33.bin"`

  ```
  U-Boot 2020.04 (May 28 2022 - 10:06:42 -0700)
  
  DRAM:  1 GiB
  WARNING: Caches not enabled
  In:    pl011@9000000
  Out:   pl011@9000000
  Err:   pl011@9000000
  Net:
  Warning: virtio-net#31 using MAC address from ROM
  eth0: virtio-net#31
  Hit any key to stop autoboot:  0
  loaded file zImage from 40400000 to 408DDBFF, 004DDC00 bytes
  QEMU: Saw last TARGET_SYS_OPEN
  loaded file rootfs.cpio.gz from 44000000 to 445951E7, 005951E8 bytes
  Kernel image @ 0x40400000 [ 0x000000 - 0x4ddc00 ]
  ## Flattened Device Tree blob at 40000000
     Booting using the fdt blob at 0x40000000
     Using Device Tree in place at 40000000, end 40006fff
  
  Starting kernel ...
  
  Booting Linux on physical CPU 0x0
  ...
  ```

而前面有提到說 secure wolrd (?) 有另一個 output，在一開始的設定中是會被導向至 `/dev/null`，而我們可以控制成用 `telnet` 存取，下面即是輸出中包含 secure world ASLR 的資訊：

```
D/TC:0   add_phys_mem:555 ROUNDDOWN(0x09040000, CORE_MMU_PGDIR_SIZE) type IO_SEC 0x09000000 size 0x00100000
D/TC:0   add_phys_mem:555 ROUNDDOWN(0x0e000000, CORE_MMU_PGDIR_SIZE) type IO_SEC 0x0e000000 size 0x00100000
D/TC:0   add_phys_mem:555 ROUNDDOWN((0x08000000 + 0), CORE_MMU_PGDIR_SIZE) type IO_SEC 0x08000000 size 0x00100000
D/TC:0   add_phys_mem:555 ROUNDDOWN((0x08000000 + 0x10000), CORE_MMU_PGDIR_SIZE) type IO_SEC 0x08000000 size 0x00100000
D/TC:0   add_phys_mem:569 Physical mem map overlaps 0x8000000
D/TC:0   add_phys_mem:555 VCORE_UNPG_RX_PA type TEE_RAM_RX 0x0e100000 size 0x0008e000
D/TC:0   add_phys_mem:555 VCORE_UNPG_RW_PA type TEE_RAM_RW 0x0e18e000 size 0x00172000
D/TC:0   add_phys_mem:555 TA_RAM_START type TA_RAM 0x0e300000 size 0x00d00000
D/TC:0   add_phys_mem:555 TEE_SHMEM_START type NSEC_SHM 0x7fe00000 size 0x00200000
D/TC:0   add_va_space:595 type RES_VASPACE size 0x00a00000
D/TC:0   add_va_space:595 type SHM_VASPACE size 0x02000000
D/TC:0   init_mem_map:1155 Mapping core at 0xa3721000 offs 0x95621000
D/TC:0   dump_mmap_table:718 type IDENTITY_MAP_RX va 0x0e100000..0x0e100fff pa 0x0e100000..0x0e100fff size 0x00001000 (smallpg)
D/TC:0   dump_mmap_table:718 type NSEC_SHM     va 0x9f800000..0x9f9fffff pa 0x7fe00000..0x7fffffff size 0x00200000 (pgdir)
D/TC:0   dump_mmap_table:718 type TA_RAM       va 0x9fa00000..0xa06fffff pa 0x0e300000..0x0effffff size 0x00d00000 (pgdir)
D/TC:0   dump_mmap_table:718 type IO_SEC       va 0xa0800000..0xa08fffff pa 0x0e000000..0x0e0fffff size 0x00100000 (pgdir)
D/TC:0   dump_mmap_table:718 type IO_SEC       va 0xa0900000..0xa09fffff pa 0x09000000..0x090fffff size 0x00100000 (pgdir)
D/TC:0   dump_mmap_table:718 type IO_SEC       va 0xa0a00000..0xa0afffff pa 0x08000000..0x080fffff size 0x00100000 (pgdir)
D/TC:0   dump_mmap_table:718 type RES_VASPACE  va 0xa0b00000..0xa14fffff pa 0x00000000..0x009fffff size 0x00a00000 (pgdir)
D/TC:0   dump_mmap_table:718 type SHM_VASPACE  va 0xa1600000..0xa35fffff pa 0x00000000..0x01ffffff size 0x02000000 (pgdir)
D/TC:0   dump_mmap_table:718 type TEE_RAM_RX   va 0xa3721000..0xa37aefff pa 0x0e100000..0x0e18dfff size 0x0008e000 (smallpg)
D/TC:0   dump_mmap_table:718 type TEE_RAM_RW   va 0xa37af000..0xa3920fff pa 0x0e18e000..0x0e2fffff size 0x00172000 (smallpg)
D/TC:0   core_mmu_alloc_l2:276 L2 table used: 1/6
D/TC:0   core_mmu_alloc_l2:276 L2 table used: 2/6
D/TC:0   core_mmu_alloc_l2:276 L2 table used: 3/6
D/TC:0   core_mmu_alloc_l2:276 L2 table used: 4/6
```

- Message 前有 function name 與行數，而找一下會發現這些 function 都在 optee-os 中被定義



做個整理：

- BL1 - 執行 bl1.bin，載入 BL2 的 image
  - 定位為 Boot ROM
  - 實際上一開始會先 boot BL2 (Trusted Firmware)，等到 BL2 檢查 + 載入結束後，會再交回執行權限，此時就會去執行 BL32 (Trusted OS)
- BL2 - 執行 bl2.bin，檢查 BL32 的 header (bl32.bin)，並將剩餘的 bl32 與 bl33 的 image 載到記憶體中
  - 定位為 Trusted Boot Firmware
  - BL1 與 BL2 皆是 [Trusted Firmware-A](https://github.com/ARM-software/arm-trusted-firmware)
- BL32 - 執行 bl32_extra1.bin ，同時 secure world 的另一個 output (telnet) 也會開始輸出
  - 定位為 Trusted OS Kernel
  - 其實就是編譯後的 [OP-TEE Trusted OS](https://github.com/OP-TEE/optee_os)
- BL33 - 執行 bl33.bin，最後載入 non-secure OS
  - 定位為 Non-Trusted Firmware
  - 專案為 [U-Boot](https://github.com/ARM-software/u-boot)
- OS - 執行 linux kernel (zImage)
  - 定位為 Non-Secure Kernel
- Other
  - BL31 在 Aarch64 才會使用到，為 runtime firmware (?)

流程

- BL1 載入 BL2
- BL1 執行 BL2
- BL2 檢查 BL32
- BL2 載入 BL32
- BL2 載入 BL33
- BL2 回到 BL1
- BL1 執行 BL32
- BL32 執行 BL33
- BL33 載入 linux
- BL33 執行 linux

檔案對應

- BL1 - bl1.bin
- BL2 - bl2.bin
- BL32 - bl32_extra1.bin
- BL33 - bl33.bin



#### Trust os internal

由於 bl32_extra1.bin 沒有 symbol，因此斷點與對應的 function 必須動態跟 source code 做對應，以下為執行至 TA 的過程 trusted os 的呼叫流程：

- `sm_vect_table_bpiall`

- `sm_smc_entry`
  - `.smc_from_nsec` branch，因為來自 non-secure world

- `sm_from_nsec()`
  - `OPTEE_SMC_OWNER_NUM(args->a0)` 為 50 (`OPTEE_SMC_OWNER_TRUSTED_OS`)
  - `bx` instruction 將 instruction mode 轉成 Thumb 或是反過來

- `vector_std_smc_entry()`

- `thread_handle_std_smc()`

- `thread_resume()`

- `thread_std_smc_entry()`

- `__thread_std_smc_entry()`

- `std_smc_entry()`
  - 參數 `a0` 為 `OPTEE_SMC_CALL_WITH_ARG`

- `std_entry_with_parg()`

- `call_entry_std()`

- `tee_entry_std()`

- `__tee_entry_std()` - 到此就能直接看 source code 去比對執行流程
  - 0x1E3EE - 此斷點為執行 `arg->cmd` 的 switch case

- 後續會走到：
  ```c
  const struct ts_ops user_ta_ops __weak __relrodata_unpaged("user_ta_ops") = {
  	.enter_open_session = user_ta_enter_open_session,
  	.enter_invoke_cmd = user_ta_enter_invoke_cmd,
  	.enter_close_session = user_ta_enter_close_session,
  #if defined(CFG_TA_STATS)
  	.dump_mem_stats = user_ta_enter_dump_memstats,
  #endif
  	.dump_state = user_ta_dump_state,
  #ifdef CFG_FTRACE_SUPPORT
  	.dump_ftrace = user_ta_dump_ftrace,
  #endif
  	.destroy = user_ta_ctx_destroy,
  	.get_instance_id = user_ta_get_instance_id,
  	.handle_svc = user_ta_handle_svc,
  #ifdef CFG_TA_GPROF_SUPPORT
  	.gprof_set_status = user_ta_gprof_set_status,
  #endif
  };
  ```

  - `enter_open_session()`
  - `user_ta_enter_open_session()`
  - `thread_enter_user_mode()`
  - `__thread_enter_user_mode()` (0x8d8)
  - `eret_to_user_mode()`
    - 執行到此時，virtual memory 的 base 會變成是 0x100000
    - 執行過程中還是 supervisor mode (10011)
    - 最後 `movs pc, lr` 執行結束後就會進 user mode (10001)



### TA internal

而當到達 userspace，實際上還沒直接執行 TA application，而是透過 `ldelf` 將其載入，因此最先執行的 binary 會是 `ldelf`，並且該檔案被包在 `bl32_extra.bin` 當中，並且透過下列腳本成功找到入口點：

```python
a = bytes.fromhex('e59f5050e28f4054')[::-1] # first 8 bytes instruction
b = open("bl32_extra1.bin", "rb").read()
print(hex(b.find(a)) # output 0x5f000
```

對應到的是原始碼中 `_ldelf_start` (ldelf/start_a32.S)，呼叫鏈如下：

- `_ldelf_start`
- `ldelf()` - 過程中會印出 `elf->load_addr`，即可與 binary offset 相加得到斷點位址
- TA - `start()`，實際上為原始碼當中的 `__ta_entry()`
- `__utee_entry()`
- `entry_open_session()`
- `TA_OpenSessionEntryPoint()` - 此 function 會由 user 自己實作，只需要滿足 optee 的 TA 框架即可

而關於 OpenSession、InvokeCommand 等實作，即是 TA 可能會出現問題的地方。



### TA 程式分析

#### OpenSession

當傳入的參數中帶有 0x1337 值的時候，OpenSession 的操作會印出與 flag 有關的字串，以下是部分程式碼：

```c
if ( *a2 == 0x1337 )
{
    sub_296A("TA_OpenSessionEntryPoint", 1095, 1, 1, "Showing you how to read the flag (it's a flag syscall!)...");
    get_flag_syscall(&v13, 32);
    sub_21ECC(&v13, 0, 32);
}
```

而 `get_flag_syscall()` 的 sys number 為 71，是由出題者自己實作，能夠讀 flag 進到參數的記憶體當中。實際怎麼讀的，必須先找出 trusted os 的 syscall table 並做對照，以下為 trusted os 的 syscall table：

```c
static const struct syscall_entry tee_svc_syscall_table[] = {
	SYSCALL_ENTRY(syscall_sys_return),
	SYSCALL_ENTRY(syscall_log),
    ...,
}
```

麻煩在於即使在 bl32_extra1.bin 當中找到關於 syscall 印出 flag 的字串，但是因為 syscall function 沒有被解析，因此沒辦法對相關程式碼做確認，而我的做法是先斷點在 `tee_ta_open_session()`，該 function 中會使用 `user_ta_ops` 全域變數，而該變數中的成員 `handle_svc` 指向 `user_ta_handle_svc()`，此 function 的實作會使用到 `tee_svc_syscall_table[]`：

```c
res = ts_ctx->ops->enter_open_session(&s->ts_sess);
```

最後找到偏移 0x8E020 的位址有大小為 72 的 function pointer array，並且最後一個 entry 指向 function `get_flag_syscall()`，內容為：

```c
void get_flag_syscall(int a1, unsigned int a2, int a3, int a4, int a5, int a6)
{
  if ( a2 > 0x18 )
    sub_4176E(a1, "FLAG{And the flag is...}", 25);
  __asm { POP             {R7,PC} }
}
```



### 參考文章

- [wallet 1/3](https://hackmd.io/@bata24/BJ3nuVEu5)
- [wallet 2/3](https://hackmd.io/@bata24/ry1_YS-c5)
- [wallet 3/3](https://hackmd.io/@bata24/HkZkcrW95)
