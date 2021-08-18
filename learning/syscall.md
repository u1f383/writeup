## Syscall

Syscall 是 userland 要向 kernel 請求更高權限的服務時使用的方法，網路上已經有許多關於 syscall 功能的介紹，而這邊是紀錄動態追蹤的過程。



當執行完 `syscall`，userland 會切到 kernel mode `SYM_CODE_START(entry_SYSCALL_64)` 去執行 ([src](https://elixir.bootlin.com/linux/v5.13.11/source/arch/x86/entry/entry_64.S#L87)):

```asm
SYM_CODE_START(entry_SYSCALL_64)
	UNWIND_HINT_EMPTY

	/**
	 * Exchanges the current GS base register value with the value contained in MSR address C0000102H
	 * 可以想像成切換成 kernel mode 的 GS
	 */
	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2) /* 儲存舊的 rsp */
	/* 更新新的 rsp */
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

SYM_INNER_LABEL(entry_SYSCALL_64_safe_stack, SYM_L_GLOBAL)

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS				/* pt_regs->ss */
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)	/* pt_regs->sp */
	pushq	%r11					/* pt_regs->flags */
	pushq	$__USER_CS				/* pt_regs->cs */
	pushq	%rcx					/* pt_regs->ip */
SYM_INNER_LABEL(entry_SYSCALL_64_after_hwframe, SYM_L_GLOBAL)
	pushq	%rax					/* pt_regs->orig_ax */

	/* 把幾乎所有的 register push 上 stack，並且清空所有的 register */
	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	/* IRQs are off. */
	/* 雖然說 IRQ off，不過也沒看到 sti 等等 insn */
	movq	%rax, %rdi
	movq	%rsp, %rsi
	/* 真正執行 syscall，rdi 為 syscall number */
	call	do_syscall_64		/* returns with IRQs disabled */
	...
```



執行 `do_syscall_64` ([src](https://elixir.bootlin.com/linux/v5.13.11/source/arch/x86/entry/common.c#L39)):

```c
#ifdef CONFIG_X86_64
__visible noinstr void do_syscall_64(unsigned long nr, struct pt_regs *regs)
{
	add_random_kstack_offset(); /* 也沒特別做什麼? */
	nr = syscall_enter_from_user_mode(regs, nr);

	instrumentation_begin();
	if (likely(nr < NR_syscalls)) { /* NR_syscalls == 446*/
		nr = array_index_nospec(nr, NR_syscalls);
        /* sys_call_table[nr] 會得到 syscall function，而傳入 regs 作為參數 */
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

- `syscall_enter_from_user_mode` ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/entry/common.c#L100)):

  ```c
  noinstr long syscall_enter_from_user_mode(struct pt_regs *regs, long syscall)
  {
  	long ret;
  
  	__enter_from_user_mode(regs); /* 過程中會執行到 sti，不過不是要 disable 嗎 @_@ ? */
  
  	instrumentation_begin();
  	local_irq_enable();
  	ret = __syscall_enter_from_user_work(regs, syscall);
  	instrumentation_end();
  
  	return ret;
  }
  ```

  做的事情參考在 [entry-common.h](https://elixir.bootlin.com/linux/v5.13.11/source/include/linux/entry-common.h#L102) 的註解: _Syscall/interrupt entry disables interrupts, but user mode is traced as interrupts enabled_，所以會執行 `sti` 來 enable interrupt (?)。最後 `local_irq_enable()` 會執行 ([src](https://elixir.bootlin.com/linux/v5.13.11/source/arch/x86/include/asm/irqflags.h#L43)):

  ```c
  static __always_inline void native_irq_enable(void)
  {
  	asm volatile("sti": : :"memory");
  }
  
  static __always_inline void arch_local_irq_enable(void)
  {
  	native_irq_enable();
  }
  ```

- 離開時會執行 `syscall_exit_to_user_mode()` ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/entry/common.c#L299)):

  ```c
  __visible noinstr void syscall_exit_to_user_mode(struct pt_regs *regs)
  {
  	instrumentation_begin();
  	__syscall_exit_to_user_mode_work(regs); /* 會執行 cli @__@... */
  	instrumentation_end();
  	__exit_to_user_mode();
  }
  ```

  `__syscall_exit_to_user_mode_work()` 會執行 `cli` clear interrupt bit (?):

  ```c
  static __always_inline void __syscall_exit_to_user_mode_work(struct pt_regs *regs)
  {
  	syscall_exit_to_user_mode_prepare(regs);
  	local_irq_disable_exit_to_user();
  	exit_to_user_mode_prepare(regs);
  }
  ```

  - 對應的註釋都在 `include/linux/entry-common.h` 此 header file，大概的意思就是為了 exit to user 做一些準備
  - 其實過程中很多 function 展開都是 nop，不然就是 jmp 掉 or inline function，滿難追的 @_@

下半段的 `SYM_CODE_START(entry_SYSCALL_64)`:

```asm
	...
	/*
	 * Try to use SYSRET instead of IRET if we're returning to
	 * a completely clean 64-bit userspace context.  If we're not,
	 * go to the slow exit path.
	 * In the Xen PV case we must use iret anyway.
	 */

	ALTERNATIVE "", "jmp	swapgs_restore_regs_and_return_to_usermode", \
		X86_FEATURE_XENPV

	movq	RCX(%rsp), %rcx
	movq	RIP(%rsp), %r11

	cmpq	%rcx, %r11	/* SYSRET requires RCX == RIP */
	jne	swapgs_restore_regs_and_return_to_usermode
	
#ifdef CONFIG_X86_5LEVEL
	ALTERNATIVE "shl $(64 - 48), %rcx; sar $(64 - 48), %rcx", \
		"shl $(64 - 57), %rcx; sar $(64 - 57), %rcx", X86_FEATURE_LA57
#else
	shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
	sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
#endif

	/* If this changed %rcx, it was not canonical */
	cmpq	%rcx, %r11
	jne	swapgs_restore_regs_and_return_to_usermode

	cmpq	$__USER_CS, CS(%rsp)		/* CS must match SYSRET */
	jne	swapgs_restore_regs_and_return_to_usermode

	movq	R11(%rsp), %r11
	cmpq	%r11, EFLAGS(%rsp)		/* R11 == RFLAGS */
	jne	swapgs_restore_regs_and_return_to_usermode

	testq	$(X86_EFLAGS_RF|X86_EFLAGS_TF), %r11
	jnz	swapgs_restore_regs_and_return_to_usermode

	/* nothing to check for RSP */

	cmpq	$__USER_DS, SS(%rsp)		/* SS must match SYSRET */
	jne	swapgs_restore_regs_and_return_to_usermode

/* 到這邊代表資料沒被更動，也確定是透過 sysret 回去 */
syscall_return_via_sysret:
	/* rcx and r11 are already restored (see code above) */
	/* 把其他 register 恢復 */
	POP_REGS pop_rdi=0 skip_r11rcx=1

	/*
	 * Now all regs are restored except RSP and RDI.
	 * Save old stack pointer and switch to trampoline stack.
	 */
	movq	%rsp, %rdi
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
	UNWIND_HINT_EMPTY

	pushq	RSP-RDI(%rdi)	/* RSP */
	pushq	(%rdi)		/* RDI */

	/*
	 * We are on the trampoline stack.  All regs except RDI are live.
	 * We can do future final exit work right here.
	 */
	STACKLEAK_ERASE_NOCLOBBER

	SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi

	popq	%rdi
	popq	%rsp
	swapgs
	sysretq /* 正式回到 usermode */
SYM_CODE_END(entry_SYSCALL_64)
```

- 一開始會做一堆得比較，過程中若發生一些情況，會使用 `swapgs_restore_regs_and_return_to_usermode` 來 return 回 usermode

  - `rcx != r11` - 代表 rcx 在過程中有被修改到
  - `CS` 跟 `SS` 都不是 `sysret`
  - `R11 != RFLAGS`
  - 執行 syscall slowpath 時把 RFLAGS 的 `RF` 設成 1 (正常情況要是 0)，需要透過 `swapgs_restore_regs_and_return_to_usermode` 恢復
  - RFLAGS 的 `TF` 為 1，但是直接恢復 usermode `TF` 為 1 的話會產生 trap

  

其他

- `pushfq` - Push EFLAGS Register onto the Stack (f 指的是 flags)
- `lfence` - `__x86_indirect_thunk_rax` 會執行到，功能為: LFENCE does not execute **until all prior instructions have completed locally**, and **no later instruction begins execution until LFENCE completes**，就是用來當 memory barrier
- `cdqe` - 此 insn 與 `cbw` , `cwde` , `cqo` 是同一組，分別為 convert D->Q / B->W / W->D / Q->O (128)，不太確定 `cdq` 與 `cdqe` 的差別



為什麼 syscall 進入時執行 `sti`，離開時執行 `cli` 呢 @_@? `instrumentation_begin()` 跟 `instrumentation_end()` 又有什麼功能?