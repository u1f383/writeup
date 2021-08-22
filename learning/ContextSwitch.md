## Context Switch

[這篇文章](https://www.maizure.org/projects/evolution_x86_context_switch_linux/index.html)介紹了從 linux 0.1 ~ 4.14 的 context switch 演化，在此做一些筆記，建議搭配原文做為參照。

從 context switch 本身的需求來說，他要解決的就是在不同的 process 之間做切換，而相較如何切換，什麼時候切換就是 scheduler 的問題了，可以大致將 context switch 以簡單的幾個步驟概括:

1. Repointing the work space: Restore the stack (SS:SP)
   恢復下一個 process 的 work env - stack
2. Finding the next instruction: Restore the IP (CS:IP)
   將 userland 的 rip 指向下一個 process 離開時的 insn
3. Reconstructing task state: Restore the general purpose registers
   恢復其餘 register
4. Swapping memory address spaces: Updating page directory (CR3)
   改變 cr3 的值成下一個 process 的 page directory base
5. ...and more: FPUs, OS data structures, debug registers, hardware workarounds, etc
   剩下就是將其他執行環境給恢復，depend on 你使用/開啟的功能



#### Linux Pre-1.0 - Ancient History (1991)

一些重點 feature:

- hardware context switch - 透過 80386 內建的機制來切換 task
  - 80386 是晶片 - CPU
  - IA32 (x86) 是指令集
- 當時還只是 uniprocessing，只是 task 都可以 preemptive (可搶佔的)，因此在迅速的切換下讓人以為是電腦**同時**執行多個程式，此種機制也稱作多工 (multitasking)



##### Linux 0.01

```c
/** include/linux/sched.h */
#define switch_to(n) {
struct {long a,b;} __tmp;
__asm__(
  /* 比對下一個 task 是否與當前相同，ecx 為 ((long) task[n]) (見下方的 inline asm */
  "cmpl %%ecx,_current\n\t"
  "je 1f\n\t" /* 如果是 (ZF=1) 就不換 */
  "xchgl %%ecx,_current\n\t" /* swap 下個 task 成 _current */
  /**
   * dx 為 _TSS(n)，%1 代表 *&__tmp.b，將 dx 的值寫到 %1
   * 也就是把下個 task 的 segment pointer 放到 tmp.b
   * 而 _TSS(n) 確保最低的 byte 為 0 (最低的兩個 bit 代表 privilege (kernel)，第三個 bit 代表 GDT table，第四個 bit 代表 segment index)
   */
  "movw %%dx,%1\n\t"
  /**
   * 80386 提供的 hw context switch，主要就是跳到 TSS descriptor
   * 而他會以 struct {a,b} tmp 作為 base address (2 bytes selector (b) + 4 bytes offset (a))
   * (a 是 uninitialized value，只用來當 address reference)
   */
  "ljmp %0\n\t"
  /* %2 為 last_task_used_math，檢查被 swap 出去的 task 是否恢復 math coprocessor (輔助處理器 ?) ? */
  "cmpl %%ecx,%2\n\t"
  /* 如果沒有，則不清空 TS flag，等到真的要恢復時在清空 (lazy) */
  "jne 1f\n\t"
  /* 清除 TS flag */
  "clts\n"
  "1:"
  ::"m" (*&__tmp.a), /* %0 */
  "m" (*&__tmp.b), /* %1 */
  "m" (last_task_used_math),
  "d" _TSS(n), /* edx */
  "c" ((long) task[n])); /* ecx */
}
```

- 在 jump to TSS descriptor 之前，會確保以下幾點:

  - priv 為 kernel
  - TSS valid
  - 從 TR (task register) 取得 old TSS，並將 register 儲存在裡面
  - 更新 TR
  - 恢復 TR 指向的 TSS 的 saved register

- 由於 selector 的前 3 bits 用來放上面註解提到的資料，因此 index 從第四個 bit 開始計算，不過第一個 entry 的 index 為 4，以及 index 的 LSB 必定是 0 (強迫要偶數 index)，因此 index 的 order 會是 4 6 8 10...

  ```c
  #define _TSS(n) ((((unsigned long) n)<<4)+(FIRST_TSS_ENTRY<<3))
  #define FIRST_TSS_ENTRY 4
  ```

- `n` 為下個 task 的 index number

- `current` 與 `last_task_used_math` 為全域變數

- 下面是 c inline asm 的格式，細節可以參照[該文](https://www.codeproject.com/Articles/15971/Using-Inline-Assembly-in-C-C):

  ```
  asm <optional stuff> (
      "assembler template"
      : outputs
      : inputs
      : clobbers)
  ```

##### Linux 0.11

```c
/** include/linux/sched.h */
#define switch_to(n) {
struct {long a,b;} __tmp;
__asm__("cmpl %%ecx,_current\n\t"
  "je 1f\n\t"
  /* xchgl 與 movw 交換順序的原因為如果在 xchgl 後遇到 interrupt，則 task 都還沒儲存，但還是有機會在 xchgl 與 ljump 的過程中發生 context switch */
  "movw %%dx,%1\n\t"
  "xchgl %%ecx,_current\n\t"
  "ljmp %0\n\t"
  "cmpl %%ecx,_last_task_used_math\n\t" /* 直接把 _last_task_used_math 寫進 asm */
  "jne 1f\n\t"
  "clts\n"
  "1:"
  ::"m" (*&__tmp.a),
  "m" (*&__tmp.b),
  "d" (_TSS(n)),
  "c" ((long) task[n]));
}
```



#### Linux 1.x - Proof of concept (1994)

將近兩年的時間都沒什麼特別的更動，只有將 task 數量增長到 128。

##### Linux 1.0

```c
/** include/linux/sched.h */
#define switch_to(tsk) /* tsk point to next task's task_struct */
__asm__("cmpl %%ecx,_current\n\t"
	"je 1f\n\t"
	"cli\n\t" /* clear interrupt，也就是 disable interrupt */
	"xchgl %%ecx,_current\n\t"
	"ljmp %0\n\t"
	"sti\n\t" /* enable interrupt，也就是重新 enable interrupt */
	"cmpl %%ecx,_last_task_used_math\n\t"
	"jne 1f\n\t"
	"clts\n"
	"1:"
	: /* no output */
    /* tss.tr 存放 _TSS(task_number)，即是 GDT/TSS memory reference in pre 1.0 */
	:"m" (*(((char *)&tsk->tss.tr)-4)),
	 "c" (tsk)
	:"cx" /* Context switching clobbers the ECX register (?)，代表 inline asm 有使用到 cx register 吧 */)
```

- 參數不再是 index 而是 pointer



##### Linux 1.3

開始支援多個 arch，不過這邊只看 x86 version。

```c
/** include/asm-i386/system.h */
#define switch_to(tsk) do {
/* 不再比較是否相等，外部判斷式應該會確保 tsk 為不相等的 task */
__asm__("cli\n\t"
	"xchgl %%ecx,_current\n\t"
	"ljmp %0\n\t"
	"sti\n\t"
	"cmpl %%ecx,_last_task_used_math\n\t"
	"jne 1f\n\t"
	"clts\n"
	"1:"
	: /* no output */
	:"m" (*(((char *)&tsk->tss.tr)-4)),
	 "c" (tsk)
	:"cx");
	/* Now maybe reload the debug registers */
	if(current->debugreg[7]){
        /**
         * Restores the breakpoint debug registers from the saved ptrace state
         * 從 saved ptrace state 恢復 breakpoint debug registers
         */
		loaddebug(0);
		loaddebug(1);
		loaddebug(2);
		loaddebug(3);
        /**
         * Restores the status debug register from the saved ptrace state
         * 從 saved ptrace state 恢復 status debug register
         */
		loaddebug(6);
	}
} while (0)
```

- 變成了 `do {...} while(0)` 的形式，可以預防 macro expand 時的 syntax 問題
- 增加了 debug 的程式碼



#### Linux 2.x - Linux becomes a contender (1996)

linux 2.0 開始支援 multiprocessing:

- multiprocessing 強調的是可以在同一台電腦使用多個 CPU，讓多個 process 可以**同時間**的被執行
- multitasking 強調透過 **Context Switch** 來在多個 process 中切換執行

為了要實作 multiprocessing，每個 processor 引入專用的 interrupt controller (APIC, Advanced Programmable Interrupt Controller)，因此 disable interrupt 等等行為只會影響到同個 processor 的 process。而為了避免 kernel 中發生 race condition，因此也引入了 BKL (big kernel lock)。

由於硬體架構的改變，因此 `switch_to()` 分成了 uniprocessor (UP) 以及 symmetric multiprocessing (SMP) 的版本。



##### Linux 2.0.1 - Uniprocessing edition (UP)

```c
/** include/asm-i386/system.h */
#else  /* Single process only (not SMP) */
#define switch_to(prev,next) do { /* 新增了當前要被 switch 的 task 作為參數 (prev) */
__asm__(
    /**
     * %2 為 next，也就是下一個要執行的 task
     * 原本是 xchgl %%ecx,_current
     */
    "movl %2,"SYMBOL_NAME_STR(current_set)"\n\t"
	"ljmp %0\n\t"
	"cmpl %1,"SYMBOL_NAME_STR(last_task_used_math)"\n\t"
	"jne 1f\n\t"
	"clts\n"
	"1:"
	: /* no outputs */
	:"m" (*(((char *)&next->tss.tr)-4)),
	 "r" (prev), "r" (next)); /* 任何 register 都可以 */
	/* Now maybe reload the debug registers */
	if(prev->debugreg[7]){
		loaddebug(prev,0);
		loaddebug(prev,1);
		loaddebug(prev,2);
		loaddebug(prev,3);
		loaddebug(prev,6);
	}
} while (0)
#endif
```

- 改成 `SYMBOL_NAME_STR(current_set)` 的原因在於一些 assembler 如 GAS (GNU assembler) 會要求 c variable name 必須 prepend `_` (underscore)，避免寫死的方法就是多寫一個 macro



##### Linux 2.0.1 - Symmetric multiprocessing edition (SMP)

```c
/** include/asm-i386/system.h */
#ifdef __SMP__   /* Multiprocessing enabled */
#define switch_to(prev,next) do {
    cli(); /* disable interrupt*/
	/* 檢查是否有用 FPU */
    if(prev->flags&PF_USEDFPU)
    {
        /* 有的話在存就好，沒有的話就不需多此一舉 */
        /* 避免 optimizer 優化 */
        __asm__ __volatile__("fnsave %0":"=m" (prev->tss.i387.hard)); /* 將 FPU state 存到 TSS */
        __asm__ __volatile__("fwait"); /* busy wait when FPU 還在 save */
        prev->flags&=~PF_USEDFPU; /* 清空 USEDFPU bit */
    }
    prev->lock_depth=syscall_count; /* 記錄巢狀使用 kernel lock 的次數 */
    kernel_counter += next->lock_depth - prev->lock_depth; /* 更新 global counter */
    syscall_count=next->lock_depth; /* 更新下個 task 的狀態 */
__asm__(
    "pushl %%edx\n\t"
    /* 將 APIC I/O address 放到 edx，目的是要透過 APIC 得到 CPUID */
    "movl "SYMBOL_NAME_STR(apic_reg)",%%edx\n\t"
    /* 取得 APIC ID register */
    "movl 0x20(%%edx), %%edx\n\t"
    /* 因為 APIC ID 在 24~27 bit，shift 22 後會在 2~5 bit，也就是 APIC ID * 4 (CPUID 應該 == APIC ID) */
    "shrl $22,%%edx\n\t"
    "and  $0x3C,%%edx\n\t"
    /* 留一個 4 倍的原因是 pointer size，把 next (in ecx) 放到 current_set + index (edx) 的位置 */
    "movl %%ecx,"SYMBOL_NAME_STR(current_set)"(,%%edx)\n\t"
    /* recover edx */
    "popl %%edx\n\t"
    "ljmp %0\n\t"
    "sti\n\t" /* enable interrupt */
    : /* no output */
    :"m" (*(((char *)&next->tss.tr)-4)),
     "c" (next));
    /* Now maybe reload the debug registers */
    if(prev->debugreg[7]){
        loaddebug(prev,0);
        loaddebug(prev,1);
        loaddebug(prev,2);
        loaddebug(prev,3);
        loaddebug(prev,6);
    }
} while (0)
```



##### Linux 2.2 (1999)

**software context switching** !! 不再使用 80386 提供的 `ljmp` 做 context switch，並且合併 UP 以及 SMP，都使用 `switch_to()` 來 handle:

```c
/** include/asm-i386/system.h */
#define switch_to(prev,next) do {
    unsigned long eax, edx, ecx;
    asm volatile("pushl %%ebx\n\t"
                 "pushl %%esi\n\t"
                 "pushl %%edi\n\t"
                 "pushl %%ebp\n\t"
                 /* %0 是 prev->tss.esp */
                 "movl %%esp,%0\n\t" /* save ESP */
                 /* %5 是 next->tss.esp */
                 "movl %5,%%esp\n\t" /* restore ESP */
                 /* %1 是 prev->tss.eip，而 $1f 會是 1: 的位置 */
                 "movl $1f,%1\n\t"   /* save EIP */
                 /* %6 是 next->tss.eip，將 ip push 到 stack 當中，當 ret 時就會執行到 */
                 "pushl %6\n\t"      /* restore EIP */
                 "jmp __switch_to\n"
                 "1:\t"
                 "popl %%ebp\n\t"
                 "popl %%edi\n\t"
                 "popl %%esi\n\t"
                 "popl %%ebx"
                 :"=m" (prev->tss.esp),"=m" (prev->tss.eip),
                  "=a" (eax), "=d" (edx), "=c" (ecx)
                 :"m" (next->tss.esp),"m" (next->tss.eip),
                  "a" (prev), "d" (next));
} while (0)
```

- inline asm 的 `%<number>` 是從 output --> input 開始遞增

有另一個 C source 的版本:

```c
/** arch/i386/kernel/process.c */
void __switch_to(struct task_struct *prev, struct task_struct *next)
{
    /* Do the FPU save and set TS if it wasn't set before.. */
    unlazy_fpu(prev); /* 沒用到就不需要存 */

    /* 清除 task descriptor 的 busy bit，tr 為 task register */
    gdt_table[next->tss.tr >> 3].b &= 0xfffffdff;
    /* 將指向下個 task 的 segment selector (tr) 載入到 task register (load task register) */
    asm volatile("ltr %0": :"g" (*(unsigned short *)&next->tss.tr));

    /**
     * After linux 2.6,
     * FS - thread local storage
     * GS - Per-processor Data Areas
     * 不過現在沒用到還是放了
     */
    asm volatile("movl %%fs,%0":"=m" (*(int *)&prev->tss.fs));
    asm volatile("movl %%gs,%0":"=m" (*(int *)&prev->tss.gs));

    /* Re-load LDT if necessary */
    /* 如果 segment 不相同，代表必須更新 ldt (local descriptor table */
    if (next->mm->segments != prev->mm->segments)
        asm volatile("lldt %0": :"g" (*(unsigned short *)&next->tss.ldt));

    /* Re-load page tables */
    /** 
     * 如果 cr3 不相同，代表必須更新 cr3，存放 page directory table 
     * 而 smep, smap 是存放在 cr4
     */
    {
        unsigned long new_cr3 = next->tss.cr3;
        if (new_cr3 != prev->tss.cr3)
            asm volatile("movl %0,%%cr3": :"r" (new_cr3));
    }

    /* Restore %fs and %gs. */
    /* 恢復下個 task 的 fs 與 gs */
    loadsegment(fs,next->tss.fs);
    loadsegment(gs,next->tss.gs);

    if (next->tss.debugreg[7]){
        loaddebug(next,0);
        loaddebug(next,1);
        loaddebug(next,2);
        loaddebug(next,3);
        loaddebug(next,6);
        loaddebug(next,7);
    }
}
```



##### Linux 2.4 (2001)

linux 2.4 又多了一些功能，像是 kernel thread、task queue，其中 `switch_to()` 也有做些為調整:

```c
/** include/asm-i386/system.h */

/* last 的值與 prev 相同，不過目前沒使用到 */
#define switch_to(prev,next,last) do {
    asm volatile("pushl %%esi\n\t"
        "pushl %%edi\n\t"
        "pushl %%ebp\n\t"
        "movl %%esp,%0\n\t"	/* save ESP */
        "movl %3,%%esp\n\t"	/* restore ESP */
        "movl $1f,%1\n\t"		/* save EIP */
        "pushl %4\n\t"		/* restore EIP */
        "jmp __switch_to\n"
        "1:\t"
        "popl %%ebp\n\t"
        "popl %%edi\n\t"
        "popl %%esi\n\t"
        :"=m" (prev->thread.esp),"=m" (prev->thread.eip),
         "=b" (last)
        :"m" (next->thread.esp),"m" (next->thread.eip),
         "a" (prev), "d" (next),
         "b" (prev));
} while (0)
```

- 不再存 `ebx`，不過 `last` 會透過 `ebx` 傳入

C source:

```c
/** arch/i386/kernel/process.c */
/* 參數有 _p 的 appended，因為 prev 與 next 給 thread_struct 用了 */
void __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
    /* pointers to the TSS data for each task */
	struct thread_struct *prev = &prev_p->thread,
				 *next = &next_p->thread;
	
	struct tss_struct *tss = init_tss + smp_processor_id();

	unlazy_fpu(prev_p);

	tss->esp0 = next->esp0; /* 更新 ring0 的 stack offset，page 不須 reload (?) */

	asm volatile("movl %%fs,%0":"=m" (*(int *)&prev->fs));
	asm volatile("movl %%gs,%0":"=m" (*(int *)&prev->gs));

	/* Restore %fs and %gs. */
	loadsegment(fs, next->fs);
	loadsegment(gs, next->gs);

	/* Now maybe reload the debug registers */
	if (next->debugreg[7]){
		loaddebug(next, 0);
		loaddebug(next, 1);
		loaddebug(next, 2);
		loaddebug(next, 3);
		/* no 4 and 5 (多加了一行註解 XD) */
		loaddebug(next, 6);
		loaddebug(next, 7);
	}

    /* io permission */
	if (prev->ioperm || next->ioperm) {
		if (next->ioperm) {
			memcpy(tss->io_bitmap, next->io_bitmap,
				 IO_BITMAP_SIZE*sizeof(unsigned long));
            /* 設置 next task 對 port-mapped I/O 的 permission */
			tss->bitmap = IO_BITMAP_OFFSET;
		} else
            /* 如果是當前有但下個沒有，就設為 invalid (0x8000) */
			tss->bitmap = INVALID_IO_BITMAP_OFFSET;
	}
}
```

- 不再使用 tr，而是使用當前 processor 的 tss `tss_struct` (Task state segment) 來存取 per-cpu 的資料



#### Linux 2.6 - Linux goes mainstream (2003)

linux 2.6.0 為 `O(1)` scheduler 的到來，但是在 2.6.23 就被取代成 CFS (Completely-Fair Scheduler)，同時 `switch_to()` 也開始有 x86_64 的版本。

```c
/** include/asm-i386/system.h */
#define switch_to(prev,next,last) do {
    unsigned long esi,edi;
    asm volatile("pushfl\n\t"
            "pushl %%ebp\n\t"
            "movl %%esp,%0\n\t"	 /* save ESP */
            "movl %5,%%esp\n\t" /* restore ESP */
            "movl $1f,%1\n\t"   /* save EIP */
            "pushl %6\n\t"	     /* restore EIP */
            "jmp __switch_to\n"
            "1:\t"
            "popl %%ebp\n\t"
            "popfl"
            :"=m" (prev->thread.esp),"=m" (prev->thread.eip),
             "=a" (last),"=S" (esi),"=D" (edi)
            :"m" (next->thread.esp),"m" (next->thread.eip),
             "2" (prev), "d" (next));
} while (0)
```

- `push/pop `+ `esi/edi` 被 remove，原因是 they are carried through the I/O operands，有點沒看很懂

C source:

```c
/** arch/i386/kernel/process.c */
/* 會回傳 task_struct * 了 */
struct task_struct * __switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
    struct thread_struct *prev = &prev_p->thread,
                 *next = &next_p->thread;
    int cpu = smp_processor_id();
    struct tss_struct *tss = init_tss + cpu;

    __unlazy_fpu(prev_p);

    load_esp0(tss, next->esp0);

    /* Load the per-thread Thread-Local Storage descriptor. */
    /* 更新 tls descriptor in GDT */
    load_TLS(next, cpu);

    asm volatile("movl %%fs,%0":"=m" (*(int *)&prev->fs));
    asm volatile("movl %%gs,%0":"=m" (*(int *)&prev->gs));

    /* Restore %fs and %gs if needed. */
    /* 開始出現 unlikely */
    /* 如果當前與下個 task 只要有用 fs or gs 其一，就要恢復成下個 task 的狀態 */
    if (unlikely(prev->fs | prev->gs | next->fs | next->gs)) {
        loadsegment(fs, next->fs);
        loadsegment(gs, next->gs);
    }

    /* Now maybe reload the debug registers */
    if (unlikely(next->debugreg[7])) {
        loaddebug(next, 0);
        loaddebug(next, 1);
        loaddebug(next, 2);
        loaddebug(next, 3);
        /* no 4 and 5 */
        loaddebug(next, 6);
        loaddebug(next, 7);
    }

    if (unlikely(prev->io_bitmap_ptr || next->io_bitmap_ptr)) {
        if (next->io_bitmap_ptr) {
            memcpy(tss->io_bitmap, next->io_bitmap_ptr,
                IO_BITMAP_BYTES);
            tss->io_bitmap_base = IO_BITMAP_OFFSET;
        } else
            tss->io_bitmap_base = INVALID_IO_BITMAP_OFFSET;
    }
    /* 回傳的是舊的 task pointer */
    return prev_p;
}
```

- `unlikely` or `likely` 都是用來讓 code generator 知道哪個 BB 會先出現 (likely 就會傾向猜測進入)，因此幫助 pipelining 的執行
- function convention 似乎有一個規定，在 function 會影響 (or 更新/切換) 到 state 時，就必須回傳上一個 state
- linux 2.6 引進了 3 個 TLS entries in GDT，目的是提供 thread-specified 的 segment
  - 1 - glibc
  - 2 - Wine
  - 而同時 linux 2.6 也可以用 `FS` segment register 存取到 TLS 了



##### Linux 2.6.0 (x86_64 inline assembly)

```c
/** include/asm-x86_64/system.h */

#define SAVE_CONTEXT    "pushfq ; pushq %%rbp ; movq %%rsi,%%rbp\n\t"
#define RESTORE_CONTEXT "movq %%rbp,%%rsi ; popq %%rbp ; popfq\n\t" 
#define __EXTRA_CLOBBER
    ,"rcx","rbx","rdx","r8","r9","r10","r11","r12","r13","r14","r15"

#define switch_to(prev,next,last)
    asm volatile(SAVE_CONTEXT
          "movq %%rsp,%P[threadrsp](%[prev])\n\t" /* save RSP */
          "movq %P[threadrsp](%[next]),%%rsp\n\t" /* restore RSP */
          "call __switch_to\n\t"
          ".globl thread_return\n"
          "thread_return:\n\t"
          "movq %%gs:%P[pda_pcurrent],%%rsi\n\t"
          "movq %P[thread_info](%%rsi),%%r8\n\t"
          "btr  %[tif_fork],%P[ti_flags](%%r8)\n\t"
          "movq %%rax,%%rdi\n\t"
          "jc   ret_from_fork\n\t"
          RESTORE_CONTEXT
          : "=a" (last)
          : [next] "S" (next), [prev] "D" (prev),
            [threadrsp] "i" (offsetof(struct task_struct, thread.rsp)),
            [ti_flags] "i" (offsetof(struct thread_info, flags)),
            [tif_fork] "i" (TIF_FORK),
            [thread_info] "i" (offsetof(struct task_struct, thread_info)),
            [pda_pcurrent] "i" (offsetof(struct x8664_pda, pcurrent))
          : "memory", "cc" __EXTRA_CLOBBER)
```

