在真正執行我們編譯的 binary 之前，c runtime 會幫我們加一段 `_start` 程式碼，然而在 c runtime 幫我們加載前其實還有一些事情是由 linker 幫我們完成的，以下就從 dl 的 entry point 開始做分析。

[macro RTLD_START](https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/x86_64/dl-machine.h#L141) 的註解中提到 **"Initial entry point code for the dynamic linker"**，由此可知這個 macrot 下方定義的 **_start** 就是 dl 的程式進入點，source code 中的註解也解釋得相當完善：

```asm
#define RTLD_START asm ("\n\
.text\n\
	.align 16\n\
.globl _start\n\
.globl _dl_start_user\n\

# 此即是 dl 的進入點
_start:\n\
	movq %rsp, %rdi\n\
	call _dl_start\n\
	# 到此已經動態連結完畢
_dl_start_user:\n\
	# 將 user ep 放到 r12 當中，也就是 binary 的 _start
	movq %rax, %r12\n\
	# See if we were run as a command with the executable file\n\
	# name as an extra leading argument.\n\
	movl _dl_skip_args(%rip), %eax\n\
	# Pop the original argument count.\n\
	popq %rdx\n\
	# Adjust the stack pointer to skip _dl_skip_args words.\n\
	leaq (%rsp,%rax,8), %rsp\n\
	# Subtract _dl_skip_args from argc.\n\
	subl %eax, %edx\n\
	# Push argc back on the stack.\n\
	pushq %rdx\n\
	# Call _dl_init (struct link_map *main_map, int argc, char **argv, char **env)\n\
	# argc -> rsi\n\
	movq %rdx, %rsi\n\
	# Save %rsp value in %r13.\n\
	movq %rsp, %r13\n\
	# And align stack for the _dl_init call. \n\
	andq $-16, %rsp\n\
	# _dl_loaded -> rdi\n\
	movq _rtld_local(%rip), %rdi\n\
	# env -> rcx\n\
	leaq 16(%r13,%rdx,8), %rcx\n\
	# argv -> rdx\n\
	leaq 8(%r13), %rdx\n\
	# Clear %rbp to mark outermost frame obviously even for constructors.\n\
	xorl %ebp, %ebp\n\
	# Call the function to run the initializers.\n\
	# 怎...怎麼還要 init
	call _dl_init\n\
	
	# Pass our finalizer function to the user in %rdx, as per ELF ABI.\n\
	leaq _dl_fini(%rip), %rdx\n\
	# And make sure %rsp points to argc stored on the stack.\n\
	movq %r13, %rsp\n\
	# Jump to the user's entry point.\n\
	jmp *%r12\n\
.previous\n\
");
```

再來分析 `_dl_start()` ([source](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/rtld.c#L462))，在此之前可以先了解 `Elf64_Dyn` 結構長得怎樣，並且下方也有補充一些在分析時會使用到的 macro：

```c
typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;

#ifdef DONT_USE_BOOTSTRAP_MAP
# define bootstrap_map GL(dl_rtld_map)
// _rtld_global._dl_rtld_map
#else
  struct dl_start_final_info info;
# define bootstrap_map info.l
#endif

//---------
#ifndef SHARED
# define EXTERN extern
# define GL(name) _##name
#else
# define EXTERN
# if IS_IN (rtld)
#  define GL(name) _rtld_local._##name
# else
#  define GL(name) _rtld_global._##name
# endif

//----------
#ifdef DONT_USE_BOOTSTRAP_MAP
    // default
    ElfW(Addr) entry = _dl_start_final (arg);
...
    
//----------
#ifndef SHARED
# define GLRO(name) _##name
#else
# if IS_IN (rtld)
#  define GLRO(name) _rtld_local_ro._##name
# else
#  define GLRO(name) _rtld_global_ro._##name
# endif
//----------
#define __RTLD_DLOPEN	0x80000000
#define __RTLD_SPROF	0x40000000
#define __RTLD_OPENEXEC	0x20000000
#define __RTLD_CALLMAP	0x10000000
#define __RTLD_AUDIT	0x08000000
#define __RTLD_SECURE	0x04000000
#define __RTLD_NOIFUNC	0x02000000

#define GL(name) _rtld_global._##name
// _rtld_global 定義在 https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/rtld.c#L278
/* This is the structure which defines all variables global to ld.so
   (except those which cannot be added for some reason).  */
struct rtld_global _rtld_global =
  {
    ._dl_stack_flags = DEFAULT_STACK_PERMS,
	...
    ._dl_nns = 1,
    ._dl_ns = ...
  };

// https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/generic/ldsodefs.h#L308
struct rtld_global
{
	...   
}
```

`_dl_start()` 會先執行一個 inline function `elf_get_dynamic_info()` ，主要是 parse ld ELF 的整個結構，其第一個 while loop 在用 `d_tag` 來區分動態資料的型別：

```c
inline void __attribute__ ((unused, always_inline))
elf_get_dynamic_info (struct link_map *l, ElfW(Dyn) *temp)
{
  // l->l_addr 的值為整個 ELF 的開頭
  // no-aslr 的情況下為 0x7ffff7fd1000
    
  ElfW(Dyn) *dyn = l->l_ld;
  ElfW(Dyn) **info;
  while (dyn->d_tag != DT_NULL)
    {
      if ((d_tag_utype) dyn->d_tag < DT_NUM)
		info[dyn->d_tag] = dyn;
      else if (dyn->d_tag >= DT_LOPROC
	       && dyn->d_tag < DT_LOPROC + DT_THISPROCNUM)
	{
	  ...
	}
      ...
      ++dyn;
    }
```

再來是對裡面的一些 address 資料加上 base address，結束後做了一堆 `assert()` 確保資料無誤：

```c
      ADJUST_DYN_INFO (DT_HASH);
      ADJUST_DYN_INFO (DT_PLTGOT);
      ...
```

再來是 `_dl_start()` 的下半部分，註解說下半部分被放到 `_dl_start_final()` ([source code](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/rtld.c#L407))當中：

```c
static inline ElfW(Addr) __attribute__ ((always_inline))
_dl_start_final (void *arg)
{
  ElfW(Addr) start_addr;
    
  ... // set timer

  ...
  // Cache the location of MAP's hash table
  _dl_setup_hash (&GL(dl_rtld_map));
  ... // some init

  // put stack addr into ld variable __libc_stack_end
  __libc_stack_end = __builtin_frame_address (0);

  // 此為 OS-dependent function，實際上會呼叫 dl_main() 來完成 dl 做的事情
  // https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/dl-sysdep.c#L86
  start_addr = _dl_sysdep_start (arg, &dl_main); 

  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_STATISTICS))
    {
      RTLD_TIMING_VAR (rtld_total_time);
      rtld_timer_stop (&rtld_total_time, start_time);
      print_statistics (RTLD_TIMING_REF(rtld_total_time));
    }

  return start_addr; // start_addr 即是 _start
}
```

`_dl_sysdep_start()` 為 OS dependent function：

```c
// _rtld_global_ro._dl_auxv
ElfW(Addr)
_dl_sysdep_start (void **start_argptr,
		  void (*dl_main) (const ElfW(Phdr) *phdr, ElfW(Word) phnum,
				   ElfW(Addr) *user_entry, ElfW(auxv_t) *auxv))
{
    ...
    // traverse 所有 auxiliary vector
    for (av = GLRO(dl_auxv); av->a_type != AT_NULL; set_seen (av++))
    switch (av->a_type)
      {
      ...
      case AT_SECURE:
        // setting __libc_enable_secure if we need to be secure (e.g. setuid)
		__libc_enable_secure = av->a_un.a_val;
	break;
      }
    
    // Initialize the tunables list from the environment (可變動的一些環境變數)
    // ld.so --list-tunables (since 2.33)
    // Detail: https://www.gnu.org/software/libc/manual/html_node/Tunables.html
    // attr defined in variable "tunable_list"
    __tunables_init (_environ);

    // call brk() to initialize the break
    DL_SYSDEP_INIT;

    // https://elixir.bootlin.com/glibc/glibc-2.31/source/sysdeps/x86_64/dl-machine.h#L223
    // 初始化 cpu featue (by cpuid)
    DL_PLATFORM_INIT;
    
    // get dl_platform namd (e.g. "dl_platform")
    GLRO(dl_platformlen) = strlen (GLRO(dl_platform));
	...
        
    (*dl_main) (phdr, phnum, &user_entry, GLRO(dl_auxv));
    return user_entry; // user entry 即是 _start
```

而後呼叫 `dl_main()` ([source](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/rtld.c#L1086))：

```c
static void
dl_main (const ElfW(Phdr) *phdr,
	 ElfW(Word) phnum,
	 ElfW(Addr) *user_entry,
	 ElfW(auxv_t) *auxv)
{
    ...
    // _dl_make_stack_executable 可以讓 stack 變成 executable
    // _rtld_global._dl_make_stack_executable_hook
	GL(dl_make_stack_executable_hook) = &_dl_make_stack_executable;
    // Process all environments variables the dynamic linker must recognize
    // env 要有 LD_ 作為 prefix
 	process_envvars (&mode);
    
    // 直接執行 ld.so
    if (*user_entry == (ElfW(Addr)) ENTRY_POINT)
    {
     	...   
    }
    else
    {
        // 建立一個屬於 executable 本身的 link_map + 初始化一些資料
     	main_map = ...;
    }
    /* Scan the program header table for the dynamic section.  */
    // 再來就是 for loop traverse 所有的 dynamic section
    for (ph = phdr; ph < &phdr[phnum]; ++ph)
    {
        // 這個部分滿有趣的，不過只列出幾項而已
        case PT_LOAD: ...;
        case PT_TLS: ...;
        case PT_GNU_STACK: ...;
        // _dl_rtld_libname.name == /usr/src/glibc/glibc_dbg/elf/ld.so
    }
    /* If the current libname is different from the SONAME, add the
     latter as well.  */
    if (...)
    {
      static struct libname_list newname;
      newname.name = ...; // ld-linux-x86-64.so.2
      newname.next = NULL;
      newname.dont_free = 1;

      assert (GL(dl_rtld_map).l_libname->next == NULL);
      GL(dl_rtld_map).l_libname->next = &newname;
    }
    
    if (! rtld_is_main) // 如果有 dl 本身並非要執行的 executable 的話
    {
      elf_get_dynamic_info (main_map, NULL);
      _dl_setup_hash (main_map);
    }

  	struct link_map **first_preload = &GL(dl_rtld_map).l_next;
    // setup vdso 的結構
	setup_vdso (main_map, &first_preload);
	// 要更新的 pointer 像是 __vdso_clock_gettime()
    // sysdeps/unix/sysv/linux/dl-vdso-setup.h
    setup_vdso_pointers ();
    
    // 初始化 shared object 的 search paths，平常用不到
    _dl_init_paths (library_path);
    
    ... // 一大坨 code，跟 debug / library 的 loading / audit 相關
    if (__glibc_unlikely (preloadlist != NULL))
    {
      // 此時 mmap ld-preload glibc library
      npreloads += handle_preload_list (preloadlist, main_map, "LD_PRELOAD");
      // do_preload() --> _dl_catch_error() --> _dl_catch_exception() --> map_doit() --> _dl_map_object() --> _dl_map_object_from_fd() --> _dl_new_object() --> calloc() --> malloc() --> mmap()
      // _dl_new_object() 底層會呼叫到 mmap()，這也是為什麼 mmap 建立出來的 memory 都有固定的 offset
    }
  ...
  // DT_NEEDED 紀錄 library dependency (in dynamic segment)
  {
    _dl_map_object_deps (main_map, preloads, npreloads, mode == trace, 0);
  }
  ...
  // not initialize any of the TLS functionality unless any of the initial modules uses TLS
  if (tcbp == NULL)
      tcbp = init_tls (); // --> _dl_allocate_tls_storage() --> malloc()
    
  security_init(); // 初始化 canary / ptr guard
  _rtld_main_check(); // Control-Flow Enforcement Technology checking (dl_cet_check)
    ...
    // traverse 每個 link_map，看是否需要 relocate
	while (i-- > 0)
	{
	  struct link_map *l = main_map->l_initfini[i];

	  /* While we are at it, help the memory handling a bit.  We have to
	     mark some data structures as allocated with the fake malloc()
	     implementation in ld.so.  */
	  struct libname_list *lnp = l->l_libname->next;

	  while (__builtin_expect (lnp != NULL, 0))
	    {
	      lnp->dont_free = 1;
	      lnp = lnp->next;
	    }
	  /* Also allocated with the fake malloc().  */
	  l->l_free_initfini = 0;

	  if (l != &GL(dl_rtld_map))
        // got 就是在這邊被初始化的
	    _dl_relocate_object (l, l->l_scope, GLRO(dl_lazy) ? RTLD_LAZY : 0,
				 consider_profiling);

	  /* Add object to slot information data if necessasy.  */
	  if (l->l_tls_blocksize != 0 && tls_init_tp_called)
	    _dl_add_to_slotinfo (l, true);
	}
    ...
    _dl_allocate_tls_init (tcbp); // 到此因為已經完成 relocation，因此可以初始化 tls 了
    
    ...
    // cleanups for the startup OS interface code，正常情況直接 ret
    _dl_sysdep_start_cleanup ();
    // notify the debugger all new objects are now ready to go
   	... // 一些與 debuggin 相關的操作
}
```

`_dl_map_object_from_fd()` 會呼叫 `_dl_map_segments()`，分配 libc.so 相關的記憶體區塊 ([source code](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/dl-map-segments.h#L29))：

```c
static __always_inline const char *
_dl_map_segments (struct link_map *l, int fd,
                  const ElfW(Ehdr) *header, int type,
                  const struct loadcmd loadcmds[], size_t nloadcmds,
                  const size_t maplength, bool has_holes,
                  struct link_map *loader)
{
    ...
    /* Remember which part of the address space this object uses.  */
      l->l_map_start = (ElfW(Addr)) __mmap ((void *) mappref, maplength,
                                            c->prot,
                                            MAP_COPY|MAP_FILE,
                                            fd, c->mapoff);

 	... // 多個 mmap
}
```

`security_init()` 當中初始化了 `stack_chk_guard` (canary)  / `pointer_chk_guard`：

```c
static void
security_init (void)
{
  /* Set up the stack checker's canary.  */
  // 值為 _dl_random + 0 ~ 0x7
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
  THREAD_SET_STACK_GUARD (stack_chk_guard);
  __stack_chk_guard = stack_chk_guard;

  // 值其實就是 _dl_random + 8 ~ 0xf
  uintptr_t pointer_chk_guard
    = _dl_setup_pointer_guard (_dl_random, stack_chk_guard);
  THREAD_SET_POINTER_GUARD (pointer_chk_guard);
  __pointer_chk_guard_local = pointer_chk_guard;

  // 最後還會設成 NULL
  _dl_random = NULL;
}
```

`_dl_start()` 是針對 dl 去做初始化以及載入 library，`_dl_init()` 比較像是 binary 本身的關於 dynamic data 的初始化 ([source code](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/dl-init.c#L78))：

```c
void
_dl_init (struct link_map *main_map, int argc, char **argv, char **env)
{
  // preinit_array 沒特別設定的話沒有
  // c 的話要定義在 .preinit_array section 才是，而 .init_array 則是在 __libc_start_main 才會被執行
  ElfW(Dyn) *preinit_array = main_map->l_info[DT_PREINIT_ARRAY];
  ElfW(Dyn) *preinit_array_size = main_map->l_info[DT_PREINIT_ARRAYSZ];
  unsigned int i;

  if (__glibc_unlikely (GL(dl_initfirst) != NULL))
    {
      call_init (GL(dl_initfirst), argc, argv, env);
      GL(dl_initfirst) = NULL;
    }

  /* Don't do anything if there is no preinit array.  */
  if (__builtin_expect (preinit_array != NULL, 0)
      && preinit_array_size != NULL
      && (i = preinit_array_size->d_un.d_val / sizeof (ElfW(Addr))) > 0)
    {
      ElfW(Addr) *addrs;
      unsigned int cnt;

      if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
	_dl_debug_printf ("\ncalling preinit: %s\n\n",
			  DSO_FILENAME (main_map->l_name));

      addrs = (ElfW(Addr) *) (preinit_array->d_un.d_ptr + main_map->l_addr);
      for (cnt = 0; cnt < i; ++cnt)
	((init_t) addrs[cnt]) (argc, argv, env);
    }

  i = main_map->l_searchlist.r_nlist;
  while (i-- > 0)
    call_init (main_map->l_initfini[i], argc, argv, env);

#ifndef HAVE_INLINED_SYSCALLS
  /* Finished starting up.  */
  _dl_starting_up = 0;
#endif
}
```

