##  一個 process 的生命

一個簡單的 C source:

```c
int main {}
```

透過 `gcc -g -o test test.c` 來編譯，執行起來後到結束究竟發生了什麼事情?



### Compile

TODO





### Execute

程式執行時是從 `_start` 開始執行，而這一段程式碼並非我們自己所撰寫，而是透過 `crt0.o` 所提供，而 crt0 全名為 C runtime 0 (0 代表最初):

```asm
Disassembly of section .text:

0000000000001040 <_start>:
    1040:       f3 0f 1e fa             endbr64 
    1044:       31 ed                   xor    ebp,ebp
    1046:       49 89 d1                mov    r9,rdx
    1049:       5e                      pop    rsi
    104a:       48 89 e2                mov    rdx,rsp
    104d:       48 83 e4 f0             and    rsp,0xfffffffffffffff0
    1051:       50                      push   rax
    1052:       54                      push   rsp
    1053:       4c 8d 05 56 01 00 00    lea    r8,[rip+0x156]        # 11b0 <__libc_csu_fini>
    105a:       48 8d 0d df 00 00 00    lea    rcx,[rip+0xdf]        # 1140 <__libc_csu_init>
    1061:       48 8d 3d c1 00 00 00    lea    rdi,[rip+0xc1]        # 1129 <main>
    1068:       ff 15 72 2f 00 00       call   QWORD PTR [rip+0x2f72]        # 3fe0 <__libc_start_main@GLIBC_2.2.5>
    106e:       f4                      hlt    
    106f:       90                      nop

```

> Wiki: 它一般的都採用叫做crt0.o的目的檔形式，經常採用組合語言編寫，**連結器**自動的將它包括入它所建造的所有可執行檔中

也就是說 `crt0.o` 幫我們初始化執行環境，並且透過 glibc `__libc_start_main()` 來呼叫 binary 的 `main()`，而此 crt 也會根據作業系統或執行環境的不同，會有不同的程式碼。

而後會呼叫 `__libc_start_main()` 來看 user 是否有 pre-define 一些 init function 或是 fini function 做對應的動作，並且會建置更複雜的執行環境 ([src](https://elixir.bootlin.com/glibc/glibc-2.31/source/csu/libc-start.c#L111)):

```c
STATIC int LIBC_START_MAIN (int (*main) (int, char **, char **
					 MAIN_AUXVEC_DECL),
			    int argc,
			    char **argv,
#ifdef LIBC_START_MAIN_AUXVEC_ARG
			    ElfW(auxv_t) *auxvec,
#endif
			    __typeof (main) init,
			    void (*fini) (void),
			    void (*rtld_fini) (void),
			    void *stack_end)
     __attribute__ ((noreturn));


/* Note: the fini parameter is ignored here for shared library.  It
   is registered with __cxa_atexit.  This had the disadvantage that
   finalizers were called in more than one place.  */
STATIC int
LIBC_START_MAIN (int (*main) (int, char **, char ** MAIN_AUXVEC_DECL),
		 int argc, char **argv,
#ifdef LIBC_START_MAIN_AUXVEC_ARG
		 ElfW(auxv_t) *auxvec,
#endif
		 __typeof (main) init,
		 void (*fini) (void),
		 void (*rtld_fini) (void), void *stack_end)
{
  /* Result of the 'main' function.  */
  int result;

  __libc_multiple_libcs = &_dl_starting_up && !_dl_starting_up;

#ifndef SHARED
 ... /* 當 static 時才會進來 */
#endif /* !SHARED  */

  /* Register the destructor of the dynamic linker if there is any.  */
  /* 註冊 dynamic linker 的 destructor，會在 exit 時被執行*/
  if (__glibc_likely (rtld_fini != NULL))
    /**
     * ./source/stdlib/cxa_atexit.c
     * 註冊一個 struct exit_function 到 __exit_funcs (global)，並且將資料都做 mangle
     * {
          flavor = 4,
          func = {
            at = 0x256f5e18d70f6418,
            on = {
              fn = 0x256f5e18d70f6418,
              arg = 0x0
            },
            cxa = {
              fn = 0x256f5e18d70f6418,
              arg = 0x0,
              dso_handle = 0x0
            }
          }
        }
     */
    /* rtld_fini 為 _dl_fini (rt 是指 runtime) */
    __cxa_atexit ((void (*) (void *)) rtld_fini, NULL, NULL); 

#ifndef SHARED
... /* for static */
#endif

  /* Call the initializer of the program, if any.  */
#ifdef SHARED
  if (__builtin_expect (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS, 0))
    GLRO(dl_debug_printf) ("\ninitialize program: %s\n\n", argv[0]);
#endif
  /**
   * init 通常會是 __libc_csu_init
   * 而 __libc_csu_init 會去去 init array 一個個執行，其中一定會有一個 frame_dummy -> register_tm_clones
   */
  if (init)
    (*init) (argc, argv, __environ MAIN_AUXVEC_PARAM);

#ifdef SHARED
  /* Auditing checkpoint: we have a new object.  */
  /* dl 的 debug mode 之類的 ? */
  if (__glibc_unlikely (GLRO(dl_naudit) > 0))
    {
      struct audit_ifaces *afct = GLRO(dl_audit);
      struct link_map *head = GL(dl_ns)[LM_ID_BASE]._ns_loaded;
      for (unsigned int cnt = 0; cnt < GLRO(dl_naudit); ++cnt)
	{
	  if (afct->preinit != NULL)
	    afct->preinit (&link_map_audit_state (head, cnt)->cookie);

	  afct = afct->next;
	}
    }
#endif

#ifdef SHARED
  /* dl 的 debug mode 之類的 ? */
  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
    GLRO(dl_debug_printf) ("\ntransferring control: %s\n\n", argv[0]);
#endif

#ifndef SHARED
... /* for static */
#endif
#ifdef HAVE_CLEANUP_JMP_BUF
  /* Memory for the cancellation buffer.  */
  struct pthread_unwind_buf unwind_buf;

  int not_first_call;
  /* setjmp @__@，好像是給 __libc_unwind_longjmp 來跳的 */
  not_first_call = setjmp ((struct __jmp_buf_tag *) unwind_buf.cancel_jmp_buf);
  if (__glibc_likely (! not_first_call))
    {
      struct pthread *self = THREAD_SELF; /* 取得 main thread struct */

      /* Store old info.  */
      unwind_buf.priv.data.prev = THREAD_GETMEM (self, cleanup_jmp_buf);
      unwind_buf.priv.data.cleanup = THREAD_GETMEM (self, cleanup);

      /* Store the new cleanup handler info.  */
      /* 將當前狀態儲存進 fs (tls) */
      THREAD_SETMEM (self, cleanup_jmp_buf, &unwind_buf);

      /* Run the program.  */
      /**
       * RDI  0x1
	   * RSI  0x7fffffffdeb8 —▸ 0x7fffffffe22f ◂— '/home/u1f383/libc-db/test'
	   * RDX  0x7fffffffdec8 —▸ 0x7fffffffe249 ◂— 'GJS_DEBUG_TOPICS=JS ERROR;JS LOG'
	   * RCX  0x7ffff7fc0718 (__exit_funcs) —▸ 0x7ffff7fc2980 (initial) ◂— 0x0
       * R8   0x0
	   * R9   0x7ffff7fe0d50 ◂— endbr64
       */
      result = main (argc, argv, __environ MAIN_AUXVEC_PARAM);
    }
  else /* 這種情況我猜是 thread call fork() */
    {
      /* Remove the thread-local data.  */
# ifdef SHARED
      PTHFCT_CALL (ptr__nptl_deallocate_tsd, ());
# else
      extern void __nptl_deallocate_tsd (void) __attribute ((weak));
      __nptl_deallocate_tsd ();
# endif

      /* One less thread.  Decrement the counter.  If it is zero we
	 terminate the entire process.  */
      result = 0;
# ifdef SHARED
      unsigned int *ptr = __libc_pthread_functions.ptr_nthreads;
#  ifdef PTR_DEMANGLE
      PTR_DEMANGLE (ptr);
#  endif
# else
      extern unsigned int __nptl_nthreads __attribute ((weak));
      unsigned int *const ptr = &__nptl_nthreads;
# endif

      if (! atomic_decrement_and_test (ptr))
	/* Not much left to do but to exit the thread, not the process.  */
	__exit_thread ();
    }
#else
  /* Nothing fancy, just call the function.  */
  result = main (argc, argv, __environ MAIN_AUXVEC_PARAM);
#endif

  /* process exit */
  exit (result);
}
```

`__libc_start_main` 呼叫 `exit()` 後，會間接呼叫到一開始註冊的 `__cxa_atexit` 那些 function，然而為什麼是 `__cxa` 開頭，是因為這是 Itanium™ C++ ABI，而新的 atexit function 有以下好處:

- `__cxa_atexit()` is not limited to 32 functions (`atexit()` 只能 32 個)

- `__cxa_atexit()` will call the destructor of the static of a dynamic library when this dynamic library is unloaded before the program exits (`atexit()` 沒辦法很好的 handle [Dynamic Shared Objects]

基本上背後牽扯到 dynamic shared object 能不能在 `dlclose()` 前正常關閉所有動態 obj，詳細可以參照[此文](https://stackoverflow.com/a/42912336/13109204)

讓我們看看 `exit()` 的背後究竟做了些什麼:

```c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
```

只是一個 call `__run_exit_handlers` 的 wrapper function，其中傳入註冊的 atexit function list `__exit_funcs` 做為參數:

```c
/* Call all functions registered with `atexit' and `on_exit',
   in the reverse of the order in which they were registered
   perform stdio cleanup, and terminate program execution with STATUS.  */
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    /* dtor 為 destructor 的縮寫，而從 exit() 進來的話 run_dtors 都會是 true */
    if (run_dtors)
      __call_tls_dtors ();

  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (true)
    {
      struct exit_function_list *cur;

      __libc_lock_lock (__exit_funcs_lock);

    /* 第一個會是一開始在 __libc_start_main 所註冊的 rtld_fini */
    restart:
      cur = *listp;

      if (cur == NULL)
	{
	  /* Exit processing complete.  We will not allow any more
	     atexit/on_exit registrations.  */
	  __exit_funcs_done = true;
	  __libc_lock_unlock (__exit_funcs_lock);
	  break;
	}

      /* cur->idx 記錄了有多少個註冊的 exit function 需要被執行 */
      /* 而 exit_function_list 其實最多只能註冊 32 個 function */
      while (cur->idx > 0)
	{
	  struct exit_function *const f = &cur->fns[--cur->idx];
	  const uint64_t new_exitfn_called = __new_exitfn_called;

	  /* Unlock the list while we call a foreign function.  */
	  __libc_lock_unlock (__exit_funcs_lock);
	  switch (f->flavor)
	    {
          /* 這邊 fct 應該是指 function */
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);

	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      onfct (status, f->func.on.arg);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      atfct ();
	      break;
	    case ef_cxa:
	      /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
		 we must mark this function as ef_free.  */
	      f->flavor = ef_free; /* mark 成已經執行 */
	      cxafct = f->func.cxa.fn; /* 取得 function pointer */
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      cxafct (f->func.cxa.arg, status);
	      break;
	    }
	  /* Re-lock again before looking at global state.  */
	  __libc_lock_lock (__exit_funcs_lock);

	  if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
	    /* The last exit function, or another thread, has registered
	       more exit functions.  Start the loop over.  */
	    goto restart;
	}

      *listp = cur->next;
      if (*listp != NULL)
	/* Don't free the last element in the chain, this is the statically
	   allocate element.  */
	free (cur);

      __libc_lock_unlock (__exit_funcs_lock);
    }

  /**
   * 預設會有 __elf_set___libc_atexit_element__IO_cleanup__，就是做 _IO_cleanup，
   * underflow 所有的 buffer 以及 close
   */
  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());

  _exit (status); /* 確實地離開了 */
}
```

- `__call_tls_dtors()` 負責 release 關於 tls 所註冊的 dtor，不過應該要事先註冊，不然預設是沒有任何 tls dtor 的:

  ```c
  /* Call the destructors.  This is called either when a thread returns from the
     initial function or when the process exits via the exit function.  */
  void
  __call_tls_dtors (void)
  {
    /* 一般沒註冊的話是 NULL */
    while (tls_dtor_list)
      {
        struct dtor_list *cur = tls_dtor_list;
        dtor_func func = cur->func;
  #ifdef PTR_DEMANGLE
        PTR_DEMANGLE (func);
  #endif
  
        tls_dtor_list = tls_dtor_list->next;
        func (cur->obj);
  
        /* Ensure that the MAP dereference happens before
  	 l_tls_dtor_count decrement.  That way, we protect this access from a
  	 potential DSO unload in _dl_close_worker, which happens when
  	 l_tls_dtor_count is 0.  See CONCURRENCY NOTES for more detail.  */
        atomic_fetch_add_release (&cur->map->l_tls_dtor_count, -1);
        free (cur);
      }
  }
  libc_hidden_def (__call_tls_dtors)
  ```

- 像是 `__libc_lock_lock()` 的操作要 atomic，都是用 x86 insn 如 `cmpxchgl` 做到 CAS

- 大概分析一下 `dl_fini` 所做的行為，目標就是要去執行所有 namespace 的所有 loaded object 的 dtor，但是過程中必須考量每個 module 的 dependency，但是也不能 reverse order 去 destruct，因為有些 module 可能是用 `dlopen()` 載入的，所以要先確定好 module 順序在做 dtor ([src](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/dl-fini.c#L29)):

  ```c
  void
  _dl_fini (void)
  {
  #ifdef SHARED
    int do_audit = 0;
   again:
  #endif
    /* GL 應該是指 _rtld_local */
    for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
      {
        /* Protect against concurrent loads and unloads.  */
        __rtld_lock_lock_recursive (GL(dl_load_lock));
  
        unsigned int nloaded = GL(dl_ns)[ns]._ns_nloaded;
        /* No need to do anything for empty namespaces or those used for
  	 auditing DSOs.  */
        /* 沒有 loaded module，代表沒有需要被 unload */
        if (nloaded == 0
  #ifdef SHARED
  	  || GL(dl_ns)[ns]._ns_loaded->l_auditing != do_audit
  #endif
  	  )
  	__rtld_lock_unlock_recursive (GL(dl_load_lock));
        else
  	{
  	  /* Now we can allocate an array to hold all the pointers and
  	     copy the pointers in.  */
        /* 因為要在 stack 對 map link_map 做操作，因此先 create 對應大小的空間 */
  	  struct link_map *maps[nloaded];
  
  	  unsigned int i;
  	  struct link_map *l;
  	  assert (nloaded != 0 || GL(dl_ns)[ns]._ns_loaded == NULL);\
        /* ns 是指 namespace，所以先從對應的 ns 的 _ns_loaded 取得第一個 link_map，
         * 之後再透過 l->next 去 traverse 所有的 link_map
  	   */
  	  for (l = GL(dl_ns)[ns]._ns_loaded, i = 0; l != NULL; l = l->l_next)
  	    /* Do not handle ld.so in secondary namespaces.  */
          /* l_real 應該就是指所有 ns 指向的最一開始的 link_map，因此不需要在存一次 */
  	    if (l == l->l_real)
  	      {
  		assert (i < nloaded);
  
  		maps[i] = l;
  		l->l_idx = i;
  		++i;
  
  		/* Bump l_direct_opencount of all objects so that they
  		   are not dlclose()ed from underneath us.  */
  		++l->l_direct_opencount;
  	      }
  	  assert (ns != LM_ID_BASE || i == nloaded);
  	  assert (ns == LM_ID_BASE || i == nloaded || i == nloaded - 1);
  	  unsigned int nmaps = i;
  
  	  /* Now we have to do the sorting.  We can skip looking for the
  	     binary itself which is at the front of the search list for
  	     the main namespace.  */
        /**
         * 開始為 dl 做 sorting，主要根據的就是 dependencies of the contained objects，
         * 而 sort 細節繁瑣，有興趣者自行參閱 _dl_sort_maps 的 source code
         */
  	  _dl_sort_maps (maps + (ns == LM_ID_BASE), nmaps - (ns == LM_ID_BASE),
  			 NULL, true);
  
  	  /* 由於 stack 有一個自己的 maps，因此不需要在做 lock */
  	  __rtld_lock_unlock_recursive (GL(dl_load_lock));
  
  	  /* 'maps' now contains the objects in the right order.  Now
  	     call the destructors.  We have to process this array from
  	     the front.  */
        /* maps 內存放的是已經 sorted 完畢的 link_map */
  	  for (i = 0; i < nmaps; ++i)
  	    {
  	      struct link_map *l = maps[i];
  
  	      if (l->l_init_called)
  		{
  		  /* Make sure nothing happens if we are called twice.  */
            /* 避免第二次被 call (?，有可能會有 race 嗎 */
  		  l->l_init_called = 0;
  
  		  /* Is there a destructor function?  */
            /* 先檢查有沒有 dtor fct */
            /**
             * #define DT_FINI         13 - Address of termination function
             * #define DT_FINI_ARRAY   26 - Array with addresses of fini fct
             * #define DT_FINI_ARRAYSZ 28 - Size in bytes of DT_FINI_ARRAY
             */
            /* 結果最後只有第一個 elf 的 fini array 註冊的 handler 有被執行 @__@ */
  		  if (l->l_info[DT_FINI_ARRAY] != NULL
  		      || l->l_info[DT_FINI] != NULL)
  		    {
  		      /* When debugging print a message first.  */
  		      if (__builtin_expect (GLRO(dl_debug_mask)
  					    & DL_DEBUG_IMPCALLS, 0))
  			_dl_debug_printf ("\ncalling fini: %s [%lu]\n\n",
  					  DSO_FILENAME (l->l_name),
  					  ns);
  
  		      /* First see whether an array is given.  */
  		      if (l->l_info[DT_FINI_ARRAY] != NULL)
  			{
  			  ElfW(Addr) *array =
  			    (ElfW(Addr) *) (l->l_addr /* 0x555555554000，也就是 elf base */
                          /* 第一個應該會拿到 _fini_array */
  					    + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
  			  unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
  					    / sizeof (ElfW(Addr)));
                /* 執行 dtor func */
  			  while (i-- > 0)
                  /* 第一次會執行 __do_global_dtors_aux，aux 全名為 auxiliary vector */
  			    ((fini_t) array[i]) ();
  			}
  
  		      /* Next try the old-style destructor.  */
  		      if (l->l_info[DT_FINI] != NULL)
              /* 第一次會執行 _fini，做了 sub rsp, 8 ; add rsp, 8 ; retn (啥都沒做) */
  			DL_CALL_DT_FINI
  			  (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
  		    }
  
  #ifdef SHARED
  		  /* Auditing checkpoint: another object closed.  */
  		  if (!do_audit && __builtin_expect (GLRO(dl_naudit) > 0, 0))
  		    {
  		      struct audit_ifaces *afct = GLRO(dl_audit);
  		      for (unsigned int cnt = 0; cnt < GLRO(dl_naudit); ++cnt)
  			{
  			  if (afct->objclose != NULL)
  			    {
  			      struct auditstate *state
  				= link_map_audit_state (l, cnt);
  			      /* Return value is ignored.  */
  			      (void) afct->objclose (&state->cookie);
  			    }
  			  afct = afct->next;
  			}
  		    }
  #endif
  		}
  
  	      /* Correct the previous increment.  */
  	      --l->l_direct_opencount;
  	    }
  	}
      }
  
  #ifdef SHARED
    if (! do_audit && GLRO(dl_naudit) > 0)
      {
        do_audit = 1;
        goto again;
      }
  
    if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_STATISTICS))
      _dl_debug_printf ("\nruntime linker statistics:\n"
  		      "           final number of relocations: %lu\n"
  		      "final number of relocations from cache: %lu\n",
  		      GL(dl_num_relocations),
  		      GL(dl_num_cache_relocations));
  #endif
  }
  ```

  - `_do_global_dtors_aux()` 做 auxv 的 dtor，不過沒 source code，因此用 IDA pro decompile 後查看:

    ```c
    __int64 _do_global_dtors_aux()
    {
      __int64 result; // rax
    
      if ( !_bss_start )
      {
        if ( &__cxa_finalize )
          _cxa_finalize(_dso_handle);
        result = deregister_tm_clones(); /* 正常情況下好像什麼都不會執行 @__@ */
        _bss_start = 1;
      }
      return result;
    }
    ```

    - `_cxa_finalize()` 在執行一遍 `exit_function_list`，以下為刪去 comment 後的程式碼 ([src](https://elixir.bootlin.com/glibc/glibc-2.31/source/stdlib/cxa_finalize.c#L29)):

      ```c
      /* If D is non-NULL, call all functions registered with `__cxa_atexit'
         with the same dso handle.  Otherwise, if D is NULL, call all of the
         registered handlers.  */
      void
      __cxa_finalize (void *d)
      {
        struct exit_function_list *funcs;
      
        __libc_lock_lock (__exit_funcs_lock);
      
       restart:
        /* traverse 整個 __exit_funcs list */
        for (funcs = __exit_funcs; funcs; funcs = funcs->next)
          {
            struct exit_function *f;
      
            for (f = &funcs->fns[funcs->idx - 1]; f >= &funcs->fns[0]; --f)
      	if ((d == NULL || d == f->func.cxa.dso_handle) && f->flavor == ef_cxa)
      	  {
      	    const uint64_t check = __new_exitfn_called;
      	    void (*cxafn) (void *arg, int status) = f->func.cxa.fn;
      	    void *cxaarg = f->func.cxa.arg;
      	    f->flavor = ef_free;
      
      #ifdef PTR_DEMANGLE
      	    PTR_DEMANGLE (cxafn);
      #endif
      	    /* Unlock the list while we call a foreign function.  */
      	    __libc_lock_unlock (__exit_funcs_lock);
      	    cxafn (cxaarg, 0);
      	    __libc_lock_lock (__exit_funcs_lock);
      
              
      		/* -------- 以上程式碼就是在執行 exit handler -------- */        
              
      	    /* It is possible that that last exit function registered
      	       more exit functions.  Start the loop over.  */
              /* exit function 在註冊更多的 exit function @___@ ? */
      	    if (__glibc_unlikely (check != __new_exitfn_called))
      	      goto restart;
      	  }
          }
      
        /* Also remove the quick_exit handlers, but do not call them.  */
        for (funcs = __quick_exit_funcs; funcs; funcs = funcs->next)
          {
            struct exit_function *f;
      
            for (f = &funcs->fns[funcs->idx - 1]; f >= &funcs->fns[0]; --f)
      	if (d == NULL || d == f->func.cxa.dso_handle)
      	  f->flavor = ef_free;
          }
      
        /* Remove the registered fork handlers.  We do not have to
           unregister anything if the program is going to terminate anyway.  */
      #ifdef UNREGISTER_ATFORK
        if (d != NULL)
          UNREGISTER_ATFORK (d);
      #endif
        __libc_lock_unlock (__exit_funcs_lock);
      }
      ```

    - 關於 `__dso_handle` 的介紹:

      > When linking any DSO containing a call to `__cxa_atexit`, the linker should define a hidden symbol `__dso_handle`, with a value which is an address in **one of the object's segments**. (It does not matter what address, as long as they are different in different DSOs.) It should also include a call to the following function in the FINI list (to be executed first)

      - `d == NULL` - 執行所有 registered handler
      - `d == dso_handle`- 執行相同 dso_handle 的 handler