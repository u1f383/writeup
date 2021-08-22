## eBPF

在 `kernel.md`有稍微 trace eBPF 的運作機制，而這邊會做更詳細的追蹤，使用的 kernel 版本為 5.13.11。



#### 進入點 syscall

首先關於 bpf 的操作是透過 nr 321 的 syscall 來執行，下列為傳入的參數:

| %rax | System call | %rdi    | %rsi                 | %rdx              |
| ---- | ----------- | ------- | -------------------- | ----------------- |
| 321  | sys_bpf     | int cmd | union bpf_attr *attr | unsigned int size |



之後會到 kernel 的 bpf syscall handler 來執行 ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/syscall.c#L4369)):

```c
SYSCALL_DEFINE3(bpf, int, cmd, union bpf_attr __user *, uattr, unsigned int, size)
{
	union bpf_attr attr;
	int err;

	if (sysctl_unprivileged_bpf_disabled && !bpf_capable())
		return -EPERM;

    /* 傳入的 size 可能跟 sizeof(attr) 不相同，因此要檢查多的部分是否為 null */
	err = bpf_check_uarg_tail_zero(uattr, sizeof(attr), size);
	if (err)
		return err;
    /* size 為 sizeof(attr) or size 之中較小的值 */
	size = min_t(u32, size, sizeof(attr));

	/* copy attributes from user space, may be less than sizeof(bpf_attr) */
	memset(&attr, 0, sizeof(attr));
	if (copy_from_user(&attr, uattr, size) != 0)
		return -EFAULT;

   	/**
   	 * https://elixir.bootlin.com/linux/v5.13.11/source/security/security.c#L2566
   	 * 定義一連串 bpf cmd 檢測
   	 */
	err = security_bpf(cmd, &attr, size);
	if (err < 0)
		return err;

    /* 根據 user 傳入的 cmd 做對應的行為，像是 create map、update map 等等 */
	switch (cmd) {
	case BPF_MAP_CREATE:
		err = map_create(&attr);
		break;
	...
	default:
		err = -EINVAL;
		break;
	}

	return err;
}
```

- 這邊的 call flow 是從 `__x64_sys_bpf` --> `__do_sys_bpf`，所以該 macro 展開後應該會是 `__do_sys_bpf`，不過 `__x64_sys_bpf` 似乎也沒做什麼事

- `copy_from_user()` 是從 user 提供的 ptr copy 資料回 kernel mode:

  ```c
  static __always_inline unsigned long __must_check
  copy_from_user(void *to, const void __user *from, unsigned long n)
  {
  	if (likely(check_copy_size(to, n, false)))
  		n = _copy_from_user(to, from, n);
  	return n;
  }
  ```

  會先執行 `check_copy_size()` 檢查資料的合法性，合法的定義如下:

  - not bogus address
  - fully contained by stack (or stack frame, when available)
  - fully within SLAB object (or object whitelist area, when available)
  - not in kernel text

- 雖說 `security_bpf()` 看起來是檢測 bpf 的安全性，過程中會從 `security_hook_heads+1800` 嘗試拿出 function pointer 去執行 (?)，但如果沒有特別設置，則什麼都不會做:

  ```c
  int security_bpf(int cmd, union bpf_attr *attr, unsigned int size)
  {
  	return call_int_hook(bpf, 0, cmd, attr, size);
  }
  ```

  

#### BPF_MAP_CREATE --> map_create

`map_create()` 為 bpf 在建立 kernel 跟 userland 共享的記憶體空間，之後透過 `map_lookup_elem()` 來從 userland 取得 kernel space 最新資料，或是透過 `map_update_elem()` 將 userland 的資料更新上去。

首先建立時會參照 user 傳入的 struct `union bpf_attr` (size: 0x78):

```c
union bpf_attr {
	struct { /* anonymous struct used by BPF_MAP_CREATE command */
        /* 沒特別設定的話，userland 傳入的應該只會有前 5 個 */
		__u32	map_type;	/* one of enum bpf_map_type */
		__u32	key_size;	/* size of key in bytes */
		__u32	value_size;	/* size of value in bytes */
		__u32	max_entries;	/* max number of entries in a map */
		__u32	map_flags;	/* BPF_MAP_CREATE related
					 * flags defined above.
					 */
        /* ------------------------------------------ */
		__u32	inner_map_fd;	/* fd pointing to the inner map */
		__u32	numa_node;	/* numa node (effective only if
					 * BPF_F_NUMA_NODE is set).
					 */
		char	map_name[BPF_OBJ_NAME_LEN];
		__u32	map_ifindex;	/* ifindex of netdev to create on */
		__u32	btf_fd;		/* fd pointing to a BTF type data */
		__u32	btf_key_type_id;	/* BTF type_id of the key */
		__u32	btf_value_type_id;	/* BTF type_id of the value */
		__u32	btf_vmlinux_value_type_id;/* BTF type_id of a kernel-
						   * struct stored as the
						   * map value
						   */
	};
	...
```

而 `map_create()` 的程式碼如下:

```c
static int map_create(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_map *map;
	int f_flags;
	int err;

	err = CHECK_ATTR(BPF_MAP_CREATE);
	if (err)
		return -EINVAL;

    /* 不確定什麼時候會進入這兩個 condition，不過我看 attr 只有前面 4~5 個 member 被初始化而已 */
	if (attr->btf_vmlinux_value_type_id) {
		if (attr->map_type != BPF_MAP_TYPE_STRUCT_OPS ||
		    attr->btf_key_type_id || attr->btf_value_type_id)
			return -EINVAL;
	} else if (attr->btf_key_type_id && !attr->btf_value_type_id) {
		return -EINVAL;
	}

    /* 檢測 flag，bpf 的 fd 也有分 RD, WR, RDWR */
	f_flags = bpf_get_file_flag(attr->map_flags);
	if (f_flags < 0)
		return f_flags;

    /**
     * numa - Non-Uniform Memory Access
     * 應該是跟硬體架構有關的判斷式，不過 usermode 似乎可以透過 BPF_F_NUMA_NODE 此 flag 來選擇 numa node
     */
	if (numa_node != NUMA_NO_NODE &&
	    ((unsigned int)numa_node >= nr_node_ids ||
	     !node_online(numa_node)))
		return -EINVAL;

	/* find map type and init map: hashtable vs rbtree vs bloom vs ... */
	map = find_and_alloc_map(attr); /* 根據傳入的 attr 新增一個 map */
	if (IS_ERR(map))
		return PTR_ERR(map);

    /* 複製 attr 的 map_name 到 map->name */
	err = bpf_obj_name_cpy(map->name, attr->map_name,
			       sizeof(attr->map_name));
	if (err < 0)
		goto free_map;

    /* 設置與 lock 相關的 member */
	atomic64_set(&map->refcnt, 1);
	atomic64_set(&map->usercnt, 1);
	mutex_init(&map->freeze_mutex);

	map->spin_lock_off = -EINVAL;
	if (attr->btf_key_type_id || attr->btf_value_type_id ||
	    /* Even the map's value is a kernel's struct,
	     * the bpf_prog.o must have BTF to begin with
	     * to figure out the corresponding kernel's
	     * counter part.  Thus, attr->btf_fd has
	     * to be valid also.
	     */
	    attr->btf_vmlinux_value_type_id) {
		struct btf *btf;

		btf = btf_get_by_fd(attr->btf_fd);
		if (IS_ERR(btf)) {
			err = PTR_ERR(btf);
			goto free_map;
		}
		if (btf_is_kernel(btf)) {
			btf_put(btf);
			err = -EACCES;
			goto free_map;
		}
		map->btf = btf;

		if (attr->btf_value_type_id) {
			err = map_check_btf(map, btf, attr->btf_key_type_id,
					    attr->btf_value_type_id);
			if (err)
				goto free_map;
		}

		map->btf_key_type_id = attr->btf_key_type_id;
		map->btf_value_type_id = attr->btf_value_type_id;
		map->btf_vmlinux_value_type_id =
			attr->btf_vmlinux_value_type_id;
	}

    /* 這種 security_* 的 function 都是在 security/security.c 定義，會看有沒有 pre-define hook 可以呼叫
    	如果沒有的話就什麼事情也不做
    */
	err = security_bpf_map_alloc(map);
	if (err)
		goto free_map;

    /* published the map to the userspace */
    /* 背後是用 idr 做的，而 idr 的機制我不是很了解，只查到是用 radix-tree 去 implement int->ptr
     * 用途像是 device name 等等
     */
	err = bpf_map_alloc_id(map);
	if (err)
		goto free_map_sec;

	bpf_map_save_memcg(map);

    /* 會 assign 新的 fd 給 map，正常的話會是一個新的 fd */
	err = bpf_map_new_fd(map, f_flags);
	if (err < 0) {
		/* failed to allocate fd.
		 * bpf_map_put_with_uref() is needed because the above
		 * bpf_map_alloc_id() has published the map
		 * to the userspace and the userspace may
		 * have refcnt-ed it through BPF_MAP_GET_FD_BY_ID.
		 */
		bpf_map_put_with_uref(map);
		return err;
	}
	/* 正常離開 */
	return err;

free_map_sec:
	security_bpf_map_free(map);
free_map:
	btf_put(map->btf);
	map->ops->map_free(map);
	return err;
}
```

- `find_and_alloc_map()` 會根據 `attr->map_type` 來建立 map ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/syscall.c#L102)):

  ```c
  static struct bpf_map *find_and_alloc_map(union bpf_attr *attr)
  {
  	const struct bpf_map_ops *ops;
  	u32 type = attr->map_type;
  	struct bpf_map *map;
  	int err;
  
      /* bpf_map_types 一共有 29 個，如 fixed_percpu_data, htab_map_ops, array_map_ops,... 等等 */
  	if (type >= ARRAY_SIZE(bpf_map_types))
  		return ERR_PTR(-EINVAL);
  
  	type = array_index_nospec(type, ARRAY_SIZE(bpf_map_types)); /* 取得 type index (e.g. array = 2) */
  	ops = bpf_map_types[type]; /* 取得對應 type 的 op function table */
  	if (!ops)
  		return ERR_PTR(-EINVAL);
      /**
       * 同類的 ops function 都定義在同個檔案，如 array 就是在 https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/arraymap.c
       */
  
  	if (ops->map_alloc_check) {
          /* 檢查 attr 中關於 map 的資料是否為 array specified */
  		err = ops->map_alloc_check(attr);
  		if (err)
  			return ERR_PTR(err);
  	}
  	if (attr->map_ifindex)
  		ops = &bpf_map_offload_ops;
  	map = ops->map_alloc(attr); /* array 的話會 call array_map_alloc() */
  	if (IS_ERR(map))
  		return map;
      /* 到這，map 已經根據 attr 初始化完成，並且也檢測了合法性，最後只需要在 assign op function 以及 type */
  	map->ops = ops;
  	map->map_type = type;
  	return map;
  }
  ```

  - `array_map_alloc()` 做了以下事情:
    - 透過 `round_up()` bitwise 的操作，將 `attr->max_entries` 擴展到 >=  `attr->max_entries` 的二冪次值
    - `array_size += (u64) max_entries * elem_size` 為 struct 需要的大小，array_size 為 `sizeof(struct bpf_array)`，而 `max_entries` 為 extend 後的 entry 數量，elem_size 為 user 傳入的 `attr->value_size`
    - `bpf_map_area_alloc` 以 `array_size` 為參數，間接呼叫 `area = kmalloc_node(size, ...)` 來建立 
      - 用 `kmalloc_node()` 跟 `kmalloc()` 的差別在於 bpf 可能會需要選擇特定的 NUMA node，不過如果沒特別指定的話 (`node` 傳入 -1) 其實沒什麼差別
    - `bpf_map_init_from_attr()` 會根據傳入的 attr 來初始化 map，只是做一些簡單的 assign 而已



#### BPF_PROG_LOAD -->  bpf_prog_load

`bpf_prog_load` 會接收使用者傳入的 attr，並且 emulate 執行 insn 看是否合法 (是否有 infinite loop 等等)，可謂說是 bpf 最關鍵的一個 function。

透過 `switch (cmd)` 會進入 `bpf_prog_load()` ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/syscall.c#L2079))，而上半部分的程式碼在做 `bpf_prog` 的初始化，以及建構整個執行環境:

```c
static int bpf_prog_load(union bpf_attr *attr, union bpf_attr __user *uattr)
{
	enum bpf_prog_type type = attr->prog_type;
	struct bpf_prog *prog, *dst_prog = NULL;
	struct btf *attach_btf = NULL;
	int err;
	char license[128];
	bool is_gpl;

	if (CHECK_ATTR(BPF_PROG_LOAD))
		return -EINVAL;

    /* 只有這些 flag 是被允許的 */
	if (attr->prog_flags & ~(BPF_F_STRICT_ALIGNMENT |
				 BPF_F_ANY_ALIGNMENT |
				 BPF_F_TEST_STATE_FREQ |
				 BPF_F_SLEEPABLE |
				 BPF_F_TEST_RND_HI32))
		return -EINVAL;

	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) &&
	    (attr->prog_flags & BPF_F_ANY_ALIGNMENT) &&
	    !bpf_capable())
		return -EPERM;

	/* copy eBPF program license from user space */
    /* 把 license copy 到 kernel */
	if (strncpy_from_user(license, u64_to_user_ptr(attr->license),
			      sizeof(license) - 1) < 0)
		return -EFAULT;
	license[sizeof(license) - 1] = 0;

	/* eBPF programs must be GPL compatible to use GPL-ed functions */
    /* license_is_gpl_compatible() 有列出一連串相容的 license */
	is_gpl = license_is_gpl_compatible(license);

	if (attr->insn_cnt == 0 ||
	    attr->insn_cnt > (bpf_capable() ? BPF_COMPLEXITY_LIMIT_INSNS : BPF_MAXINSNS))
		return -E2BIG;
    /**
     * 只能 type BPF_PROG_TYPE_SOCKET_FILTER 或是 BPF_PROG_TYPE_CGROUP_SKB)
     * 但是 enum bpf_prog_type 裡面有很多 type @_@ ?
     */
	if (type != BPF_PROG_TYPE_SOCKET_FILTER &&
	    type != BPF_PROG_TYPE_CGROUP_SKB &&
	    !bpf_capable())
		return -EPERM;

	if (is_net_admin_prog_type(type) && !capable(CAP_NET_ADMIN) && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (is_perfmon_prog_type(type) && !perfmon_capable())
		return -EPERM;

	/* attach_prog_fd/attach_btf_obj_fd can specify fd of either bpf_prog
	 * or btf, we need to check which one it is
	 */
    /* 用來 attach 舊的 prog_fd ? */
	if (attr->attach_prog_fd) {
		dst_prog = bpf_prog_get(attr->attach_prog_fd);
		if (IS_ERR(dst_prog)) {
			dst_prog = NULL;
			attach_btf = btf_get_by_fd(attr->attach_btf_obj_fd);
			if (IS_ERR(attach_btf))
				return -EINVAL;
			if (!btf_is_kernel(attach_btf)) {
				/* attaching through specifying bpf_prog's BTF
				 * objects directly might be supported eventually
				 */
				btf_put(attach_btf);
				return -ENOTSUPP;
			}
		}
	} else if (attr->attach_btf_id) {
		/* fall back to vmlinux BTF, if BTF type ID is specified */
		attach_btf = bpf_get_btf_vmlinux();
		if (IS_ERR(attach_btf))
			return PTR_ERR(attach_btf);
		if (!attach_btf)
			return -EINVAL;
		btf_get(attach_btf);
	}

     /**
     * bpf_prog_load_check_attach():
     * Sets expected_attach_type in @attr if prog type requires it but has
	 * some attach types that have to be backward compatible
	 * 不過只有 BPF_PROG_TYPE_CGROUP_SOCK 可以設 expected_attach_type 成 BPF_CGROUP_INET_SOCK_CREATE
	 */
	bpf_prog_load_fixup_attach_type(attr);
	if (bpf_prog_load_check_attach(type, attr->expected_attach_type,
				       attach_btf, attr->attach_btf_id,
				       dst_prog)) {
        /**
         * 只有在 bpf_prog_load_check_attach() return EINVAL (invalid value) 時會進入
         * 上述 function 在一一檢查 prog_type 與 expected_attach_type 的關係
         */
		if (dst_prog)
			bpf_prog_put(dst_prog);
		if (attach_btf)
			btf_put(attach_btf);
		return -EINVAL;
	}

	/* plain bpf_prog allocation */
    /**
     * 取得 struct bpf_prog + insn length 大小的 space 作為第一個參數
     * 之後執行 bpf_prog_alloc 來
     */
	prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt), GFP_USER);
	if (!prog) {
		if (dst_prog)
			bpf_prog_put(dst_prog);
		if (attach_btf)
			btf_put(attach_btf);
		return -ENOMEM;
	}

	prog->expected_attach_type = attr->expected_attach_type;
	prog->aux->attach_btf = attach_btf;
	prog->aux->attach_btf_id = attr->attach_btf_id;
	prog->aux->dst_prog = dst_prog;
	prog->aux->offload_requested = !!attr->prog_ifindex;
	prog->aux->sleepable = attr->prog_flags & BPF_F_SLEEPABLE;

	err = security_bpf_prog_alloc(prog->aux);
	if (err)
		goto free_prog;

	prog->aux->user = get_current_user();
	prog->len = attr->insn_cnt;

	err = -EFAULT;
	if (copy_from_user(prog->insns, u64_to_user_ptr(attr->insns),
			   bpf_prog_insn_size(prog)) != 0)
		goto free_prog_sec;

	prog->orig_prog = NULL;
	prog->jited = 0;

    /* 已經有一個 reference */
	atomic64_set(&prog->aux->refcnt, 1);
	prog->gpl_compatible = is_gpl ? 1 : 0;

	if (bpf_prog_is_dev_bound(prog->aux)) {
		err = bpf_prog_offload_init(prog, attr);
		if (err)
			goto free_prog_sec;
	}

	/* find program type: socket_filter vs tracing_filter */
    /**
     * 找到對應 prog type 的 type index / ops，並 assign 給 prog->aux->ops 以及 prog->type
     * 就 BPF_PROG_TYPE_SOCKET_FILTER 來說，
     * ops 會是 sk_filter_prog_ops
     * type 會是 BPF_PROG_TYPE_SOCKET_FILTER
     */
	err = find_prog_type(type, prog);
	if (err < 0)
		goto free_prog_sec;

	prog->aux->load_time = ktime_get_boottime_ns();
    /* copy prog name from user mode */
	err = bpf_obj_name_cpy(prog->aux->name, attr->prog_name,
			       sizeof(attr->prog_name));
	if (err < 0)
		goto free_prog_sec;
	...
```

- `bpf_prog_alloc` 相關 function 有使用到 `GFP` prefix 的 flag，而 `GFP` 本身為 Get Free Pages = `__get_free_pages`

  - 指定 allocate memory 時的行為，e.g. `GFP_ATOMIC` 為在 allocate page 時不會有 context-switch

  - 背後會透過 `__vmalloc` 來建立存放 bpf_prog

  - 程式碼 ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/core.c#L115)):

    ```c
    struct bpf_prog *bpf_prog_alloc(unsigned int size, gfp_t gfp_extra_flags)
    {
        /* 上述說明的 GFP flag */
    	gfp_t gfp_flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | gfp_extra_flags;
    	struct bpf_prog *prog;
    	int cpu;
    
        /* 建立一個沒有設 stats 的 prog struct */
    	prog = bpf_prog_alloc_no_stats(size, gfp_extra_flags);
    	if (!prog)
    		return NULL;
    
        /* 這邊才設 stats */
        /* 可是回傳的不是一般的 address，而是 e.g 0x607ff0c030a0 */
    	prog->stats = alloc_percpu_gfp(struct bpf_prog_stats, gfp_flags);
    	if (!prog->stats) {
    		free_percpu(prog->active);
    		kfree(prog->aux);
    		vfree(prog);
    		return NULL;
    	}
    
        /* bpf 來說不怎麼重要 ? */
    	for_each_possible_cpu(cpu) {
    		struct bpf_prog_stats *pstats;
    
    		pstats = per_cpu_ptr(prog->stats, cpu);
    		u64_stats_init(&pstats->syncp);
    	}
    	return prog;
    }
    ```

    過程中呼叫的 `bpf_prog_alloc_no_stats()` 為主要 allocate 的部分:

    ```c
    struct bpf_prog *bpf_prog_alloc_no_stats(unsigned int size, gfp_t gfp_extra_flags)
    {
    	gfp_t gfp_flags = GFP_KERNEL_ACCOUNT | __GFP_ZERO | gfp_extra_flags;
    	struct bpf_prog_aux *aux;
    	struct bpf_prog *fp;
    
        /* 一樣找到 >= 的 pow of 2 value (以 page 為 base) */
    	size = round_up(size, PAGE_SIZE); /* 沒有很大的 prog 都會直接分一個 page 給他 (0x1000) */
    	fp = __vmalloc(size, gfp_flags);
    	if (fp == NULL)
    		return NULL;
    
    	aux = kzalloc(sizeof(*aux), GFP_KERNEL_ACCOUNT | gfp_extra_flags);
    	if (aux == NULL) {
    		vfree(fp);
    		return NULL;
    	}
    	fp->active = alloc_percpu_gfp(int, GFP_KERNEL_ACCOUNT | gfp_extra_flags);
    	if (!fp->active) {
    		vfree(fp);
    		kfree(aux);
    		return NULL;
    	}
    
    	fp->pages = size / PAGE_SIZE; /* 站了幾個 page */
    	fp->aux = aux;
    	fp->aux->prog = fp;
    	fp->jit_requested = ebpf_jit_enabled();
    
    	INIT_LIST_HEAD_RCU(&fp->aux->ksym.lnode);
        /* init lock */
    	mutex_init(&fp->aux->used_maps_mutex);
    	mutex_init(&fp->aux->dst_mutex);
    
    	return fp;
    }
    ```

    - 一共分配兩塊 memory: `bpf_prog` 以及 `aux`

    - `ebpf_jit_enabled()` 會影響到是否可以用 JIT 優化，還是只能都用 interpreter

      ```c
      static inline bool ebpf_jit_enabled(void)
      {
      	return bpf_jit_enable && bpf_jit_is_ebpf();
      }
      
      static inline bool bpf_jit_is_ebpf(void)
      {
      /* 要從編譯 kernel 的時候設定 */
      # ifdef CONFIG_HAVE_EBPF_JIT
      	return true;
      # else
      	return false;
      # endif
      }
      
      /* bpf_jit_enable 在 kernel/bpf/core.c */
      #ifdef CONFIG_BPF_JIT
      /* All BPF JIT sysctl knobs here. */
      int bpf_jit_enable   __read_mostly = IS_BUILTIN(CONFIG_BPF_JIT_DEFAULT_ON);
      ```

  - 最後還會有一個 `struct bpf_prog_stats`，還蠻小的 ([src](https://elixir.bootlin.com/linux/v5.13.11/source/include/linux/filter.h#L558)):

    ```c
    struct bpf_prog_stats {
    	u64 cnt;
    	u64 nsecs;
    	u64 misses;
    	struct u64_stats_sync syncp;
    } __aligned(2 * sizeof(u64));
    ```

到這邊為只，可以看一下 `bpf_prog` 目前長的樣子:

```c
{
  pages = 1,
  jited = 0,
  jit_requested = 1,
  gpl_compatible = 1,
  cb_access = 0,
  dst_needed = 0,
  blinded = 0,
  is_func = 0,
  kprobe_override = 0,
  has_callchain_buf = 0,
  enforce_expected_attach_type = 0,
  call_get_stack = 0,
  type = BPF_PROG_TYPE_SOCKET_FILTER,
  expected_attach_type = BPF_CGROUP_INET_INGRESS,
  len = 37,
  jited_len = 0,
  tag = "\000\000\000\000\000\000\000",
  stats = 0x607ff0c030a0,
  active = 0x607ff0c03094,
  bpf_func = 0x0 <fixed_percpu_data>,
  aux = 0xffff888006783400,
  orig_prog = 0x0 <fixed_percpu_data>,
  insns = 0xffffc9000006d048,
  insnsi = 0xffffc9000006d048
}
```



`bpf_prog_load()` 的下半部分執行 verifier，檢測 insn 本身是否合法:

```c
	...
	/* run eBPF verifier */
	err = bpf_check(&prog, attr, uattr);
	if (err < 0)
		goto free_used_maps;

	prog = bpf_prog_select_runtime(prog, &err);
	if (err < 0)
		goto free_used_maps;

	err = bpf_prog_alloc_id(prog);
	if (err)
		goto free_used_maps;

	/* Upon success of bpf_prog_alloc_id(), the BPF prog is
	 * effectively publicly exposed. However, retrieving via
	 * bpf_prog_get_fd_by_id() will take another reference,
	 * therefore it cannot be gone underneath us.
	 *
	 * Only for the time /after/ successful bpf_prog_new_fd()
	 * and before returning to userspace, we might just hold
	 * one reference and any parallel close on that fd could
	 * rip everything out. Hence, below notifications must
	 * happen before bpf_prog_new_fd().
	 *
	 * Also, any failure handling from this point onwards must
	 * be using bpf_prog_put() given the program is exposed.
	 */
	bpf_prog_kallsyms_add(prog);
	perf_event_bpf_event(prog, PERF_BPF_EVENT_PROG_LOAD, 0);
	bpf_audit_prog(prog, BPF_AUDIT_LOAD);

	err = bpf_prog_new_fd(prog);
	if (err < 0)
		bpf_prog_put(prog);
	return err;

free_used_maps:
	/* In case we have subprogs, we need to wait for a grace
	 * period before we can tear down JIT memory since symbols
	 * are already exposed under kallsyms.
	 */
	__bpf_prog_put_noref(prog, prog->aux->func_cnt);
	return err;
free_prog_sec:
	free_uid(prog->aux->user);
	security_bpf_prog_free(prog->aux);
free_prog:
	if (prog->aux->attach_btf)
		btf_put(prog->aux->attach_btf);
	bpf_prog_free(prog);
	return err;
}
```

其中 `bpf_check()` 是關鍵。



#### bpf_check() - the verifier

verifier 使用到的 struct 可以在 `include/linux/bpf_verifier.h`，主要有兩個 `bpf_verifier_env` (size: 0x1d30) 以及 `bpf_verifier_log` (size: 0x418):

```c
/* single container for all structs
 * one verifier_env per bpf_check() call
 * 一次只會有一個 bpf_verifier_env 在 bpf_check() 的執行過程
 */
struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;		/* eBPF program being verified */
	const struct bpf_verifier_ops *ops;
	struct bpf_verifier_stack_elem *head; /* stack of verifier states to be processed */
	int stack_size;			/* number of states to be processed */
	bool strict_alignment;		/* perform strict pointer alignment checks */
	bool test_state_freq;
    ...
};
```

```c
#define BPF_VERIFIER_TMP_LOG_SIZE	1024
struct bpf_verifier_log {
	u32 level;
	char kbuf[BPF_VERIFIER_TMP_LOG_SIZE];
	char __user *ubuf;
	u32 len_used;
	u32 len_total;
};
```



`bpf_check()` 上半段程式碼如下 ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/verifier.c#L13278)):

```c
int bpf_check(struct bpf_prog **prog, union bpf_attr *attr,
	      union bpf_attr __user *uattr)
{
	u64 start_time = ktime_get_ns();
	struct bpf_verifier_env *env;
	struct bpf_verifier_log *log;
	int i, len, ret = -EINVAL;
	bool is_priv;

	/* no program is valid */
	if (ARRAY_SIZE(bpf_verifier_ops) == 0)
		return -EINVAL;

	/* 'struct bpf_verifier_env' can be global, but since it's not small,
	 * allocate/free it every time bpf_check() is called
	 */
    /* allocate 用來存放 env 的 memory */
	env = kzalloc(sizeof(struct bpf_verifier_env), GFP_KERNEL);
	if (!env)
		return -ENOMEM;
    
    /* env 中也包含 log */
	log = &env->log;

	len = (*prog)->len;
    /* 每個 insn 都有一個 struct bpf_insn_aux_data */
	env->insn_aux_data =
		vzalloc(array_size(sizeof(struct bpf_insn_aux_data), len));
	ret = -ENOMEM;
	if (!env->insn_aux_data)
		goto err_free_env;
	for (i = 0; i < len; i++)
		env->insn_aux_data[i].orig_idx = i;
	env->prog = *prog;
    /* 每個 prog->type 都有不同的 verifier ops，如 fixed_percpu_data, sk_filter_verifier_ops, kprobe_verifier_ops, ... */
    /* BPF_PROG_TYPE_SOCKET_FILTER 對到 sk_filter_verifier_ops */
	env->ops = bpf_verifier_ops[env->prog->type];
	is_priv = bpf_capable(); /* capable(CAP_BPF) || capable(CAP_SYS_ADMIN) */

    /* 什麼都沒做 @_@ */
	bpf_get_btf_vmlinux();

	/* grab the mutex to protect few globals used by verifier */
    /* lock ! 保護 verifier 的 globals */
	if (!is_priv)
		mutex_lock(&bpf_verifier_lock);

	if (attr->log_level || attr->log_buf || attr->log_size) {
		/* user requested verbose verifier output
		 * and supplied buffer to store the verification trace
		 */
		log->level = attr->log_level;
		log->ubuf = (char __user *) (unsigned long) attr->log_buf;
		log->len_total = attr->log_size;

		ret = -EINVAL;
		/* log attributes have to be sane */
        /**
         * (2**31 - 1) >> 2 >= log size >= 128
         * 5 > log->level > 0
         * @BPF_LOG_MASK = 1 (l1) | 2 (l2) | 4 (stats) == 0b111
         */
		if (log->len_total < 128 || log->len_total > UINT_MAX >> 2 ||
		    !log->level || !log->ubuf || log->level & ~BPF_LOG_MASK)
			goto err_unlock;
	}

    /* 什麼都沒做, too */
	if (IS_ERR(btf_vmlinux)) {
		/* Either gcc or pahole or kernel are broken. */
		verbose(env, "in-kernel BTF is malformed\n");
		ret = PTR_ERR(btf_vmlinux);
		goto skip_full_check;
	}

    /* 沒特別設就是 false */
	env->strict_alignment = !!(attr->prog_flags & BPF_F_STRICT_ALIGNMENT);
	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
		env->strict_alignment = true;
	if (attr->prog_flags & BPF_F_ANY_ALIGNMENT)
		env->strict_alignment = false;

    /* capable(CAP_PERFMON) || capable(CAP_SYS_ADMIN) */
	env->allow_ptr_leaks = bpf_allow_ptr_leaks();
    /* capable(CAP_PERFMON) || capable(CAP_SYS_ADMIN) */
	env->allow_uninit_stack = bpf_allow_uninit_stack();
    /* capable(CAP_PERFMON) || capable(CAP_SYS_ADMIN) */
	env->allow_ptr_to_map_access = bpf_allow_ptr_to_map_access();
    /* capable(CAP_PERFMON) || capable(CAP_SYS_ADMIN) */
  	env->bypass_spec_v1 = bpf_bypass_spec_v1();
    /* capable(CAP_PERFMON) || capable(CAP_SYS_ADMIN) */
	env->bypass_spec_v4 = bpf_bypass_spec_v4();
    /* 以上都是需要 perfmon_capable() */
    
    /* capable(CAP_BPF) || capable(CAP_SYS_ADMIN)，看有無執行 bpf 的權限 */
	env->bpf_capable = bpf_capable();

	if (is_priv)
		env->test_state_freq = attr->prog_flags & BPF_F_TEST_STATE_FREQ;

    /**
     * bpf_verifier_state_list 紀錄每個 verifier 的階段，不過這邊單純 allocate ptr size
     * 因為 env->explored_states 是 pointer of pointer
     */
	env->explored_states = kvcalloc(state_htab_size(env),
				       sizeof(struct bpf_verifier_state_list *),
				       GFP_USER);
	ret = -ENOMEM;
	if (!env->explored_states)
		goto skip_full_check;

	ret = add_subprog_and_kfunc(env);
	if (ret < 0)
		goto skip_full_check;

	ret = check_subprogs(env);
	if (ret < 0)
		goto skip_full_check;

	ret = check_btf_info(env, attr, uattr);
	if (ret < 0)
		goto skip_full_check;

	ret = check_attach_btf_id(env);
	if (ret)
		goto skip_full_check;

	ret = resolve_pseudo_ldimm64(env);
	if (ret < 0)
		goto skip_full_check;

   	/* return aux->offload_requested */
	if (bpf_prog_is_dev_bound(env->prog->aux)) {
		ret = bpf_prog_offload_verifier_prep(env->prog);
		if (ret)
			goto skip_full_check;
	}

	ret = check_cfg(env);
	if (ret < 0)
		goto skip_full_check;

	ret = do_check_subprogs(env);
	ret = ret ?: do_check_main(env);

	if (ret == 0 && bpf_prog_is_dev_bound(env->prog->aux))
		ret = bpf_prog_offload_finalize(env);
	...
}
```

- 一系列的檢查:
  - `add_subprog_and_kfunc()` --> `add_subprog()` --> `find_subprog()`
    - `add_subprog()` - 新增 sub prog (淺顯易懂 ?)
    - `find_subprog()` - 用 `bsearch` 找對應 off 的 subprog，不過透過 `add_subprog_and_kfunc()` 呼叫的 off 為 0
  - `check_subprogs()`
  - 只有特定 type 的 prog 會需要做更多的檢查:
    - `check_btf_info()`
    - `check_attach_btf_id()`
  - `resolve_pseudo_ldimm64()`
  - `check_cfg()`
  - `do_check_subprogs()`
  - `do_check_main()`

`add_subprog_and_kfunc()` 新增 sub prog 以及 kfunc:

```c
static int add_subprog_and_kfunc(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprog = env->subprog_info;
	struct bpf_insn *insn = env->prog->insnsi;
	int i, ret, insn_cnt = env->prog->len;

	/* Add entry function. */
	ret = add_subprog(env, 0);
	if (ret)
		return ret;

	for (i = 0; i < insn_cnt; i++, insn++) {
        /**
         * call --> insn->code == (BPF_JMP | BPF_CALL) && insn->src_reg == BPF_PSEUDO_CALL
         * kfunc call --> insn->code == (BPF_JMP | BPF_CALL) && insn->src_reg == BPF_PSEUDO_KFUNC_CALL
         * func --> insn->code == (BPF_LD | BPF_IMM | BPF_DW) && insn->src_reg == BPF_PSEUDO_FUNC
         */
        /* 不是 func + 不是 call + 不是 kfunc --> cont */
		if (!bpf_pseudo_func(insn) && !bpf_pseudo_call(insn) &&
		    !bpf_pseudo_kfunc_call(insn))
			continue;

		if (!env->bpf_capable) {
			verbose(env, "loading/calling other bpf or kernel functions are allowed for CAP_BPF and CAP_SYS_ADMIN\n");
			return -EPERM;
		}

        /* 若為 call / kfunc call / func，就新增一個 sub prog */
		if (bpf_pseudo_func(insn)) {
			ret = add_subprog(env, i + insn->imm + 1);
			if (ret >= 0)
				/* remember subprog */
				insn[1].imm = ret;
		} else if (bpf_pseudo_call(insn)) {
			ret = add_subprog(env, i + insn->imm + 1);
		} else {
			ret = add_kfunc_call(env, insn->imm);
		}

		if (ret < 0)
			return ret;
	}

	/* Add a fake 'exit' subprog which could simplify subprog iteration
	 * logic. 'subprog_cnt' should not be increased.
	 */
    /* 假的 exit subprog @_@ ? */
	subprog[env->subprog_cnt].start = insn_cnt;

	if (env->log.level & BPF_LOG_LEVEL2)
		for (i = 0; i < env->subprog_cnt; i++)
			verbose(env, "func#%d @%d\n", i, subprog[i].start);

	return 0;
}
```

但實際上新增 subprog 是由 `add_subprog()` 完成:

```c
static int add_subprog(struct bpf_verifier_env *env, int off)
{
	int insn_cnt = env->prog->len;
	int ret;

	if (off >= insn_cnt || off < 0) {
		verbose(env, "call to invalid destination\n");
		return -EINVAL;
	}
	ret = find_subprog(env, off); /* 找 off = 0 的 subprog 是否存在 */
	if (ret >= 0)
		return ret;
	if (env->subprog_cnt >= BPF_MAX_SUBPROGS) {
		verbose(env, "too many subprograms\n");
		return -E2BIG;
	}
	/* determine subprog starts. The end is one before the next starts */
    /* env->subprog_cnt++ */
	env->subprog_info[env->subprog_cnt++].start = off;
    /* sorted by prog->start，因此新增的 subprog 會是起頭 */
	sort(env->subprog_info, env->subprog_cnt,
	     sizeof(env->subprog_info[0]), cmp_subprogs, NULL);
	return env->subprog_cnt - 1;
}
```

接著執行 `check_subprogs()`，檢查所有的 subprog 是否 JMP 都在同個 subprog:

```c
static int check_subprogs(struct bpf_verifier_env *env)
{
	int i, subprog_start, subprog_end, off, cur_subprog = 0;
	struct bpf_subprog_info *subprog = env->subprog_info;
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;

	/* now check that all jumps are within the same subprog */
    /* 檢查所有 JMP 相關的 insn 都在同個 subprog (?) */
    
    /* 當前的 subprog 的開頭 ~ 下一個 subprog 的開頭為當前 subprog 執行的週期 */
    /* 在 add_subprog_and_kfunc() 最後會有 fake subprog，就是要產生 subprog_end */
	subprog_start = subprog[cur_subprog].start;
	subprog_end = subprog[cur_subprog + 1].start;
	for (i = 0; i < insn_cnt; i++) {
		u8 code = insn[i].code;

		if (code == (BPF_JMP | BPF_CALL) &&
		    insn[i].imm == BPF_FUNC_tail_call &&
		    insn[i].src_reg != BPF_PSEUDO_CALL)
			subprog[cur_subprog].has_tail_call = true;
		if (BPF_CLASS(code) == BPF_LD &&
		    (BPF_MODE(code) == BPF_ABS || BPF_MODE(code) == BPF_IND))
			subprog[cur_subprog].has_ld_abs = true;
		if (BPF_CLASS(code) != BPF_JMP && BPF_CLASS(code) != BPF_JMP32)
			goto next;
		if (BPF_OP(code) == BPF_EXIT || BPF_OP(code) == BPF_CALL)
			goto next;
        
		off = i + insn[i].off + 1;
		if (off < subprog_start || off >= subprog_end) {
			verbose(env, "jump out of range from insn %d to %d\n", i, off);
			return -EINVAL;
		}
next:
		if (i == subprog_end - 1) {
			/* to avoid fall-through from one subprog into another
			 * the last insn of the subprog should be either exit
			 * or unconditional jump back
			 */
			if (code != (BPF_JMP | BPF_EXIT) &&
			    code != (BPF_JMP | BPF_JA)) {
				verbose(env, "last insn is not an exit or jmp\n");
				return -EINVAL;
			}
            /* 換下一個 subprog */
			subprog_start = subprog_end;
			cur_subprog++;
			if (cur_subprog < env->subprog_cnt)
				subprog_end = subprog[cur_subprog + 1].start;
		}
	}
	return 0;
}
```

`check_btf_info()` 檢查 BTF (BPF Type Format) :

```c
static int check_btf_info(struct bpf_verifier_env *env,
			  const union bpf_attr *attr,
			  union bpf_attr __user *uattr)
{
	struct btf *btf;
	int err;

	if (!attr->func_info_cnt && !attr->line_info_cnt) {
        /**
         * traverse 所有的 env->subprog_info[]，檢查是否有 has_ld_abs / has_tail_call 的情況
         * @ LD_ABS is not allowed in subprogs without BTF
         * @ tail_call is not allowed in subprogs without BTF
         */
		if (check_abnormal_return(env))
			return -EINVAL;
		return 0;
	}

    /* TODO: 以下還沒 trace 到 */
	...
	return 0;
}
```

`resolve_pseudo_ldimm64()` 找到 `ld_imm64` insn 中的 imm，並將 map_fd 轉換成 `struct bpf_map *`:

```c
/* find and rewrite pseudo imm in ld_imm64 instructions:
 *
 * 1. if it accesses map FD, replace it with actual map pointer.
 * 2. if it accesses btf_id of a VAR, replace it with pointer to the var.
 *
 * NOTE: btf_vmlinux is required for converting pseudo btf_id.
 */
static int resolve_pseudo_ldimm64(struct bpf_verifier_env *env)
{
	struct bpf_insn *insn = env->prog->insnsi; /* 取得 insn list */
	int insn_cnt = env->prog->len;
	int i, j, err;

	err = bpf_prog_calc_tag(env->prog); /* 為 prog 計算 tag，過程中會使用到 SHA1 */
	if (err)
        return err;
    /* 遍歷每個 insn */
    for (i = 0; i < insn_cnt; i++, insn++) {
        /**
         * 使用 LDX 但是不是用 MEM，或是 imm 不為 0，就代表使用到其他保留的欄位
         * 猜想是因為 LDX 在 userland 只有 BPF_LDX_MEM 能用，而使用時 imm == 0 以及 mode == BPF_MEM
         */
		if (BPF_CLASS(insn->code) == BPF_LDX &&
		    (BPF_MODE(insn->code) != BPF_MEM || insn->imm != 0)) {
			verbose(env, "BPF_LDX uses reserved fields\n");
			return -EINVAL;
		}

        /**
         * usermode 使用 BPF_LD_IMM64_RAW macro 時為 {.code  = BPF_LD | BPF_DW | BPF_IMM,...}
         * 並且只有 BPF_LD_MAP_FD 以及 BPF_LD_IMM64 macro 作為 wrapper 使用 BPF_LD_IMM64_RAW
         * 兩者差在 LD_MAP_FD 的 src 會是 BPF_PSEUDO_MAP_FD (1)，而 LD_IMM64 src 為 0
         */
		if (insn[0].code == (BPF_LD | BPF_IMM | BPF_DW)) {
			struct bpf_insn_aux_data *aux;
			struct bpf_map *map;
			struct fd f;
			u64 addr;

            /**
             * ld_imm 為最後一個 insn，或者是下一個 insn 有被使用
             * 因為 bpf_insn 只能使用 imm32，因此如果要用 imm64 的話，
             * 則需要兩個 insn，並且分別保存前 32 bits 的 imm 以及後 32 bits 的 imm
             * 而第二個 insn 除了 imm 外其他欄位階為 0
             */
			if (i == insn_cnt - 1 || insn[1].code != 0 ||
			    insn[1].dst_reg != 0 || insn[1].src_reg != 0 ||
			    insn[1].off != 0) {
				verbose(env, "invalid bpf_ld_imm64 insn\n");
				return -EINVAL;
			}

            /* 當 src_reg 不同時有不同的檢查機制，有的甚至直接當作合法的 (?) */
			if (insn[0].src_reg == 0)
				/* valid generic load 64-bit imm */
				goto next_insn;

			if (insn[0].src_reg == BPF_PSEUDO_BTF_ID) {
				aux = &env->insn_aux_data[i];
				err = check_pseudo_btf_id(env, insn, aux);
				if (err)
					return err;
				goto next_insn;
			}

			if (insn[0].src_reg == BPF_PSEUDO_FUNC) {
				aux = &env->insn_aux_data[i];
				aux->ptr_type = PTR_TO_FUNC;
				goto next_insn;
			}

			/* In final convert_pseudo_ld_imm64() step, this is
			 * converted into regular 64-bit imm load insn.
			 */
			if ((insn[0].src_reg != BPF_PSEUDO_MAP_FD &&
			     insn[0].src_reg != BPF_PSEUDO_MAP_VALUE) ||
			    (insn[0].src_reg == BPF_PSEUDO_MAP_FD &&
			     insn[1].imm != 0)) {
				verbose(env,
					"unrecognized bpf_ld_imm64 insn\n");
				return -EINVAL;
			}
			/* 使用 BPF_LD_MAP_FD 時 imm 會是 fd number，透過此 func 來取得 kernel fd struct */
			f = fdget(insn[0].imm);
            /* kernel fd struct 是用欄位 file->private 來保存檔案資料，e.g. f.file->private_data */
			map = __bpf_map_get(f);
			if (IS_ERR(map)) {
				verbose(env, "fd %d is not pointing to valid bpf_map\n",
					insn[0].imm);
				return PTR_ERR(map);
			}
			
            /**
             * Validate that trace type programs use preallocated hash maps
             * trace type 有 BPF_PROG_TYPE_KPROBE, TRACEPOINT, PERF_EVENT, RAW_TRACEPOINT
             *
             * 除此之外還檢查 spinlock 的使用，如 socket filter, tracing prog 以及 sleepable prog
             * 都不能使用 bpf_spin_lock，因為在 tracing prog tracepoint 在 locked region、或是在
             * locked region 睡著，就會造成其他的 thread 拿不到 lock
             *
             * 設計考量 (?) 只允許 sleepable prog 使用 array, hash, ringbuf maps
             */
			err = check_map_prog_compatibility(env, map, env->prog);
			if (err) {
				fdput(f);
				return err;
			}

			aux = &env->insn_aux_data[i];
            /**
             * 當 src 是 BPF_PSEUDO_MAP_FD，就會把 imm 從 fd number 改成 map addr
             * 因此 BPF_LD_MAP_FD 能夠取得指令 fd 的 map struct
             */
			if (insn->src_reg == BPF_PSEUDO_MAP_FD) {
				addr = (unsigned long)map;
			} else {
				u32 off = insn[1].imm;

				if (off >= BPF_MAX_VAR_OFF) {
					verbose(env, "direct value offset of %u is not allowed\n", off);
					fdput(f);
					return -EINVAL;
				}

				/* map 的檢測 ... */

				aux->map_off = off;
				addr += off;
			}

			insn[0].imm = (u32)addr;
			insn[1].imm = addr >> 32;

			/* check whether we recorded this map already */
			for (j = 0; j < env->used_map_cnt; j++) {
				if (env->used_maps[j] == map) { /* 找到 pre-allocate 的 map */
					aux->map_index = j; /* aux 記錄下來*/
					fdput(f); /* 將資料印出 @__@ ? */
					goto next_insn;
				}
			}

			if (env->used_map_cnt >= MAX_USED_MAPS) {
				fdput(f);
				return -E2BIG;
			}

            /* atomic 增加 map->refcnt */
			bpf_map_inc(map);

			aux->map_index = env->used_map_cnt;
			env->used_maps[env->used_map_cnt++] = map;

			if (bpf_map_is_cgroup_storage(map) &&
			    bpf_cgroup_storage_assign(env->prog->aux, map)) {
				verbose(env, "only one cgroup storage of each type is allowed\n");
				fdput(f);
				return -EBUSY;
			}

			fdput(f);
next_insn:
			insn++;
			i++;
			continue;
		}

		/* Basic sanity check before we invest more work here. */
		if (!bpf_opcode_in_insntable(insn->code)) {
			verbose(env, "unknown opcode %02x\n", insn->code);
			return -EINVAL;
		}
	}

	/* now all pseudo BPF_LD_IMM64 instructions load valid
	 * 'struct bpf_map *' into a register instead of user map_fd.
	 * These pointers will be used later by verifier to validate map access.
	 */
    /* 將 map_fd 轉換成 struct bpf_map * */
	return 0;
}
```

- 關於 `BPF_XXX` 的 macro 於 [include/uapi/linux/bpf_common.h](https://elixir.bootlin.com/linux/v5.13.11/source/include/uapi/linux/bpf_common.h) 被定義 (uapi 為 user api ?)，主要幾個重點 macro 如下:

  ```c
  /**
   * user mode 傳入的是 bpf_insn.code，而通常都會以 | 的方式將 class / size / mode 組合起來，如:
   * .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM
   */
  /* 0000 0111 */
  #define BPF_CLASS(code) ((code) & 0x07)
  #define		BPF_LD		0x00
  #define		BPF_LDX		0x01
  ...
  /* ld/ldx fields */
  /* 0001 1000 */
  #define BPF_SIZE(code)  ((code) & 0x18)
  #define		BPF_W		0x00 /* 32-bit */
  ...
  /* 1110 0000 */
  #define BPF_MODE(code)  ((code) & 0xe0)
  #define		BPF_IMM		0x00
  #define		BPF_ABS		0x20
  ...
  /* alu/jmp fields */
  /* 1111 0000 */
  #define BPF_OP(code)    ((code) & 0xf0)
  #define		BPF_ADD		0x00
  #define		BPF_SUB		0x10
  ...
      
  /* 並且在 common.h 中也有定義最多的 insn 數量為 4096 */
  #ifndef BPF_MAXINSNS
  #define BPF_MAXINSNS 4096
  ```

  - `LD` 與 `LDX` 的差別在於是否可以使用 offset，因此 X 的意思應該為 extended

下個 `check_cfg()` 程式碼意外的少，主要是用 DFS 看 BPF 內是否有 loop (back edge):

```c
static int check_cfg(struct bpf_verifier_env *env)
{
	int insn_cnt = env->prog->len;
	int *insn_stack, *insn_state;
	int ret = 0;
	int i;

    /* 標記每個 insn 是否被 discover */
	insn_state = env->cfg.insn_state = kvcalloc(insn_cnt, sizeof(int), GFP_KERNEL);
	if (!insn_state)
		return -ENOMEM;

    /* DFS stack，將目前走到的 insn push 上去 */
	insn_stack = env->cfg.insn_stack = kvcalloc(insn_cnt, sizeof(int), GFP_KERNEL);
	if (!insn_stack) {
		kvfree(insn_state);
		return -ENOMEM;
	}

    /* 第一個 insn 被走訪過 */
	insn_state[0] = DISCOVERED; /* mark 1st insn as discovered */
	insn_stack[0] = 0; /* 0 is the first instruction */
	env->cfg.cur_stack = 1; /* stack top */

	while (env->cfg.cur_stack > 0) {
		int t = insn_stack[env->cfg.cur_stack - 1];

        /* 走訪 insn */
		ret = visit_insn(t, insn_cnt, env);
		switch (ret) {
		case DONE_EXPLORING: /* EXIT */
			insn_state[t] = EXPLORED;
			env->cfg.cur_stack--;
			break;
		case KEEP_EXPLORING:
			break;
		default:
			if (ret > 0) { /* error happen */
				verbose(env, "visit_insn internal bug\n");
				ret = -EFAULT;
			}
			goto err_free;
		}
	}

    /* top 最低為 0 */
	if (env->cfg.cur_stack < 0) {
		verbose(env, "pop stack internal bug\n");
		ret = -EFAULT;
		goto err_free;
	}

    /* 有些 insn 不會被走到 */
	for (i = 0; i < insn_cnt; i++) {
		if (insn_state[i] != EXPLORED) {
			verbose(env, "unreachable insn %d\n", i);
			ret = -EINVAL;
			goto err_free;
		}
	}
	ret = 0; /* cfg looks good */

err_free:
	kvfree(insn_state);
	kvfree(insn_stack);
	env->cfg.insn_state = env->cfg.insn_stack = NULL;
	return ret;
}
```

- 看過 `kmalloc()`、`vmalloc()`，但是就沒看過  `kvcalloc()`。為 `kvmalloc_array(n, size, flags | __GFP_ZERO)` ，底層呼叫 `kvmalloc_node()`，function 的說明為:

  > ```
  > attempt to allocate physically contiguous memory, but upon failure, fall back to non-contiguous (vmalloc) allocation
  > ```

  就是一種 `kmalloc()` 以及 `vmalloc()` 混用的 fu

- 關鍵的部分在 `visit_insn()` 的回傳值:

  ```c
  /* Visits the instruction at index t and returns one of the following:
   *  < 0 - an error occurred
   *  DONE_EXPLORING - the instruction was fully explored
   *  KEEP_EXPLORING - there is still work to be done before it is fully explored
   */
  /**
   * init_explored_state(env, w)
   * env->insn_aux_data[idx].prune_point = true
   */
  /* visit insn[t] */
  static int visit_insn(int t, int insn_cnt, struct bpf_verifier_env *env)
  {
  	struct bpf_insn *insns = env->prog->insnsi;
  	int ret;
  
      /* pseudo function call */
  	if (bpf_pseudo_func(insns + t))
  		return visit_func_call_insn(t, insn_cnt, insns, env, true);
  
  	/* All non-branch instructions have a single fall-through edge. */
  	/* jmp 的 edge 為單一 (fall-through) */
  	if (BPF_CLASS(insns[t].code) != BPF_JMP &&
  	    BPF_CLASS(insns[t].code) != BPF_JMP32)
  		return push_insn(t, t + 1, FALLTHROUGH, env, false);
  
  	switch (BPF_OP(insns[t].code)) {
  	case BPF_EXIT: /* EXIT */
  		return DONE_EXPLORING;
  
  	case BPF_CALL: /* call pseudo func */
  		return visit_func_call_insn(t, insn_cnt, insns, env,
  					    insns[t].src_reg == BPF_PSEUDO_CALL);
  
  	case BPF_JA: /* jmp always */
  		if (BPF_SRC(insns[t].code) != BPF_K)
  			return -EINVAL;
  
  		/* unconditional jump with single edge */
          /* 直接跳去 offset 的地方執行 */
  		ret = push_insn(t, t + insns[t].off + 1, FALLTHROUGH, env,
  				true);
  		if (ret) /* DONE_EXPLORING */
  			return ret;
              
  		init_explored_state(env, t + insns[t].off + 1);
  		if (t + 1 < insn_cnt)
  			init_explored_state(env, t + 1);
  
  		return ret;
  
  	default:
  		/* conditional jump with two edges */
  		init_explored_state(env, t);
  		ret = push_insn(t, t + 1, FALLTHROUGH, env, true);
  		if (ret)
  			return ret;
  
  		return push_insn(t, t + insns[t].off + 1, BRANCH, env, true);
  	}
  }
  ```

  - 其中 `visit_func_call_insn()`:

    ```c
    /* 不太確定 visit_callee 的意思 */
    static int visit_func_call_insn(int t, int insn_cnt,
    				struct bpf_insn *insns,
    				struct bpf_verifier_env *env,
    				bool visit_callee)
    {
    	int ret;
    	/* function 的 edge 為單一 (fall-through) */
    	ret = push_insn(t, t + 1, FALLTHROUGH, env, false);
    	if (ret)
    		return ret;
    
    	if (t + 1 < insn_cnt)
    		init_explored_state(env, t + 1);
    	if (visit_callee) {
    		init_explored_state(env, t);
    		ret = push_insn(t, t + insns[t].imm + 1, BRANCH,
    				env, false);
    	}
    	return ret;
    }
    ```

  - `push_insn()` (這部份把 verbose 的程式碼拿掉了):

    ```c
    /* t, w, e - match pseudo-code above:
     * t - index of current instruction
     * w - next instruction
     * e - edge
     */
    /**
     * 當 function or jmp 執行 push_insn 時，loop_ok 為 false，代表不允許走到 discovered insn
     * discovered ---> discovered (X) (loop)
     * discovered ---> explored (O) (cross-edge)
     */
    static int push_insn(int t, int w, int e, struct bpf_verifier_env *env,
    		     bool loop_ok)
    {
    	int *insn_stack = env->cfg.insn_stack;
    	int *insn_state = env->cfg.insn_state;
    
        /* 已經走過了 */
    	if (e == FALLTHROUGH && insn_state[t] >= (DISCOVERED | FALLTHROUGH))
    		return DONE_EXPLORING;
    	if (e == BRANCH && insn_state[t] >= (DISCOVERED | BRANCH))
    		return DONE_EXPLORING;
    
        /* insn 不合法 */
    	if (w < 0 || w >= env->prog->len) {
    		return -EINVAL;
    	}
    
    	if (e == BRANCH)
    		/* mark branch target for state pruning */
    		init_explored_state(env, w);
    
    	if (insn_state[w] == 0) { /* 還沒 discovered */
    		/* tree-edge */
    		insn_state[t] = DISCOVERED | e;
    		insn_state[w] = DISCOVERED;
    		if (env->cfg.cur_stack >= env->prog->len)
    			return -E2BIG;
    		insn_stack[env->cfg.cur_stack++] = w; /* push to stack */
    		return KEEP_EXPLORING;
    	} else if ((insn_state[w] & 0xF0) == DISCOVERED) {
            /* function / jmp */
            /* DONE_EXPLORING 的部分在 check_cfg 才會 assign */
    		if (loop_ok && env->bpf_capable)
    			return DONE_EXPLORING;
    		return -EINVAL;
    	} else if (insn_state[w] == EXPLORED) {
    		/* forward- or cross-edge */
            /* 走到其他已經 explored 完畢的 edge */
    		insn_state[t] = DISCOVERED | e;
    	} else {
    		return -EFAULT;
    	}
    	return DONE_EXPLORING;
    }
    ```

  - insn state:

    ```c
    enum {
        /* insn 狀態 */
    	DISCOVERED = 0x10, /* 發現了，正在走 */
    	EXPLORED = 0x20, /* 此後的 insn 已經走完 */
        /* insn 對應的 bb 情況，branch 會有分岔 */
    	FALLTHROUGH = 1,
    	BRANCH = 2,
    };
    
    enum {
    	DONE_EXPLORING = 0,
    	KEEP_EXPLORING = 1,
    };
    ```

  - pseudo code:

    ```c
    procedure DFS-iterative(G,v):
        label v as discovered
        let S be a stack
        S.push(v)
        while S is not empty
              t <- S.pop()
              if t is what we are looking for:
                  return t
              for all edges e in G.adjacentEdges(t) do
                  if edge e is already labelled
                      continue with the next edge
                  w <- G.adjacentVertex(t,e)
                  if vertex w is not discovered and not explored
                      label e as tree-edge
                      label w as discovered
                      S.push(w)
                      continue at 5
                  else if vertex w is discovered
                      label e as back-edge
                  else
                      // vertex w is explored
                      label e as forward- or cross-edge
              label t as explored
              S.pop()
    ```

到此還是不太了解 subprog 是以怎樣的方式存在，也許能透過 bpf check function `do_check_subprogs()` 來更加了解:

```c
static int do_check_subprogs(struct bpf_verifier_env *env)
{
	struct bpf_prog_aux *aux = env->prog->aux;
	int i, ret;

	if (!aux->func_info)
		return 0;

	for (i = 1; i < env->subprog_cnt; i++) {
		if (aux->func_info_aux[i].linkage != BTF_FUNC_GLOBAL)
			continue;
		env->insn_idx = env->subprog_info[i].start;
		WARN_ON_ONCE(env->insn_idx == 0);
		ret = do_check_common(env, i);
		if (ret) {
			return ret;
		} else if (env->log.level & BPF_LOG_LEVEL) {
			verbose(env,
				"Func#%d is safe for any args that match its prototype\n",
				i);
		}
	}
	return 0;
}
```

- linux 在 function 上方有提供一段 useful 的註釋:

  ```
  /* Verify all global functions in a BPF program one by one based on their BTF.
   * All global functions must pass verification. Otherwise the whole program is rejected.
   * Consider:
   * int bar(int);
   * int foo(int f)
   * {
   *    return bar(f);
   * }
   * int bar(int b)
   * {
   *    ...
   * }
   * foo() will be verified first for R1=any_scalar_value. During verification it
   * will be assumed that bar() already verified successfully and call to bar()
   * from foo() will be checked for type match only. Later bar() will be verified
   * independently to check that it's safe for R1=any_scalar_value.
   */
  ```

  代表在檢查 `foo()` 時，會假設使用到的 function 皆為 verification，而在檢查 `bar()` 時會再自行檢查一次

- `do_check_subprog()` 會呼叫到 `do_common()`，而在 `bpf_check()` 當中的 `do_check_main()` 也會呼叫到 `do_common()`:

  ```c
  /**
   * main prog 的 int subprog 會是 0，而其他 subprog 會是 1, 2, 3...
   * 所有 (包含 main prog) 的 subprog 數量為 env->subprog_cnt
   */
  static int do_check_common(struct bpf_verifier_env *env, int subprog)
  {
  	bool pop_log = !(env->log.level & BPF_LOG_LEVEL2);
  	struct bpf_verifier_state *state;
  	struct bpf_reg_state *regs;
  	int ret, i;
  
  	env->prev_linfo = NULL;
  	env->pass_cnt++; /* 紀錄被 check_common 的次數，不過在其他 function 當中似乎用不到 */
  
  	state = kzalloc(sizeof(struct bpf_verifier_state), GFP_KERNEL);
  	if (!state)
  		return -ENOMEM;
  	state->curframe = 0;
  	state->speculative = false;
  	state->branches = 1;
      /* 每個 function frame 會有 10 個 register (struct bpf_reg_state regs[MAX_BPF_REG]) */
  	state->frame[0] = kzalloc(sizeof(struct bpf_func_state), GFP_KERNEL);
  	if (!state->frame[0]) {
  		kfree(state);
  		return -ENOMEM;
  	}
  	env->cur_state = state;
      /**
       * init_func_state(env, state, callsite, frameno, subprogno):
       * state->callsite = callsite;
       * state->frameno = frameno;
       * state->subprogno = subprogno;
       * init_reg_state(env, state);
       */
  	init_func_state(env, state->frame[0],
  			/* #define BPF_MAIN_FUNC (-1) */
  			BPF_MAIN_FUNC /* callsite */,
  			0 /* frameno */,
  			subprog);
  	/* 每個 frame 都會有一組 register 可以使用，what is frame @__@ ? */
  	regs = state->frame[state->curframe]->regs;
  	if (subprog /* >= 1 為 subprog */ || env->prog->type == BPF_PROG_TYPE_EXT) {
  		ret = btf_prepare_func_args(env, subprog, regs);
  		if (ret)
  			goto out;
  		for (i = BPF_REG_1; i <= BPF_REG_5; i++) {
  			if (regs[i].type == PTR_TO_CTX)
  				mark_reg_known_zero(env, regs, i);
  			else if (regs[i].type == SCALAR_VALUE)
  				mark_reg_unknown(env, regs, i);
  			else if (regs[i].type == PTR_TO_MEM_OR_NULL) {
  				const u32 mem_size = regs[i].mem_size;
  
  				mark_reg_known_zero(env, regs, i);
  				regs[i].mem_size = mem_size;
  				regs[i].id = ++env->id_gen;
  			}
  		}
  	} else { /* == 0 為 main prog */
  		/* 1st arg to a function */
          /* ctx = context, PTR_TO_CTX: reg points to bpf_context */
  		regs[BPF_REG_1].type = PTR_TO_CTX; /* func(r1, r2, ...) */
  		mark_reg_known_zero(env, regs, BPF_REG_1);
  		ret = btf_check_subprog_arg_match(env, subprog, regs);
  		if (ret == -EFAULT)
  			goto out;
  	}
  
  	ret = do_check(env);
  out:
  	/* check for NULL is necessary, since cur_state can be freed inside
  	 * do_check() under memory pressure.
  	 */
  	if (env->cur_state) {
  		free_verifier_state(env->cur_state, true);
  		env->cur_state = NULL;
  	}
  	while (!pop_stack(env, NULL, NULL, false)); /* 清空 stack (?) */
  	if (!ret && pop_log)
  		bpf_vlog_reset(&env->log, 0);
  	free_states(env);
  	return ret;
  }
  ```

  - 初始化 register state `init_reg_state()`:

    ```c
    static void init_reg_state(struct bpf_verifier_env *env,
    			   struct bpf_func_state *state)
    {
        /**
         * 注意這邊的 state type 為 bpf_func_state (state->frame[0])，
         * 而 do_check_common 的 state 為 bpf_verifier_state
         */
    	struct bpf_reg_state *regs = state->regs;
    	int i;
    
    	for (i = 0; i < MAX_BPF_REG /* 10 */; i++) {
    		mark_reg_not_init(env, regs, i);
    		regs[i].live = REG_LIVE_NONE;
    		regs[i].parent = NULL;
    		regs[i].subreg_def = DEF_NOT_SUBREG;
    	}
    
    	/* frame pointer */
    	regs[BPF_REG_FP].type = PTR_TO_STACK;
        /* 將 BPF_REG_FP (frame pointer, reg_10) mark 成 known，並將內容都設成 0 */
    	mark_reg_known_zero(env, regs, BPF_REG_FP);
    	regs[BPF_REG_FP].frameno = state->frameno;
    }
    ```

    - `mark_reg_not_init()` 滿多層的，不過大概作了以下事情來初始化 register 的狀態:

      ```c
      memset(reg, 0, offsetof(struct bpf_reg_state, var_off)); /* 將位置 ~ var_off 都設為 0 */
      reg->type = SCALAR_VALUE;
      reg->var_off = tnum_unknown;
      reg->frameno = 0;
      reg->precise = env->subprog_cnt > 1 || !env->bpf_capable;
      
      // __mark_reg_unbounded(reg);
      reg->smin_value = S64_MIN;
      reg->smax_value = S64_MAX;
      reg->umin_value = 0;
      reg->umax_value = U64_MAX;
      
      reg->s32_min_value = S32_MIN;
      reg->s32_max_value = S32_MAX;
      reg->u32_min_value = 0;
      reg->u32_max_value = U32_MAX;
      
      reg->type = NOT_INIT;
      ```

      看起來 code 的註釋想表達初始化前還有一個狀態為 **unknown**，這邊的行為就是初始化 **unknown** (?)

  - `bpf_check_subprog_arg_match()` 檢查 BTF (bpf typr format) 是否符合 regs 的 expection:

    ```c
    /**
     * 在 do_check_common() 當中，如果在做 main prog 的 arg match，如果回傳是 -EFAULT 並不是 error (?)
     * 只有 -EFAULT 會被當作 error 發生
     */
    int btf_check_subprog_arg_match(struct bpf_verifier_env *env, int subprog,
    				struct bpf_reg_state *regs)
    {
    	struct bpf_prog *prog = env->prog;
    	struct btf *btf = prog->aux->btf;
    	bool is_global;
    	u32 btf_id;
    	int err;
    
        /* 代表 subprog 並非 function ? */
    	if (!prog->aux->func_info)
    		return -EINVAL;
    
    	btf_id = prog->aux->func_info[subprog].type_id;
    	if (!btf_id)
    		return -EFAULT;
    	
        /**
         * function unreliable 代表 compiler 在 optimize 時把 static func 的參數給移除了，
         * 或是對 global function 的錯誤參數傳遞 (?)
         * 此 function 是以 BTF 觀點來檢查是否 match，因此可以先 mark 成 unreliable
         */
    	if (prog->aux->func_info_aux[subprog].unreliable)
    		return -EINVAL;
    
    	is_global = prog->aux->func_info_aux[subprog].linkage == BTF_FUNC_GLOBAL;
    	err = btf_check_func_arg_match(env, btf, btf_id, regs, is_global);
    
    	/* Compiler optimizations can remove arguments from static functions
    	 * or mismatched type can be passed into a global function.
    	 * In such cases mark the function as unreliable from BTF point of view.
    	 */
    	if (err)
    		prog->aux->func_info_aux[subprog].unreliable = true;
    	return err;
    }
    ```

    - `btf_check_func_arg_match()` 尚未 trace (太大坨 + 沒被執行到)

  - 重頭戲 `do_check()`，第一部分說明了開頭的基本檢查以及 alu operation (刪除了 verbose，細節請參閱 [src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/verifier.c#L10563)):

    ```c
    static int do_check(struct bpf_verifier_env *env)
    {
    	bool pop_log = !(env->log.level & BPF_LOG_LEVEL2);
    	struct bpf_verifier_state *state = env->cur_state;
    	struct bpf_insn *insns = env->prog->insnsi;
    	struct bpf_reg_state *regs;
    	int insn_cnt = env->prog->len;
    	bool do_print_state = false;
    	int prev_insn_idx = -1;
    
    	for (;;) {
    		struct bpf_insn *insn;
    		u8 class;
    		int err;
    
    		env->prev_insn_idx = prev_insn_idx;
            /* 超過範圍 */
    		if (env->insn_idx >= insn_cnt) {
    			return -EFAULT;
    		}
    
    		insn = &insns[env->insn_idx];
    		class = BPF_CLASS(insn->code);
    
            /* insn 太複雜，已經被處理過太多次了 */
    		if (++env->insn_processed > BPF_COMPLEXITY_LIMIT_INSNS /* 1000000 */) {
    			return -E2BIG;
    		}
    
    		err = is_state_visited(env, env->insn_idx);
    		if (err < 0)
    			return err;
    		if (err == 1) {
    			/* found equivalent state, can prune the search */
    			goto process_bpf_exit;
    		}
    
    		if (signal_pending(current)) /* 看是否有 signal 正在傳送 */
    			return -EAGAIN;
    
    		if (need_resched()) /* 也許需要 reschedule */
    			cond_resched();
    
    		if (env->log.level & BPF_LOG_LEVEL2 ||
    		    (env->log.level & BPF_LOG_LEVEL && do_print_state)) {
    			do_print_state = false;
    		}
    
    		if (bpf_prog_is_dev_bound(env->prog->aux) /* aux->offload_requested */) {
    			err = bpf_prog_offload_verify_insn(env, env->insn_idx,
    							   env->prev_insn_idx);
    			if (err)
    				return err;
    		}
    
    		regs = cur_regs(env); /* cur->frame[cur->curframe] */
            /**
             * 如果 insn 沒有要用猜的 (speculative)，則執行:
             * env->insn_aux_data[env->insn_idx].seen = env->pass_cnt
             * 為了讓後續 verify unreachable path 時，sanitize_dead_code() 還能夠 rewrite/sanitize
             */
    		sanitize_mark_insn_seen(env);
    		prev_insn_idx = env->insn_idx;
    
    		if (class == BPF_ALU || class == BPF_ALU64) {
    			err = check_alu_op(env, insn);
    			if (err)
    				return err;
    
    		}
            ...
    ```

    - class check list:

      - `ALU` | `ALU64` - `check_alu_op()`
        - `NEG`
        - `END`
        - `MOV`
        - `AND`, `SUB`, ...
      - `LDX` - `check_reg_arg()` for src and dst reg, ` check_mem_access()`, `reg_type_mismatch()`
      - `STX` - `check_reg_arg()` for src and dst reg, ` check_mem_access()`, `reg_type_mismatch()`
      - `ST` - `check_reg_arg()` for src reg, `is_ctx_reg()` for dst reg, `check_mem_access()`
      - `JMP` | `JMP32`
        - `CALL`
        - `JA`
        - `EXIT`
        - `JNE`, `JGE` ...
      - `LD` - `check_ld_abs()`, `check_ld_imm()`

    - `is_state_visited()` 用來檢查 state 是否走訪過(comment 細節在 [src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/verifier.c#L10319)):

      ```c
      static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
      {
      	struct bpf_verifier_state_list *new_sl;
      	struct bpf_verifier_state_list *sl, **pprev;
      	struct bpf_verifier_state *cur = env->cur_state, *new;
      	int i, j, err, states_cnt = 0;
      	bool add_new_state = env->test_state_freq ? true : false;
      
      	cur->last_insn_idx = env->prev_insn_idx;
          /**
           * 當初在執行 init_explored_state(env, w) 有更動到 prune_point，
      	 * (env->insn_aux_data[idx].prune_point = true)，
      	 *
      	 * 而這裡要 prunn_point 為 0 才能繼續往下走
      	 */
      	if (!env->insn_aux_data[insn_idx].prune_point)
      		return 0;
      	/* 後面還沒看 @_@ */
      }
      ```

    - 當 class 為 `ALU` 時，會執行 `check_alu_op()` 檢查 ALU 內部的 operation 是否合法:

      ```c
      /* check validity of 32-bit and 64-bit arithmetic operations */
      /**
       * ALU 的 operation 有:
       * BPF_END, BPF_NEG, BPF_MOV, BPF_SUB, ... SUB_XOR
       */
      static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
      {
      	struct bpf_reg_state *regs = cur_regs(env);
      	u8 opcode = BPF_OP(insn->code);
      	int err;
      
      	if (opcode == BPF_END || opcode == BPF_NEG) {
      		if (opcode == BPF_NEG) {
                  /**
                   * #define BPF_SRC(code)   ((code) & 0x08)
      			 * #define BPF_K 0x00
      			 * #define BPF_X 0x08
      			 * 不確定 K 與 X 的意思 @__@，不過 NEG 只能是 BPF_K
      			 * off, imm 要為 0，src_reg 要用 reg_0
                   */
      			if (BPF_SRC(insn->code) != 0 ||
      			    insn->src_reg != BPF_REG_0 ||
      			    insn->off != 0 || insn->imm != 0) {
      				verbose(env, "BPF_NEG uses reserved fields\n");
      				return -EINVAL;
      			}
      		} else {
                  /**
                   * src_reg == reg_0, off == 0, imm 要是 16/32/64，class 要是 ALU64，
                   * 進來此 function 時 class 可以是 alu or alu64
                   */
      			if (insn->src_reg != BPF_REG_0 || insn->off != 0 ||
      			    (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) ||
      			    BPF_CLASS(insn->code) == BPF_ALU64) {
      				verbose(env, "BPF_END uses reserved fields\n");
      				return -EINVAL;
      			}
      		}
      
      		/* check src operand */
              /* 檢查 dst_reg 在 type SRC_OP 時是否合法 */
      		err = check_reg_arg(env, insn->dst_reg, SRC_OP);
      		if (err)
      			return err;
      
              /* 不能 pointer operation */
      		if (is_pointer_value(env, insn->dst_reg)) {
      			return -EACCES;
      		}
      
      		/* check dest operand */
              /* 檢查 dst_reg 在 type DST_OP 時是否合法 */
      		err = check_reg_arg(env, insn->dst_reg, DST_OP);
      		if (err)
      			return err;
      
      	} else if (opcode == BPF_MOV) {
      		/* a constant (BPF_K) or the index register (BPF_X) */
      		if (BPF_SRC(insn->code) == BPF_X) {
                  /* 要 imm == 0 && off == 0 */
      			if (insn->imm != 0 || insn->off != 0) {
      				return -EINVAL;
      			}
      
      			/* check src operand */
      			err = check_reg_arg(env, insn->src_reg, SRC_OP);
      			if (err)
      				return err;
      		} else {
                  /* 要 src_reg == r0 && off == 0 */
      			if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
      				return -EINVAL;
      			}
      		}
      
      		/* check dest operand, mark as required later */
      		err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
      		if (err)
      			return err;
      
              /* 如果是 index register */
      		if (BPF_SRC(insn->code) == BPF_X) {
      			struct bpf_reg_state *src_reg = regs + insn->src_reg;
      			struct bpf_reg_state *dst_reg = regs + insn->dst_reg;
      
      			if (BPF_CLASS(insn->code) == BPF_ALU64) {
      				/* case: R1 = R2
      				 * copy register state to dest reg
      				 */
      				if (src_reg->type == SCALAR_VALUE && !src_reg->id)
      					/* Assign src and dst registers the same ID
      					 * that will be used by find_equal_scalars()
      					 * to propagate min/max range.
      					 */
      					src_reg->id = ++env->id_gen; /* same id */
      				*dst_reg = *src_reg; /* assign (r1 = r2) */
      				dst_reg->live |= REG_LIVE_WRITTEN; /* 被寫 */
      				dst_reg->subreg_def = DEF_NOT_SUBREG; /* 64bit 沒 subreg (?) */
      			} else {
      				/* R1 = (u32) R2 */
                      /* 不能 assign pointer */
      				if (is_pointer_value(env, insn->src_reg)) {
      					return -EACCES;
      				} else if (src_reg->type == SCALAR_VALUE) {
      					*dst_reg = *src_reg;
      					/* Make sure ID is cleared otherwise
      					 * dst_reg min/max could be incorrectly
      					 * propagated into src_reg by find_equal_scalars()
      					 */
      					dst_reg->id = 0;
      					dst_reg->live |= REG_LIVE_WRITTEN;
                          /* 32 bit 的 subreg_def 為 env->insn_idx + 1 */
      					dst_reg->subreg_def = env->insn_idx + 1;
      				} else {
                          /* 不是 pointer 也不是 scalar value */
      					mark_reg_unknown(env, regs,
      							 insn->dst_reg);
      				}
                      /**
                       * BPF architecture zero extends alu32 ops into 64-bit registesr (a typo)
                       */
      				zext_32_to_64(dst_reg);
      			}
      		} else {
      	        /* 如果是 imm */
      			/* case: R = imm
      			 * remember the value we stored into this reg
      			 */
      			/* clear any state __mark_reg_known doesn't set */
      			mark_reg_unknown(env, regs, insn->dst_reg);
                  /* assign an imm --> scalar value */
      			regs[insn->dst_reg].type = SCALAR_VALUE;
                  /* Mark the unknown part of a register (variable offset or scalar value) as
                   * known to have the value @imm.
                   */
      			if (BPF_CLASS(insn->code) == BPF_ALU64) {
      				__mark_reg_known(regs + insn->dst_reg,
      						 insn->imm);
      			} else {
      				__mark_reg_known(regs + insn->dst_reg,
      						 (u32)insn->imm);
      			}
      		}
      
      	} else if (opcode > BPF_END) { /* invalid */
      		return -EINVAL;
      	} else {	/* all other ALU ops: and, sub, xor, add, ... */
      		if (BPF_SRC(insn->code) == BPF_X) { /* index register */
                  /* 要 imm == 0 && off == 0 */
      			if (insn->imm != 0 || insn->off != 0) {
      				return -EINVAL;
      			}
      			/* check src1 operand */
      			err = check_reg_arg(env, insn->src_reg, SRC_OP);
      			if (err)
      				return err;
      		} else {
                  /* 要 src_reg == reg_0 && off == 0 */
                  /* reg_0 代表沒在用 */
      			if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
      				return -EINVAL;
      			}
      		}
              /* user space 中 bpf macro 結尾 _IMM 都是 BPF_K，而結尾 _REG 的都是 BPF_X */
      
      		/* check src2 operand */
      		err = check_reg_arg(env, insn->dst_reg, SRC_OP);
      		if (err)
      			return err;
      
      		if ((opcode == BPF_MOD || opcode == BPF_DIV) &&
      		    BPF_SRC(insn->code) == BPF_K && insn->imm == 0) {
      			return -EINVAL;
      		}
      
      		if ((opcode == BPF_LSH || opcode == BPF_RSH ||
      		     opcode == BPF_ARSH) && BPF_SRC(insn->code) == BPF_K) {
      			int size = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;
      
                  /* invalid shift */
      			if (insn->imm < 0 || insn->imm >= size) {
      				return -EINVAL;
      			}
      		}
      
      		/* check dest operand */
      		err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
      		if (err)
      			return err;
      
              /* Handles ALU ops other than BPF_END, BPF_NEG and BPF_MOV: computes new min/max
               * and var_off.
               */
      		return adjust_reg_min_max_vals(env, insn); /* 下方的某 section 獨立分析 */
      	}
      
      	return 0;
      }
      ```

      - 大多數都會檢查某個 operation 是否有用到不該用的欄位 (reversed field)

      `check_reg_arg()` 經常被呼叫到，會根據 reg 的 type 去做一些基本的檢查:

      ```c
      static int check_reg_arg(struct bpf_verifier_env *env, u32 regno,
      			 enum reg_arg_type t)
      {
      	struct bpf_verifier_state *vstate = env->cur_state;
      	struct bpf_func_state *state = vstate->frame[vstate->curframe];
      	struct bpf_insn *insn = env->prog->insnsi + env->insn_idx;
      	struct bpf_reg_state *reg, *regs = state->regs;
      	bool rw64;
      
          /* 使用 register 超出範圍 */
      	if (regno >= MAX_BPF_REG) {
      		return -EINVAL;
      	}
      
      	reg = &regs[regno];
          /* is_reg64(): returns TRUE if the source or destination register operates on 64-bit */
      	rw64 = is_reg64(env, insn, regno, reg, t);
      	if (t == SRC_OP) {
      		/* check whether register used as source operand can be read */
              
              /* 還沒初始化 ? */
      		if (reg->type == NOT_INIT) {
      			verbose(env, "R%d !read_ok\n", regno);
      			return -EACCES;
      		}
      		/* We don't need to worry about FP liveness because it's read-only */
              /* fp (reg10) 唯讀 */
      		if (regno == BPF_REG_FP)
      			return 0;
      
      		if (rw64)
                  /* zext == zero extended */
                  /**
                   * The dst will be zero extended, so won't be sub-register anymore.
                   * 代表有些 register 需要 sub-reg ?
                   * 
                   * env->insn_aux_data[reg->subreg_def - 1].zext_dst = true;
                   * reg->subreg_def = DEF_NOT_SUBREG;
                   */
      			mark_insn_zext(env, reg);
      		
              /**
               * 將 reg mark 成 read，並且有區分 64 and 32
               * mark_reg_read() 會 traverse reg 的 parent (因此才有 sub reg ?)
               * 而且 parent == NULL 就不會被 mark (reg->live |= flag)
               */
      		return mark_reg_read(env, reg, reg->parent,
      				     rw64 ? REG_LIVE_READ64 : REG_LIVE_READ32);
      	} else {
      		/* check whether register used as dest operand can be written to */
              
              /* fp 唯讀 */
      		if (regno == BPF_REG_FP) {
      			verbose(env, "frame pointer is read only\n");
      			return -EACCES;
      		}
              
              /* written 沒有分 32/64 */
      		reg->live |= REG_LIVE_WRITTEN;
              /* 64 就不需要 subreg，32 則需要，並且值為 env->insn_idx + 1 (下一個 insn ?) */
              /* 還不知道 subreg_def 是用來幹嘛的 */
      		reg->subreg_def = rw64 ? DEF_NOT_SUBREG : env->insn_idx + 1;
      		if (t == DST_OP) /* 此時 t 可能為 DST_OP_NO_MARK or DST_OP */
      			mark_reg_unknown(env, regs, regno);
      	}
      	return 0;
      }
      ```

      - 結論:

        1. `DST_OP` - check whether register used as dest operand can be written to
        2. `SRC_OP` - check whether register used as source operand can be read

      - `reg_arg_type` 一共有三種:

        ```c
        enum reg_arg_type {
        	SRC_OP,		/* register is used as source operand */
        	DST_OP,		/* register is used as destination operand */
        	DST_OP_NO_MARK	/* same as above, check only, don't mark */
        };
        ```

  - 第二部分說明 `BPF_LDX` 的行為:

    ```c
    	...
    	else if (class == BPF_LDX) {
    			enum bpf_reg_type *prev_src_type, src_reg_type;
    
    			/* check for reserved fields is already done */
    
    			/* check src operand */
    			err = check_reg_arg(env, insn->src_reg, SRC_OP);
    			if (err)
    				return err;
    
    			err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
    			if (err)
    				return err;
    
    			src_reg_type = regs[insn->src_reg].type;
    
    			/* check that memory (src_reg + off) is readable,
    			 * the state of dst_reg will be updated by this func
    			 */
    			err = check_mem_access(env, env->insn_idx, insn->src_reg,
    					       insn->off, BPF_SIZE(insn->code),
    					       BPF_READ, insn->dst_reg, false);
    			if (err)
    				return err;
    
    			prev_src_type = &env->insn_aux_data[env->insn_idx].ptr_type;
    
    			if (*prev_src_type == NOT_INIT) {
    				/* saw a valid insn
    				 * dst_reg = *(u32 *)(src_reg + off)
    				 * save type to validate intersecting paths
    				 */
    				*prev_src_type = src_reg_type;
    
    			} else if (reg_type_mismatch(src_reg_type, *prev_src_type)) {
    				/* ABuser program is trying to use the same insn
    				 * dst_reg = *(u32*) (src_reg + off)
    				 * with different pointer types:
    				 * src_reg == ctx in one branch and
    				 * src_reg == stack|map in some other branch.
    				 * Reject it.
    				 */
    				verbose(env, "same insn cannot be used with different pointers\n");
    				return -EINVAL;
    			}
    
    		} 
    	...
    ```

  - 第三部分為 `BPF_STX`:

    ```c
    		...
    		else if (class == BPF_STX) {
    			enum bpf_reg_type *prev_dst_type, dst_reg_type;
    
    			if (BPF_MODE(insn->code) == BPF_ATOMIC) { /* atomic operation */
    				err = check_atomic(env, env->insn_idx, insn);
    				if (err)
    					return err;
    				env->insn_idx++;
    				continue;
    			}
    
                /* reversed field */
    			if (BPF_MODE(insn->code) != BPF_MEM || insn->imm != 0) {
    				return -EINVAL;
    			}
    
    			/* check src1 operand */
                /* readable */
    			err = check_reg_arg(env, insn->src_reg, SRC_OP);
    			if (err)
    				return err;
    			
                /* check src2 operand */
                /* readable */
    			err = check_reg_arg(env, insn->dst_reg, SRC_OP);
    			if (err)
    				return err;
    
    			dst_reg_type = regs[insn->dst_reg].type;
    
    			/* check that memory (dst_reg + off) is writeable */
                /* BPF_READ = 1
                 * BPF_WRITE = 2 
                 */
    			err = check_mem_access(env, env->insn_idx, insn->dst_reg,
    					       insn->off, BPF_SIZE(insn->code),
    					       BPF_WRITE, insn->src_reg, false);
    			if (err)
    				return err;
    
                /* 當前的 ptr type */
    			prev_dst_type = &env->insn_aux_data[env->insn_idx].ptr_type;
    
    			if (*prev_dst_type == NOT_INIT) {
                    /* regs[insn->dst_reg].type */
    				*prev_dst_type = dst_reg_type;
    			} else if (reg_type_mismatch(dst_reg_type /* src */, *prev_dst_type /* dst */)) {
                    /* return src != prev (reg type 不同，代表 different type)
                     * && (!reg_type_mismatch_ok(src) || !reg_type_mismatch_ok(prev))
    			     *
    			     * reg_type_mismatch_ok():
    			     * Return true if it's OK to have the same insn return a different type
    			     * PTR_TO_CTX, PTR_TO_SOCKET, ... 都會回傳 false
    			     */
                    
                    /* 相同的 insn 不能用不同的 pointer (?) */
    				verbose(env, "same insn cannot be used with different pointers\n");
    				return -EINVAL;
    			}
    		} 
    		...
    ```

  - 其中有一個 `check_mem_access()` 被頻繁使用到，目的是用來檢查 `(regno + off)` 是否可存取，並且根據不同的 `bpf_access_type` 有不同的行為 ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/verifier.c#L4038)):

    - 檢查當 `t = (read | write)` 時， memory at `(regno + off)` 是否可以存取
    - `t = write` --> `regno` 為其值要被放入 memory 當中的 register
    - `t = read` --> `regno` 為要被寫入 memory 內的值的 register
    - `t = write && regno == -1` --> unknown  value 要被存入 memory
    - `t = read && regno == -1` -- > 不管我們讀什麼

    ```c
    static int check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regno,
    			    int off, int bpf_size, enum bpf_access_type t,
    			    int value_regno, bool strict_alignment_once)
    {
    	struct bpf_reg_state *regs = cur_regs(env);
    	struct bpf_reg_state *reg = regs + regno;
    	struct bpf_func_state *state;
    	int size, err = 0;
    
    	size = bpf_size_to_bytes(bpf_size); /* 看是 BPF_W, BPF_DW 等等就會對到 4, 8 ... */
    	if (size < 0)
    		return size;
    
    	/* alignment checks will add in reg->off themselves */
        /* 加上 offset 之後需要做對齊的 check，必須要 align size */
    	err = check_ptr_alignment(env, reg, off, size, strict_alignment_once);
    	if (err)
    		return err;
    
    	/* for access checks, reg->off is just part of off */
    	off += reg->off;
    
    	if (reg->type == PTR_TO_MAP_KEY) { /* map key */
    		if (t == BPF_WRITE) { /* 不能 change key */
    			return -EACCES;
    		}
    		
            /* check read/write into a memory region with possible variable offset */
    		err = check_mem_region_access(env, regno, off, size,
    					      reg->map_ptr->key_size, false);
    		if (err)
    			return err;
    		if (value_regno >= 0)
    			mark_reg_unknown(env, regs, value_regno);
    	} else if (reg->type == PTR_TO_MAP_VALUE) {
    		if (t == BPF_WRITE && value_regno >= 0 &&
                /* 	return allow_ptr_leaks ? false : reg->type != SCALAR_VALUE; */
    		    is_pointer_value(env, value_regno)) {
    			return -EACCES;
    		}
            /* type == BPF_WRITE && !(bpf_map_flags_to_cap(map) & BPF_MAP_CAN_WRITE)
             * type == BPF_READ && !(bpf_map_flags_to_cap(map) & BPF_MAP_CAN_READ)
             * will return -EACCES
             */
    		err = check_map_access_type(env, regno, off, size, t);
    		if (err)
    			return err;
            /* 沒有 spinlock 的話，check_map_access() 就是 check_mem_region_access() 的 wrapper */
    		err = check_map_access(env, regno, off, size, false);
    		if (!err && t == BPF_READ && value_regno >= 0) {
    			struct bpf_map *map = reg->map_ptr;
    
    			/* if map is read-only, track its contents as scalars */
    			if (tnum_is_const(reg->var_off) &&
    			    bpf_map_is_rdonly(map) &&
    			    map->ops->map_direct_value_addr) {
    				int map_off = off + reg->var_off.value;
    				u64 val = 0;
    
    				err = bpf_map_direct_read(map, map_off, size,
    							  &val);
    				if (err)
    					return err;
    
    				regs[value_regno].type = SCALAR_VALUE;
    				__mark_reg_known(&regs[value_regno], val);
    			} else {
    				mark_reg_unknown(env, regs, value_regno);
    			}
    		}
    	} else if (reg->type == PTR_TO_MEM) {
    		if (t == BPF_WRITE && value_regno >= 0 &&
    		    is_pointer_value(env, value_regno)) { /* 不給 leak */
    			return -EACCES;
    		}
    		err = check_mem_region_access(env, regno, off, size,
    					      reg->mem_size, false);
    		if (!err && t == BPF_READ && value_regno >= 0) /* 寫成 unknown */
    			mark_reg_unknown(env, regs, value_regno);
    	} else if (reg->type == PTR_TO_CTX) {
    		enum bpf_reg_type reg_type = SCALAR_VALUE;
    		struct btf *btf = NULL;
    		u32 btf_id = 0;
    
    		if (t == BPF_WRITE && value_regno >= 0 &&
    		    is_pointer_value(env, value_regno)) { /* 不給 leak */
    			return -EACCES;
    		}
    
    		err = check_ctx_reg(env, reg, regno);
    		if (err < 0)
    			return err;
    
    		err = check_ctx_access(env, insn_idx, off, size, t, &reg_type, &btf, &btf_id);
            /* CTX 的部分還沒看 */
    		if (!err && t == BPF_READ && value_regno >= 0) {
    			/* ctx access returns either a scalar, or a
    			 * PTR_TO_PACKET[_META,_END]. In the latter
    			 * case, we know the offset is zero.
    			 */
    			if (reg_type == SCALAR_VALUE) {
    				mark_reg_unknown(env, regs, value_regno);
    			} else {
    				mark_reg_known_zero(env, regs,
    						    value_regno);
    				if (reg_type_may_be_null(reg_type))
    					regs[value_regno].id = ++env->id_gen;
    				/* A load of ctx field could have different
    				 * actual load size with the one encoded in the
    				 * insn. When the dst is PTR, it is for sure not
    				 * a sub-register.
    				 */
    				regs[value_regno].subreg_def = DEF_NOT_SUBREG;
    				if (reg_type == PTR_TO_BTF_ID ||
    				    reg_type == PTR_TO_BTF_ID_OR_NULL) {
    					regs[value_regno].btf = btf;
    					regs[value_regno].btf_id = btf_id;
    				}
    			}
    			regs[value_regno].type = reg_type;
    		}
    
    	} else if (reg->type == PTR_TO_STACK) {
    		/* Basic bounds checks. */
            /* Check that the stack access at 'regno + off' falls within the maximum stack bounds */
    		err = check_stack_access_within_bounds(env, regno, off, size, ACCESS_DIRECT, t);
    		if (err)
    			return err;
    
            /* return env->cur_state->frame[reg->frameno] */
            state = func(env, reg);
            /* 如果原本 stack size 比較小，就執行
             * env->subprog_info[func->subprogno].stack_depth = -off
             */
    		err = update_stack_depth(env, state, off);
    		if (err)
    			return err;
    
            /* 這兩個 check_stack 好大坨 @__@，之後在看 */
    		if (t == BPF_READ)
    			err = check_stack_read(env, regno, off, size,
    					       value_regno);
    		else
    			err = check_stack_write(env, regno, off, size,
    						value_regno, insn_idx);
    	} else if (reg_is_pkt_pointer(reg)) {
    		/* pass packet */
    	} else if (reg->type == PTR_TO_FLOW_KEYS) {
    		/* pass flow keys */
    	} else if (type_is_sk_pointer(reg->type)) {
    		/* pass socket */
    	} else if (reg->type == PTR_TO_TP_BUFFER) {
    		/* pass tp buffer */
    	} else if (reg->type == PTR_TO_BTF_ID) {
    		/* pass btf id */
    	} else if (reg->type == CONST_PTR_TO_MAP) {
    		err = check_ptr_to_map_access(env, regs, regno, off, size, t,
    					      value_regno);
    	} else if (reg->type == PTR_TO_RDONLY_BUF) {
    		if (t == BPF_WRITE) { /* read only */
    			return -EACCES;
    		}
    		err = check_buffer_access(env, reg, regno, off, size, false,
    					  "rdonly",
    					  &env->prog->aux->max_rdonly_access);
    		if (!err && value_regno >= 0)
    			mark_reg_unknown(env, regs, value_regno);
    	} else if (reg->type == PTR_TO_RDWR_BUF) {
    		err = check_buffer_access(env, reg, regno, off, size, false,
    					  "rdwr",
    					  &env->prog->aux->max_rdwr_access);
    		if (!err && t == BPF_READ && value_regno >= 0)
    			mark_reg_unknown(env, regs, value_regno);
    	} else {
    		/* invalid mem access */
    		return -EACCES;
    	}
        /* 到這邊發現，如果 operation 是 BPF_READ (or read 相關的 ?)，register 就會被 mark 成 unknown，
         * 作用為將幾乎整個 struct 設為 0
         */
    
        /* BPF_WRITE 不需要 */
    	if (!err && size < BPF_REG_SIZE && value_regno >= 0 && t == BPF_READ &&
    	    regs[value_regno].type == SCALAR_VALUE) {
    		/* b/h/w load zero-extends, mark upper bits as known 0 */
            /* truncate register to smaller size (in bytes) */
            /* https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/verifier.c#L3778 */
    		coerce_reg_to_size(&regs[value_regno], size);
    	}
    	return err;
    }
    ```

    - 各種 check memory/reg 的權限，其中 `check_mem_region_access()` 的分析如下:

      ```c
      static int check_mem_region_access(struct bpf_verifier_env *env, u32 regno,
      				   int off, int size, u32 mem_size,
      				   bool zero_size_allowed)
      {
      	struct bpf_verifier_state *vstate = env->cur_state;
      	struct bpf_func_state *state = vstate->frame[vstate->curframe];
      	struct bpf_reg_state *reg = &state->regs[regno];
      	int err;
      
      	...
      
          /* smin 為 neg，並且
           * smin 為最小值 (不能在低) || off + reg->smin_value 在 cast 成 32 後 != 原本的值 ||
           * reg->smin_value + off 為負數
           */
      	if (reg->smin_value < 0 &&
      	    (reg->smin_value == S64_MIN ||
      	     (off + reg->smin_value != (s64)(s32)(off + reg->smin_value)) ||
      	      reg->smin_value + off < 0)) {
      		return -EACCES;
      	}
      	err = __check_mem_access(env, regno, reg->smin_value + off, size,
      				 mem_size, zero_size_allowed);
      	if (err) {
      		return err;
      	}
      
      	/* If we haven't set a max value then we need to bail since we can't be
      	 * sure we won't do bad things.
      	 * If reg->umax_value + off could overflow, treat that as unbounded too.
      	 */
          /* unbounded memory access */
      	if (reg->umax_value >= BPF_MAX_VAR_OFF /* (1 << 29), 0x20000000 */) {
      		return -EACCES;
      	}
      	err = __check_mem_access(env, regno, reg->umax_value + off, size,
      				 mem_size, zero_size_allowed);
      	if (err) {
      		return err;
      	}
      
      	return 0;
      }
      ```

    - `__check_mem_access()` 檢查 memory region read/write:

      ```c
      /* check read/write into memory region (e.g., map value, ringbuf sample, etc) */
      static int __check_mem_access(struct bpf_verifier_env *env, int regno,
      			      int off, int size, u32 mem_size,
      			      bool zero_size_allowed)
      {
      	bool size_ok = size > 0 || (size == 0 && zero_size_allowed);
      	struct bpf_reg_state *reg;
      
      	if (off >= 0 && size_ok && (u64)off + size <= mem_size)
      		return 0;
      
      	reg = &cur_regs(env)[regno];
      	switch (reg->type) {
              /* 到此已經代表 invalid，只是根據不同的 type 有不同的 verbose */
      	}
      
      	return -EACCES;
      }
      ```

    - stack 的 bound check function `check_stack_access_within_bounds()`:

      ```c
      /* 'off' includes `regno->offset`, but not its dynamic part (if any). */
      /* ACCESS_DIRECT = 1,  the access is performed by an instruction
       * ACCESS_HELPER = 2,  the access is performed by a helper
       */
      static int check_stack_access_within_bounds(
      		struct bpf_verifier_env *env,
      		int regno, int off, int access_size,
      		enum stack_access_src src, enum bpf_access_type type)
      {
      	struct bpf_reg_state *regs = cur_regs(env);
      	struct bpf_reg_state *reg = regs + regno;
      	struct bpf_func_state *state = func(env, reg);
      	int min_off, max_off;
      	int err;
      	char *err_extra;
      
      	if (src == ACCESS_HELPER)
      		/* We don't know if helpers are reading or writing (or both). */
      		err_extra = " indirect access to";
      	else if (type == BPF_READ)
      		err_extra = " read from";
      	else
      		err_extra = " write to";
      
          /* var_off 存的是 struct tnum
           * mask 為 1 代表未知，!mask 為 true 代表都知道了 --> const
           */
      	if (tnum_is_const(reg->var_off) /* !reg->var_off.mask */) {
      		min_off = reg->var_off.value + off;
      		if (access_size > 0)
                  /* access_size 為 user 傳入的 W, DW 等等 */
      			max_off = min_off + access_size - 1;
      		else
      			max_off = min_off;
      	} else {
              /* invalid unbounded variable-offset */
      		if (reg->smax_value >= BPF_MAX_VAR_OFF /* >= 0x20000000 */ ||
      		    reg->smin_value <= -BPF_MAX_VAR_OFF /* <= -0x20000000 */) {
      			return -EACCES;
      		}
      		min_off = reg->smin_value + off;
      		if (access_size > 0)
      			max_off = reg->smax_value + off + access_size - 1;
      		else
      			max_off = min_off;
      	}
      	/* Check that the stack access at the given offset is within bounds
      	 * maximum valid offset is -1
      	 * minimum valid offset is -MAX_BPF_STACK (-512) for write, -state->allocated_stack for
      	 * read
      	 *
      	 * 也就是 stack access 的 range 為 -1 <= off <= -MAX_BPF_STACK
      	 */
      	err = check_stack_slot_within_bounds(min_off, state, type);
      	if (!err)
      		err = check_stack_slot_within_bounds(max_off, state, type);
      
      	if (err) {
      		/* verbose */
      	}
      	return err;
      }
      ```

  - 第四部份為 `BPF_ST`:

    ```c
    		...
    		else if (class == BPF_ST) {
    			if (BPF_MODE(insn->code) != BPF_MEM ||
    			    insn->src_reg != BPF_REG_0) {
    				verbose(env, "BPF_ST uses reserved fields\n");
    				return -EINVAL;
    			}
    			/* check src operand */
    			err = check_reg_arg(env, insn->dst_reg, SRC_OP);
    			if (err)
    				return err;
    
    			if (is_ctx_reg(env, insn->dst_reg)) {
    				verbose(env, "BPF_ST stores into R%d %s is not allowed\n",
    					insn->dst_reg,
    					reg_type_str[reg_state(env, insn->dst_reg)->type]);
    				return -EACCES;
    			}
    
    			/* check that memory (dst_reg + off) is writeable */
    			err = check_mem_access(env, env->insn_idx, insn->dst_reg,
    					       insn->off, BPF_SIZE(insn->code),
    					       BPF_WRITE, -1, false);
    			if (err)
    				return err;
    
    		}
    		...
    ```

  - 第五部分為 `JMP` 系列:

    ```c
    		...
    		else if (class == BPF_JMP || class == BPF_JMP32) {
    			u8 opcode = BPF_OP(insn->code);
    
    			env->jmps_processed++;
                /* function call */
    			if (opcode == BPF_CALL) {
                    /* reserved fields */
    				if (BPF_SRC(insn->code) != BPF_K ||
    				    insn->off != 0 ||
    				    (insn->src_reg != BPF_REG_0 &&
    				     insn->src_reg != BPF_PSEUDO_CALL &&
    				     insn->src_reg != BPF_PSEUDO_KFUNC_CALL) ||
    				    insn->dst_reg != BPF_REG_0 ||
    				    class == BPF_JMP32) {
    					return -EINVAL;
    				}
    
                    /* function call 不能 hold lock */
    				if (env->cur_state->active_spin_lock &&
    				    (insn->src_reg == BPF_PSEUDO_CALL ||
    				     insn->imm != BPF_FUNC_spin_unlock)) {
    					return -EINVAL;
    				}
    				if (insn->src_reg == BPF_PSEUDO_CALL)
    					err = check_func_call(env, insn, &env->insn_idx);
    				else if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL)
    					err = check_kfunc_call(env, insn);
    				else
    					err = check_helper_call(env, insn, &env->insn_idx);
                    
    				if (err)
    					return err;
    			} else if (opcode == BPF_JA) {
                    /* reserved field */
    				if (BPF_SRC(insn->code) != BPF_K ||
    				    insn->imm != 0 ||
    				    insn->src_reg != BPF_REG_0 ||
    				    insn->dst_reg != BPF_REG_0 ||
    				    class == BPF_JMP32) {
    					return -EINVAL;
    				}
    				
                    /* 直接跳過 insn->off 個 insn */
    				env->insn_idx += insn->off + 1;
    				continue;
    
    			} else if (opcode == BPF_EXIT) {
                    /* reserved field */
    				if (BPF_SRC(insn->code) != BPF_K ||
    				    insn->imm != 0 ||
    				    insn->src_reg != BPF_REG_0 ||
    				    insn->dst_reg != BPF_REG_0 ||
    				    class == BPF_JMP32) {
    					return -EINVAL;
    				}
    
                    /* missing spinlock，應該是要被 release 的 ? */
    				if (env->cur_state->active_spin_lock) {
    					return -EINVAL;
    				}
    
    				if (state->curframe) {
    					/* exit from nested function */
    					err = prepare_func_exit(env, &env->insn_idx);
    					if (err)
    						return err;
    					do_print_state = true;
    					continue;
    				}
    
    				err = check_reference_leak(env);
    				if (err)
    					return err;
    
    				err = check_return_code(env);
    				if (err)
    					return err;
    process_bpf_exit:
    				update_branch_counts(env, env->cur_state);
    				err = pop_stack(env, &prev_insn_idx,
    						&env->insn_idx, pop_log);
    				if (err < 0) {
    					if (err != -ENOENT)
    						return err;
    					break;
    				} else {
    					do_print_state = true;
    					continue;
    				}
    			} else { /* 其他的 condition jump */
    				err = check_cond_jmp_op(env, insn, &env->insn_idx);
    				if (err)
    					return err;
    			}
    		}
    	...
    ```

    - 一共有三種呼叫方式:

      - `BPF_PSEUDO_CALL` - `check_func_call()`
      - `BPF_PSEUDO_KFUNC_CALL` - `check_kfunc_call()`
      - other - `check_helper_call()`

    - `check_helper_call()`，在 `__BPF_FUNC_MAPPER` ([src](https://elixir.bootlin.com/linux/v5.13.11/source/include/uapi/linux/bpf.h#L4739)) 當中有定義 fn 對應到的 function:

      ```c
      static int check_helper_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
      			     int *insn_idx_p)
      {
      	const struct bpf_func_proto *fn = NULL;
      	struct bpf_reg_state *regs;
      	struct bpf_call_arg_meta meta;
      	int insn_idx = *insn_idx_p;
      	bool changes_data;
      	int i, err, func_id;
      
      	/* find function prototype */
      	func_id = insn->imm;
      	if (func_id < 0 || func_id >= __BPF_FUNC_MAX_ID /* 165 */) {
      		return -EINVAL;
      	}
      
          /* e.g. sk_filter_func_proto */
      	if (env->ops->get_func_proto)
              /* 舉 lookup_elem 為例子，
               * 一開始執行 sk_filter_func_proto，一層層找對應 fund_id 以及 type 的 func proto，
               * 最後在 bpf_base_func_proto 找到 bpf_map_lookup_elem_proto
               */
      		fn = env->ops->get_func_proto(func_id, env->prog);
      	if (!fn) { /* unknown */
      		return -EINVAL;
      	}
      
      	/* eBPF programs must be GPL compatible to use GPL-ed functions */
          /* license 必須要是 GPL 的 */
      	if (!env->prog->gpl_compatible && fn->gpl_only) {
      		return -EINVAL;
      	}
      
          /* 不允許在 probe 階段呼叫 */
      	if (fn->allowed && !fn->allowed(env->prog)) {
      		return -EINVAL;
      	}
      
      	/* With LD_ABS/IND some JITs save/restore skb from r1. */
          /* 有些 func 會修改到 pkt 的內容 */
      	changes_data = bpf_helper_changes_pkt_data(fn->func);
          /* 如果會修改 pkt 的內容，但是 r1 卻不要求指向 ctx，為 misconfig */
      	if (changes_data && fn->arg1_type != ARG_PTR_TO_CTX) {
      		return -EINVAL;
      	}
      
      	memset(&meta, 0, sizeof(meta));
      	meta.pkt_access = fn->pkt_access;
      
          /* check_raw_mode_ok() - arg type 為 ARG_PTR_TO_UNINIT_MEM 只能有一個
           * check_arg_pair_ok() - 另一個滿有趣的限制 - arg1 不能是 const type，arg5 不能是 ptr_to_mem type
           *						，以及 argn 跟 argn+1 必須要是 (ptr, size) or (size, ptr)，
           *    					否則就不能用 ptr
           * check_btf_id_ok() - ARG_PTR_TO_BTF_ID 跟 fn->arg_btf_id[i] 必須同時有 / 同時沒有
           * check_refcount_ok() - arg type 為 ARG_PTR_TO_SOCK_COMMON 只能有一個 (unref)
           */
      	err = check_func_proto(fn, func_id);
      	if (err) { /* misconfig */
      		return err;
      	}
      
      	meta.func_id = func_id;
      	/* check args */
      	for (i = 0; i < MAX_BPF_FUNC_REG_ARGS /* 5 */; i++) {
              /* 有點大坨，還沒看 */
      		err = check_func_arg(env, i, &meta, fn);
      		if (err)
      			return err;
      	}
      
          /* 更新 env->insn_aux_data[insn_idx]->map_ptr_state */
      	err = record_func_map(env, &meta, func_id, insn_idx);
      	if (err)
      		return err;
          
          /* 更新 env->insn_aux_data[insn_idx]->map_key_state */
      	err = record_func_key(env, &meta, func_id, insn_idx);
      	if (err)
      		return err;
      
      	/* Mark slots with STACK_MISC in case of raw mode, stack offset
      	 * is inferred from register state.
      	 */
      	for (i = 0; i < meta.access_size; i++) { /* 前面整個 meta 都被設成 0 了不是 (?) */
      		err = check_mem_access(env, insn_idx, meta.regno, i, BPF_B,
      				       BPF_WRITE, -1, false);
      		if (err)
      			return err;
      	}
      
      	if (func_id == BPF_FUNC_tail_call) {
      		/* ... */
      	} else if (is_release_function(func_id)) {
      		/* ... */
      	}
      
      	regs = cur_regs(env);
      
      	if (func_id == BPF_FUNC_get_local_storage &&
              /* get storage 的 reg2 要是 null */
      	    !register_is_null(&regs[BPF_REG_2])) {
      		return -EINVAL;
      	}
      
      	if (func_id == BPF_FUNC_for_each_map_elem) {
      		err = __check_func_call(env, insn, insn_idx_p, meta.subprogno,
      					set_map_elem_callback_state);
      		if (err < 0)
      			return -EINVAL;
      	}
      
      	if (func_id == BPF_FUNC_snprintf) {
      		err = check_bpf_snprintf_call(env, regs);
      		if (err < 0)
      			return err;
      	}
      
      	/* reset caller saved regs */
      	for (i = 0; i < CALLER_SAVED_REGS; i++) {
              /* __mark_reg_unknown(env, reg); reg->type = NOT_INIT; */
      		mark_reg_not_init(env, regs, caller_saved[i]);
      		check_reg_arg(env, caller_saved[i], DST_OP_NO_MARK);
      	}
      
      	/* helper call returns 64-bit value. */
      	regs[BPF_REG_0].subreg_def = DEF_NOT_SUBREG; /* why 32 bit needs a subreg */
      
      	/* update return register (already marked as written above) */
      	if (fn->ret_type == RET_INTEGER) {
      		/* sets type to SCALAR_VALUE */
              /* unknown 意即 scalar value (?) */
      		mark_reg_unknown(env, regs, BPF_REG_0);
      	} else if (fn->ret_type == RET_VOID) {
              /* return void 的情況代表 reg not init (?) */
      		regs[BPF_REG_0].type = NOT_INIT;
      	} else if (fn->ret_type == RET_PTR_TO_MAP_VALUE_OR_NULL ||
      		   fn->ret_type == RET_PTR_TO_MAP_VALUE) {
              /* 還沒有 offset，因此先設為 zero */
      		mark_reg_known_zero(env, regs, BPF_REG_0);
      		/* meta.map_ptr 在 check_func_arg 設置的，指向 map address */
              /* https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/verifier.c#L4927 */
      		if (meta.map_ptr == NULL) {
      			return -EINVAL;
      		}
      		regs[BPF_REG_0].map_ptr = meta.map_ptr;
      		if (fn->ret_type == RET_PTR_TO_MAP_VALUE) {
      			regs[BPF_REG_0].type = PTR_TO_MAP_VALUE;
      			if (map_value_has_spin_lock(meta.map_ptr))
      				regs[BPF_REG_0].id = ++env->id_gen;
      		} else {
      			regs[BPF_REG_0].type = PTR_TO_MAP_VALUE_OR_NULL;
      		}
          } else if (...) {
      	    /* 省略一些 else if 的 case，行為大同小異 */
      	} else if (fn->ret_type == RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL ||
      		/* 頗亂，先 pass */
      	} else if (fn->ret_type == RET_PTR_TO_BTF_ID_OR_NULL ||
      		   fn->ret_type == RET_PTR_TO_BTF_ID) {
      		/* 頗亂，先 pass */	
      	} else { /* unknown */
      		return -EINVAL;
      	}
      	/* 感覺 return type 結尾為 _OR_NULL 的，reg0 都會先設為 known_zero */
      
          /* 只要 return type 後面有 _OR_NULL 都 return true */
      	if (reg_type_may_be_null(regs[BPF_REG_0].type))
              /* 為 reg assign 一個 id，當 return or_null 或是 spinlock 都會，還有其他少數特例 */
      		regs[BPF_REG_0].id = ++env->id_gen;
      
      	if (is_ptr_cast_function(func_id)) { /* func_id 為 BPF_FUNC prefix */
      		/* For release_reference() */
      		regs[BPF_REG_0].ref_obj_id = meta.ref_obj_id;
      	} else if (is_acquire_function(func_id, meta.map_ptr)) {
      		/* 看不太懂，先 pass */
      	}
      
      	do_refine_retval_range(regs, fn->ret_type, func_id, &meta);
      
      	/* 這是因為 func 有時候只能用某些 map，而 map 也有相對應的 func，
      	 * 因此要從 map & func 的觀點分別作檢查
      	 */
      	err = check_map_func_compatibility(env, meta.map_ptr, func_id);
      	if (err)
      		return err;
      
      	/* 有 function 的 type 與 get stack / get task stack 相關 */
      	if ((func_id == BPF_FUNC_get_stack ||
      	     func_id == BPF_FUNC_get_task_stack) &&
      	    !env->prog->has_callchain_buf) {
      		if (err) {
      			return err;
      		}
      		env->prog->has_callchain_buf = true;
      	}
      
      	if (func_id == BPF_FUNC_get_stackid || func_id == BPF_FUNC_get_stack)
      		env->prog->call_get_stack = true;
      
      	/* return value of bpf_helper_changes_pkt_data(fn->func)
      	 * 可能會改變 pkt 內容的 func
      	 */
      	if (changes_data)
      		/* Packet data might have moved, any old PTR_TO_PACKET[_META,_END]
               * are now invalid, so turn them into unknown SCALAR_VALUE.
               *
               * 大概就是只要 reg 存著指向 pkt 的 pointer，就呼叫 mark_reg_unknown() 將其設為 unknown
               * 不過 function 中有 spilled register，不確定是什麼
               */
      		clear_all_pkt_pointers(env);
      	return 0;
      }
      ```

      - 不同 helper function 使用到的 func prototype 不太一樣，可以參考 [src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/helpers.c#L36)，下方為使用到的 struct `bpf_func_proto`:

        ```c
        /* eBPF function prototype used by verifier to allow BPF_CALLs from eBPF programs
         * to in-kernel helper functions and for adjusting imm32 field in BPF_CALL
         * instructions after verifying
         */
        struct bpf_func_proto {
        	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
        	bool gpl_only;
        	bool pkt_access;
        	enum bpf_return_type ret_type;
        	union {
        		struct {
        			enum bpf_arg_type arg1_type;
        			enum bpf_arg_type arg2_type;
        			enum bpf_arg_type arg3_type;
        			enum bpf_arg_type arg4_type;
        			enum bpf_arg_type arg5_type;
        		};
        		enum bpf_arg_type arg_type[5];
        	};
        	union {
        		struct {
        			u32 *arg1_btf_id;
        			u32 *arg2_btf_id;
        			u32 *arg3_btf_id;
        			u32 *arg4_btf_id;
        			u32 *arg5_btf_id;
        		};
        		u32 *arg_btf_id[5];
        	};
        	int *ret_btf_id; /* return value btf_id */
        	bool (*allowed)(const struct bpf_prog *prog);
        };
        
        /* example */
        const struct bpf_func_proto bpf_map_lookup_elem_proto = {
        	.func		= bpf_map_lookup_elem,
        	.gpl_only	= false,
        	.pkt_access	= true,
        	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
        	.arg1_type	= ARG_CONST_MAP_PTR, /* r1 要放指向 map 的 ptr，userland 可以用 BPF_LD_MAP_FD 取得˙*/
        	.arg2_type	= ARG_PTR_TO_MAP_KEY, /* key */
        };
        ```

      - condition jmp 像是 JNE, 等等 `check_cond_jmp_op` ([src](https://elixir.bootlin.com/linux/v5.13.11/source/kernel/bpf/verifier.c#L8690)):

        ```c
        static int check_cond_jmp_op(struct bpf_verifier_env *env,
        			     struct bpf_insn *insn, int *insn_idx)
        {
        	struct bpf_verifier_state *this_branch = env->cur_state;
        	struct bpf_verifier_state *other_branch;
        	struct bpf_reg_state *regs = this_branch->frame[this_branch->curframe]->regs;
        	struct bpf_reg_state *dst_reg, *other_branch_regs, *src_reg = NULL;
        	u8 opcode = BPF_OP(insn->code);
        	bool is_jmp32;
        	int pred = -1;
        	int err;
        
        	/* Only conditional jumps are expected to reach here. */
            /* 不過為什麼會到這邊 @__@ ? */
        	if (opcode == BPF_JA || opcode > BPF_JSLE) {
        		return -EINVAL;
        	}
        
        	if (BPF_SRC(insn->code) == BPF_X) {
        		if (insn->imm != 0) { /* BPF_X 用 register */
        			return -EINVAL;
        		}
        
        		/* check src1 operand */
        		err = check_reg_arg(env, insn->src_reg, SRC_OP);
        		if (err)
        			return err;
        
                /* 不能比 ptr */
        		if (is_pointer_value(env, insn->src_reg)) {
        			return -EACCES;
        		}
        		src_reg = &regs[insn->src_reg];
        	} else {
        		if (insn->src_reg != BPF_REG_0) { /* BPF_K */
        			return -EINVAL;
        		}
        	}
        
        	/* check src2 operand */
        	err = check_reg_arg(env, insn->dst_reg, SRC_OP);
        	if (err)
        		return err;
        
        	dst_reg = &regs[insn->dst_reg];
        	is_jmp32 = BPF_CLASS(insn->code) == BPF_JMP32; /* if false, jmp64 */
        
        	if (BPF_SRC(insn->code) == BPF_K) { /* 用 imm */
                /* prediction */
        		pred = is_branch_taken(dst_reg, insn->imm, opcode, is_jmp32);
        	} else if (src_reg->type == SCALAR_VALUE &&
        		   is_jmp32 && tnum_is_const(tnum_subreg(src_reg->var_off))) {
                /* 用 src_reg 的 value 
                 * 並且 jmp32，
                 * 由於 jmp32 的關係也使用 subreg (tnum_cast(a, 4))
                 */
        		pred = is_branch_taken(dst_reg,
        				       tnum_subreg(src_reg->var_off).value,
        				       opcode,
        				       is_jmp32);
        	} else if (src_reg->type == SCALAR_VALUE &&
        		   !is_jmp32 && tnum_is_const(src_reg->var_off)) {
                /* 跟上面只差在 jmp64 */
        		pred = is_branch_taken(dst_reg,
        				       src_reg->var_off.value,
        				       opcode,
        				       is_jmp32);
        	} else if (/* 與 pkt (packet) 相關 */) { ... }
        
            /* 1 - taken, 0 - not taken, -1 - unknown */
        	if (pred >= 0) {
        		/* If we get here with a dst_reg pointer type it is because
        		 * above is_branch_taken() special cased the 0 comparison.
        		 */
                /* mark_chain == Markov chain (?) */
        		if (!__is_pointer_value(false, dst_reg))
        			err = mark_chain_precision(env, insn->dst_reg);
        		if (BPF_SRC(insn->code) == BPF_X && !err &&
        		    !__is_pointer_value(false, src_reg))
        			err = mark_chain_precision(env, insn->src_reg);
        		if (err)
        			return err;
        	}
        
        	if (pred == 1) {
        		/* Only follow the goto, ignore fall-through. If needed, push
        		 * the fall-through branch for simulation under speculative
        		 * execution.
        		 */
        		if (!env->bypass_spec_v1 &&
        		    !sanitize_speculative_path(env, insn, *insn_idx + 1,
        					       *insn_idx))
        			return -EFAULT;
        		*insn_idx += insn->off;
        		return 0;
        	} else if (pred == 0) {
        		/* Only follow the fall-through branch, since that's where the
        		 * program will go. If needed, push the goto branch for
        		 * simulation under speculative execution.
        		 */
        		if (!env->bypass_spec_v1 &&
        		    !sanitize_speculative_path(env, insn,
        					       *insn_idx + insn->off + 1,
        					       *insn_idx))
        			return -EFAULT;
        		return 0;
        	}
        
            /* 得到新的 struct bpf_verifier_state */
        	other_branch = push_stack(env, *insn_idx + insn->off + 1, *insn_idx,
        				  false);
        	if (!other_branch)
        		return -EFAULT;
        	other_branch_regs = other_branch->frame[other_branch->curframe]->regs;
        
            /* 檢查是否正在與 const value 比較，讓我們可以調整 dst_reg 的 min/max，
             * 只有在 src/dst 都是 scalar (或指向同個 obj 的 ptr in future） 時才合法，
             * 否則不同的 base ptr 代表著 offset 不可比較
             */
            /* 設置 register value range 的 function - reg_set_min_max() */
        	if (BPF_SRC(insn->code) == BPF_X) { /* register operation */
        		struct bpf_reg_state *src_reg = &regs[insn->src_reg];
        
                /* 都是 scalar */
        		if (dst_reg->type == SCALAR_VALUE &&
        		    src_reg->type == SCALAR_VALUE) {
        			if (tnum_is_const(src_reg->var_off) ||
        			    (is_jmp32 &&
        			     tnum_is_const(tnum_subreg(src_reg->var_off))))
        				reg_set_min_max(&other_branch_regs[insn->dst_reg],
        						dst_reg,
        						src_reg->var_off.value,
        						tnum_subreg(src_reg->var_off).value,
        						opcode, is_jmp32);
        			else if (tnum_is_const(dst_reg->var_off) ||
        				 (is_jmp32 &&
        				  tnum_is_const(tnum_subreg(dst_reg->var_off))))
        				reg_set_min_max_inv(&other_branch_regs[insn->src_reg],
        						    src_reg,
        						    dst_reg->var_off.value,
        						    tnum_subreg(dst_reg->var_off).value,
        						    opcode, is_jmp32);
        			else if (!is_jmp32 &&
        				 (opcode == BPF_JEQ || opcode == BPF_JNE))
        				/* Comparing for equality, we can combine knowledge */
        				reg_combine_min_max(&other_branch_regs[insn->src_reg],
        						    &other_branch_regs[insn->dst_reg],
        						    src_reg, dst_reg, opcode);
        			if (src_reg->id &&
        			    !WARN_ON_ONCE(src_reg->id != other_branch_regs[insn->src_reg].id)) {
        				find_equal_scalars(this_branch, src_reg);
        				find_equal_scalars(other_branch, &other_branch_regs[insn->src_reg]);
        			}
        
        		}
        	} else if (dst_reg->type == SCALAR_VALUE) {
        		reg_set_min_max(&other_branch_regs[insn->dst_reg],
        					dst_reg, insn->imm, (u32)insn->imm,
        					opcode, is_jmp32);
        	}
        
        	if (dst_reg->type == SCALAR_VALUE && dst_reg->id &&
        	    !WARN_ON_ONCE(dst_reg->id != other_branch_regs[insn->dst_reg].id)) {
        		find_equal_scalars(this_branch, dst_reg);
        		find_equal_scalars(other_branch, &other_branch_regs[insn->dst_reg]);
        	}
        
        	/* detect if R == 0 where R is returned from bpf_map_lookup_elem().
        	 * NOTE: these optimizations below are related with pointer comparison
        	 *       which will never be JMP32.
        	 */
        	if (!is_jmp32 && BPF_SRC(insn->code) == BPF_K &&
        	    insn->imm == 0 && (opcode == BPF_JEQ || opcode == BPF_JNE) &&
        	    reg_type_may_be_null(dst_reg->type)) {
        		/* Mark all identical registers in each branch as either
        		 * safe or unknown depending R == 0 or R != 0 conditional.
        		 */
                /* 如果 ret_type 是 _OR_NULL，則會被 mark 成 unknown_zero or not_null */
                /* 突然想到 reg->id 是否為 ticket spinlock 取得號碼牌的機制 */
        		mark_ptr_or_null_regs(this_branch, insn->dst_reg,
        				      opcode == BPF_JNE);
        		mark_ptr_or_null_regs(other_branch, insn->dst_reg,
        				      opcode == BPF_JEQ);
        	} else if (...) {
        		return -EACCES;
        	}
        	return 0;
        }
        ```

        - check branch taken 相關的 function `is_branch_taken()`:

          ```c
          /* compute branch direction of the expression "if (reg opcode val) goto target;"
           * and return:
           *  1 - branch will be taken and "goto target" will be executed
           *  0 - branch will not be taken and fall-through to next insn
           * -1 - unknown. Example: "if (reg < 5)" is unknown when register value
           *      range [0,10]
           */
          static int is_branch_taken(struct bpf_reg_state *reg, u64 val, u8 opcode,
          			   bool is_jmp32)
          {
          	if (__is_pointer_value(false, reg) /* reg->type != SCALAR_VALUE */) {
                  /* return
                   * PTR_TO_SOCKET ||
                   * PTR_TO_TCP_SOCK ||
                   * PTR_TO_MAP_VALUE ||
                   * PTR_TO_MAP_KEY ||
                   * PTR_TO_SOCK_COMMON
                   */
          		if (!reg_type_not_null(reg->type))
          			return -1;
          
          		/* If pointer is valid tests against zero will fail so we can
          		 * use this to direct branch taken.
          		 */
          		if (val != 0)
          			return -1;
          
          		switch (opcode) {
          		case BPF_JEQ:
          			return 0;
          		case BPF_JNE:
          			return 1;
          		default: /* make sense，大於小於相關的都不確定 */
          			return -1;
          		}
          	}
          
          	if (is_jmp32)
          		return is_branch32_taken(reg, val, opcode);
          	return is_branch64_taken(reg, val, opcode);
          }
          ```

        - `sanitize_speculative_path()`:

          ```c
          static struct bpf_verifier_state *
          sanitize_speculative_path(struct bpf_verifier_env *env,
          			  const struct bpf_insn *insn,
          			  u32 next_idx, u32 curr_idx)
          {
          	struct bpf_verifier_state *branch;
          	struct bpf_reg_state *regs;
          
          	branch = push_stack(env, next_idx, curr_idx, true);
          	if (branch && insn) {
          		regs = branch->frame[branch->curframe]->regs;
          		if (BPF_SRC(insn->code) == BPF_K) {
          			mark_reg_unknown(env, regs, insn->dst_reg);
          		} else if (BPF_SRC(insn->code) == BPF_X) {
          			mark_reg_unknown(env, regs, insn->dst_reg);
          			mark_reg_unknown(env, regs, insn->src_reg);
          		}
          	}
          	return branch;
          }
          ```

        - `push_stack()` 新增一個 `bpf_verifier_stack_elem` element:

          ```c
          static struct bpf_verifier_state *push_stack(struct bpf_verifier_env *env,
          					     int insn_idx, int prev_insn_idx,
          					     bool speculative)
          {
          	struct bpf_verifier_state *cur = env->cur_state;
          	struct bpf_verifier_stack_elem *elem;
          	int err;
          
          	elem = kzalloc(sizeof(struct bpf_verifier_stack_elem), GFP_KERNEL);
          	if (!elem)
          		goto err;
          
              /* copy value to elem */
          	elem->insn_idx = insn_idx;
          	elem->prev_insn_idx = prev_insn_idx;
          	elem->next = env->head;
          	elem->log_pos = env->log.len_used;
          	env->head = elem;
          	env->stack_size++;
              /* copy 當前的整個 struct bpf_verifier_state */
          	err = copy_verifier_state(&elem->st, cur);
          	if (err)
          		goto err;
              /* elem->st 為 element state */
          	elem->st.speculative |= speculative;
          	if (env->stack_size > BPF_COMPLEXITY_LIMIT_JMP_SEQ) { /* jmp size 過於複雜 */
          		goto err;
          	}
          	if (elem->st.parent) {
          		++elem->st.parent->branches;
          	}
          	return &elem->st;
          err:
          	free_verifier_state(env->cur_state, true);
          	env->cur_state = NULL;
          	/* pop all elements and return */
          	while (!pop_stack(env, NULL, NULL, false));
          	return NULL;
          }
          ```

          

      

  - 最後一個部分為 `BPF_LD`:

    ```c
    		... 	
    		else if (class == BPF_LD) {
                /* BPF_IMM   0x00
                 * BPF_ABS   0x20
                 * BPF_IND   0x40
                 * BPF_MEM   0x60
                 * BPF_LEN   0x80
                 * BPF_MSH   0xa0
                 */
    			u8 mode = BPF_MODE(insn->code);
                
    			if (mode == BPF_ABS || mode == BPF_IND) {
    				err = check_ld_abs(env, insn);
    				if (err)
    					return err;
    
    			} else if (mode == BPF_IMM) {
    				err = check_ld_imm(env, insn);
    				if (err)
    					return err;
    
    				env->insn_idx++; /* BPF_LD_IMM64_RAW，所以下個 insn 不看 (存 imm 後 32 bit) */
    				sanitize_mark_insn_seen(env); /* mark 成看過的 */
    			} else { /* ABS IND IMM 都不是 */
    				return -EINVAL;
    			}
    		} else  /* 未知的 insn class (invalid) */
    			return -EINVAL;
    		}
    
    		env->insn_idx++;
    	}
    
    	return 0;
    }
    ```

    - 其中兩個 check_ld function `check_ld_abs()` 以及 `check_ld_imm()`

    - `check_ld_abs()` 確保兩件事:

      - 當 ctx == skb (socket buffer) 才會出現 `LD_ABS|LD_IND` insn

      - 會使用到 R1-R5 regs

      - R6-R9 不會 touch，並且將 return value 放在 R0

      ```c
      static int check_ld_abs(struct bpf_verifier_env *env, struct bpf_insn *insn)
      {
      	struct bpf_reg_state *regs = cur_regs(env);
      	static const int ctx_reg = BPF_REG_6;
      	u8 mode = BPF_MODE(insn->code);
      	int i, err;
      
          /* 此 prog type 不能使用 ABS|IND */
      	if (!may_access_skb(resolve_prog_type(env->prog))) {
      		return -EINVAL;
      	}
      
      	if (!env->ops->gen_ld_abs) { /* misconfigured */
      		return -EINVAL;
      	}
      
          /* uses reserved fields */
      	if (insn->dst_reg != BPF_REG_0 || insn->off != 0 ||
      	    BPF_SIZE(insn->code) == BPF_DW ||
      	    (mode == BPF_ABS && insn->src_reg != BPF_REG_0)) {
      		return -EINVAL;
      	}
      
      	/* check whether implicit source operand (register R6) is readable */
          /* r6 存放 skb data，確保可以讀 (SRC_OP) */
      	err = check_reg_arg(env, ctx_reg, SRC_OP);
      	if (err)
      		return err;
      
      	err = check_reference_leak(env); /* ABS|IND 不能與 socket ref 同時用 (?) */
      	if (err) {
      		return err;
      	}
      
          /* 不能在 bpf_spin_lock active 時用 */
      	if (env->cur_state->active_spin_lock) {
      		return -EINVAL;
      	}
      
      	if (regs[ctx_reg].type != PTR_TO_CTX) { /* r6 不指向 ctx */
      		return -EINVAL;
      	}
      
      	if (mode == BPF_IND) {
              /* src_reg 是否可讀 */
      		err = check_reg_arg(env, insn->src_reg, SRC_OP);
      		if (err)
      			return err;
      	}
      	/* reg->off 是 ctx ptr 的 offset
           *
           * 確保只能讀取 unmodified form:
           * - reg->off == 0
           * - tnum_is_const(reg->var_off)
           * - !reg->var_off.value
           */
      	err = check_ctx_reg(env, &regs[ctx_reg], ctx_reg);
      	if (err < 0)
      		return err;
      
      	/* reset caller saved regs to unreadable */
      	for (i = 0; i < CALLER_SAVED_REGS; i++) {
      		mark_reg_not_init(env, regs, caller_saved[i]);
      		check_reg_arg(env, caller_saved[i], DST_OP_NO_MARK);
      	}
      
      	/* mark destination R0 register as readable, since it contains
      	 * the value fetched from the packet.
      	 * Already marked as written above.
      	 */
          /* unknown 就是 readable 嗎 ? */
      	mark_reg_unknown(env, regs, BPF_REG_0);
      	/* ld_abs load up to 32-bit skb data. */
      	regs[BPF_REG_0].subreg_def = env->insn_idx + 1;
      	return 0;
      }
      ```

    - `check_ld_imm()`:

      ```c
      /* verify BPF_LD_IMM64 instruction */
      static int check_ld_imm(struct bpf_verifier_env *env, struct bpf_insn *insn)
      {
      	struct bpf_insn_aux_data *aux = cur_aux(env); /* &env->insn_aux_data[env->insn_idx] */
          /* cur_func(env)->regs
           * cur_func: env->cur_state->frame[env->cur_state->curframe]
           */
      	struct bpf_reg_state *regs = cur_regs(env); 
      	struct bpf_reg_state *dst_reg;
      	struct bpf_map *map;
      	int err;
      
      	if (BPF_SIZE(insn->code) != BPF_DW) { /* 要是 imm64 */
      		return -EINVAL;
      	}
          /* reserved field */
      	if (insn->off != 0) {
      		return -EINVAL;
      	}
      	
          /* 確定可寫 */
      	err = check_reg_arg(env, insn->dst_reg, DST_OP);
      	if (err)
      		return err;
      
      	dst_reg = &regs[insn->dst_reg];
      	if (insn->src_reg == 0) {
              /* 因為 64 bits 是由兩個 insn 組成 */
      		u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;
      
      		dst_reg->type = SCALAR_VALUE;
      		__mark_reg_known(&regs[insn->dst_reg], imm);
      		return 0;
      	}
      
      	if (insn->src_reg == BPF_PSEUDO_BTF_ID /* 3 */) {
      		mark_reg_known_zero(env, regs, insn->dst_reg);
      		/* 沒有很理解 BTF_ID 的功能也沒用過 */
      		return 0;
      	}
      
      	if (insn->src_reg == BPF_PSEUDO_FUNC) {
      		struct bpf_prog_aux *aux = env->prog->aux;
      		u32 subprogno = insn[1].imm;
      
      		if (!aux->func_info) { /* miss func_info */
      			return -EINVAL;
      		}
              /* callback function 要是靜態的 */
              /* aux->func_info_aux[subprogno] 指向 callback function ? */
      		if (aux->func_info_aux[subprogno].linkage != BTF_FUNC_STATIC) {
      			return -EINVAL;
      		}
      
      		dst_reg->type = PTR_TO_FUNC;
      		dst_reg->subprogno = subprogno;
      		return 0;
      	}
      
      	map = env->used_maps[aux->map_index];
      	mark_reg_known_zero(env, regs, insn->dst_reg); /* 將大多資料設成 0 */
      	dst_reg->map_ptr = map;
      
          /* 沒看懂 */
      	if (insn->src_reg == BPF_PSEUDO_MAP_VALUE) {
      		dst_reg->type = PTR_TO_MAP_VALUE;
      		dst_reg->off = aux->map_off;
      		if (map_value_has_spin_lock(map))
      			dst_reg->id = ++env->id_gen;
      	} else if (insn->src_reg == BPF_PSEUDO_MAP_FD) {
      		dst_reg->type = CONST_PTR_TO_MAP; /* BPF_PSEUDO_MAP_FD 的目的是要讀 map address */
      	} else {
      		return -EINVAL;
      	}
      
      	return 0;
      }
      ```

      - `env->insn_aux_data[env->insn_idx]` 為 insn 的 metadata







#### Adjust min max 

adjust min max 系列一共有三個 function:

- `adjust_reg_min_max_vals()` - register，不過只有在 `check_alu_op()` 被執行
- `adjust_ptr_min_max_vals()` - pointer，在 `adjust_reg_min_max_vals()` 被執行
- `adjust_scalar_min_max_vals()` - scalar，在 `adjust_reg_min_max_vals()` 被執行

`adjust_reg_min_max_vals()`:

```c
static int adjust_reg_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	struct bpf_func_state *state = vstate->frame[vstate->curframe];
	struct bpf_reg_state *regs = state->regs, *dst_reg, *src_reg;
	struct bpf_reg_state *ptr_reg = NULL, off_reg = {0};
	u8 opcode = BPF_OP(insn->code);
	int err;

	dst_reg = &regs[insn->dst_reg];
	src_reg = NULL;
	if (dst_reg->type != SCALAR_VALUE)
		ptr_reg = dst_reg;
	else
		/* Make sure ID is cleared otherwise dst_reg min/max could be
		 * incorrectly propagated into other registers by find_equal_scalars()
		 */
		dst_reg->id = 0;
	if (BPF_SRC(insn->code) == BPF_X) {
		src_reg = &regs[insn->src_reg];
		if (src_reg->type != SCALAR_VALUE) {
			if (dst_reg->type != SCALAR_VALUE) {
				/* Combining two pointers by any ALU op yields
				 * an arbitrary scalar. Disallow all math except
				 * pointer subtraction
				 */
				if (opcode == BPF_SUB && env->allow_ptr_leaks) {
					mark_reg_unknown(env, regs, insn->dst_reg);
					return 0;
				}
				verbose(env, "R%d pointer %s pointer prohibited\n",
					insn->dst_reg,
					bpf_alu_string[opcode >> 4]);
				return -EACCES;
			} else {
				/* scalar += pointer
				 * This is legal, but we have to reverse our
				 * src/dest handling in computing the range
				 */
				err = mark_chain_precision(env, insn->dst_reg);
				if (err)
					return err;
				return adjust_ptr_min_max_vals(env, insn,
							       src_reg, dst_reg);
			}
		} else if (ptr_reg) {
			/* pointer += scalar */
			err = mark_chain_precision(env, insn->src_reg);
			if (err)
				return err;
			return adjust_ptr_min_max_vals(env, insn,
						       dst_reg, src_reg);
		}
	} else {
		/* Pretend the src is a reg with a known value, since we only
		 * need to be able to read from this state.
		 */
		off_reg.type = SCALAR_VALUE;
		__mark_reg_known(&off_reg, insn->imm);
		src_reg = &off_reg;
		if (ptr_reg) /* pointer += K */
			return adjust_ptr_min_max_vals(env, insn,
						       ptr_reg, src_reg);
	}

	/* Got here implies adding two SCALAR_VALUEs */
	if (WARN_ON_ONCE(ptr_reg)) {
		print_verifier_state(env, state);
		verbose(env, "verifier internal error: unexpected ptr_reg\n");
		return -EINVAL;
	}
	if (WARN_ON(!src_reg)) {
		print_verifier_state(env, state);
		verbose(env, "verifier internal error: no src_reg\n");
		return -EINVAL;
	}
	return adjust_scalar_min_max_vals(env, insn, dst_reg, *src_reg);
}
```







insn 的 struct `bpf_insn`:

```c
struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};
```

insn 的輔助 struct `bpf_insn_aux_data`:

```c
struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;	/* pointer type for load/store insns */
		unsigned long map_ptr_state;	/* pointer/poison value for maps */
		s32 call_imm;			/* saved imm field of call insn */
		u32 alu_limit;			/* limit for add/sub register with pointer */
		struct {
			u32 map_index;		/* index into used_maps[] */
			u32 map_off;		/* offset from value base address */
		};
		struct {
			enum bpf_reg_type reg_type;	/* type of pseudo_btf_id */
			union {
				struct {
					struct btf *btf;
					u32 btf_id;	/* btf_id for struct typed var */
				};
				u32 mem_size;	/* mem_size for non-struct typed var */
			};
		} btf_var;
	};
	u64 map_key_state; /* constant (32 bit) key tracking for maps */
	int ctx_field_size; /* the ctx field size for load insn, maybe 0 */
	u32 seen; /* this insn was processed by the verifier at env->pass_cnt */
	bool sanitize_stack_spill; /* subject to Spectre v4 sanitation */
	bool zext_dst; /* this insn zero extends dst reg */
	u8 alu_state; /* used in combination with alu_limit */

	/* below fields are initialized once */
	unsigned int orig_idx; /* original instruction index */
	bool prune_point;
};
```

state list 的 struct `bpf_verifier_state_list`:

```c
/* linked list of verifier states used to prune search */
struct bpf_verifier_state_list {
	struct bpf_verifier_state state;BPF_REG_
	struct bpf_verifier_state_list *next;
	int miss_cnt, hit_cnt;
};
```

而 `bpf_verifier_state` 則是 ([src](https://elixir.bootlin.com/linux/v5.13.11/source/include/linux/bpf_verifier.h#L226) 有提供一些 comment 幫助理解):

```c
/* Maximum number of register states that can exist at once */
#define BPF_ID_MAP_SIZE (MAX_BPF_REG + MAX_BPF_STACK / BPF_REG_SIZE)
#define MAX_CALL_FRAMES 8
struct bpf_verifier_state {
	struct bpf_func_state *frame[MAX_CALL_FRAMES];
	struct bpf_verifier_state *parent;
	u32 branches;
	u32 insn_idx;
	u32 curframe;
	u32 active_spin_lock;
	bool speculative;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_idx_pair *jmp_history;
	u32 jmp_history_cnt;
};
```











`bpf_check()` 下半段:

```c
	...
	skip_full_check:
	kvfree(env->explored_states);

	if (ret == 0)
		ret = check_max_stack_depth(env);

	/* instruction rewrites happen after this point */
	if (is_priv) {
		if (ret == 0)
			opt_hard_wire_dead_code_branches(env);
		if (ret == 0)
			ret = opt_remove_dead_code(env);
		if (ret == 0)
			ret = opt_remove_nops(env);
	} else {
		if (ret == 0)
			sanitize_dead_code(env);
	}

	if (ret == 0)
		/* program is valid, convert *(u32*)(ctx + off) accesses */
		ret = convert_ctx_accesses(env);

	if (ret == 0)
		ret = do_misc_fixups(env);

	/* do 32-bit optimization after insn patching has done so those patched
	 * insns could be handled correctly.
	 */
	if (ret == 0 && !bpf_prog_is_dev_bound(env->prog->aux)) {
		ret = opt_subreg_zext_lo32_rnd_hi32(env, attr);
		env->prog->aux->verifier_zext = bpf_jit_needs_zext() ? !ret
								     : false;
	}

	if (ret == 0)
		ret = fixup_call_args(env);

	env->verification_time = ktime_get_ns() - start_time;
	print_verification_stats(env);

	if (log->level && bpf_verifier_log_full(log))
		ret = -ENOSPC;
	if (log->level && !log->ubuf) {
		ret = -EFAULT;
		goto err_release_maps;
	}

	if (ret)
		goto err_release_maps;

	if (env->used_map_cnt) {
		/* if program passed verifier, update used_maps in bpf_prog_info */
		env->prog->aux->used_maps = kmalloc_array(env->used_map_cnt,
							  sizeof(env->used_maps[0]),
							  GFP_KERNEL);

		if (!env->prog->aux->used_maps) {
			ret = -ENOMEM;
			goto err_release_maps;
		}

		memcpy(env->prog->aux->used_maps, env->used_maps,
		       sizeof(env->used_maps[0]) * env->used_map_cnt);
		env->prog->aux->used_map_cnt = env->used_map_cnt;
	}
	if (env->used_btf_cnt) {
		/* if program passed verifier, update used_btfs in bpf_prog_aux */
		env->prog->aux->used_btfs = kmalloc_array(env->used_btf_cnt,
							  sizeof(env->used_btfs[0]),
							  GFP_KERNEL);
		if (!env->prog->aux->used_btfs) {
			ret = -ENOMEM;
			goto err_release_maps;
		}

		memcpy(env->prog->aux->used_btfs, env->used_btfs,
		       sizeof(env->used_btfs[0]) * env->used_btf_cnt);
		env->prog->aux->used_btf_cnt = env->used_btf_cnt;
	}
	if (env->used_map_cnt || env->used_btf_cnt) {
		/* program is valid. Convert pseudo bpf_ld_imm64 into generic
		 * bpf_ld_imm64 instructions
		 */
		convert_pseudo_ld_imm64(env);
	}

	adjust_btf_func(env);

err_release_maps:
	if (!env->prog->aux->used_maps)
		/* if we didn't copy map pointers into bpf_prog_info, release
		 * them now. Otherwise free_used_maps() will release them.
		 */
		release_maps(env);
	if (!env->prog->aux->used_btfs)
		release_btfs(env);

	/* extension progs temporarily inherit the attach_type of their targets
	   for verification purposes, so set it back to zero before returning
	 */
	if (env->prog->type == BPF_PROG_TYPE_EXT)
		env->prog->expected_attach_type = 0;

	*prog = env->prog;
err_unlock:
	if (!is_priv)
		mutex_unlock(&bpf_verifier_lock);
	vfree(env->insn_aux_data);
err_free_env:
	kfree(env);
	return ret;
}
```
