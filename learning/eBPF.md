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

`resolve_pseudo_ldimm64()` 找到 `ld_imm64` insn 中的 imm:

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
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i, j, err;

	err = bpf_prog_calc_tag(env->prog); /* 為 prog 計算 tag，過程中會使用到 SHA1 */
	if (err)
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
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
	int miss_cnt, hit_cnt;
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

