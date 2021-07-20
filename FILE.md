## FILE

##### Struct

```c
// libio/bits/libio.h

struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */ //0x0
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */ // 0x8
  char* _IO_read_end;	/* End of get area. */ // 0x10
  char* _IO_read_base;	/* Start of putback+get area. */ // 0x18
  char* _IO_write_base;	/* Start of put area. */ // // 0x20
  char* _IO_write_ptr;	/* Current put pointer. */ // 0x28
  char* _IO_write_end;	/* End of put area. */ // 0x30
  char* _IO_buf_base;	/* Start of reserve area. */ // 0x38
  char* _IO_buf_end;	/* End of reserve area. */ // 0x40
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */ // 0x48
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */ // 0x50
  char *_IO_save_end; /* Pointer to end of non-current get area. */ // 0x58

  struct _IO_marker *_markers; // 0x60

  struct _IO_FILE *_chain; // 0x68

  int _fileno; // 0x70
#if 0
  int _blksize;
#else
  int _flags2; // 0x74
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */ // 0x78

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column; // 0x80
  signed char _vtable_offset; // 0x82
  char _shortbuf[1]; // 0x73

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock; // 0x88
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset; // 0x90
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt; // 0x98
  struct _IO_wide_data *_wide_data; // 0xa0
  struct _IO_FILE *_freeres_list; // 0xa8
  void *_freeres_buf; // 0xb0
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5; // 0xb8
  int _mode; // 0xc0
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)]; // 0xc4 - 0xd8
#endif
};
```

flag macro:

```c
#define _IO_MAGIC 0xFBAD0000 /* Magic number */
#define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
#define _IO_UNBUFFERED 2
#define _IO_NO_READS 4 /* Reading not allowed */
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
#define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/
#define _IO_IN_BACKUP 0x100
#define _IO_LINE_BUF 0x200
#define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
#define _IO_BAD_SEEN 0x4000
#define _IO_USER_LOCK 0x8000
```

Example:

```c
{
  file = {
    _flags = 0xfbad2288, // 0x1-0x8 (0x1-0x4 + 4 padding zero bytes)
    _IO_read_ptr = 0x5555555596b1, // 0x9-0x10
    _IO_read_end = 0x555555559ab0 , // 0x11-0x18
    _IO_read_base = 0x5555555596b0, // 0x19-0x20
    _IO_write_base = 0x5555555596b0, // 0x21-0x28
    _IO_write_ptr = 0x5555555596b0, // 0x29-0x30
    _IO_write_end = 0x5555555596b0, // 0x31-0x38
    _IO_buf_base = 0x5555555596b0, // 0x39-0x40
    _IO_buf_end = 0x555555559ab0, // 0x41-0x48
    _IO_save_base = 0x0, // 0x49-0x50
    _IO_backup_base = 0x0, // 0x51-0x58
    _IO_save_end = 0x0, // 0x59-0x60
    _markers = 0x0, // 0x61-0x68
    _chain = 0x0, // 0x69-0x70
    _fileno = 0, // 0x71-0x74
    _flags2 = 0, // 0x75-0x78
    _old_offset = -1, // 0x79-0x80
    _cur_column = 0, // 0x81-0x82
    _vtable_offset = 0 '\000', // 0x83
    _shortbuf = "", // 0x84
    _lock = 0x7ffff7fa84d0 <_IO_stdfile_0_lock>, // 0x89-0x90
    _offset = -1, // 0x91-0x98
    _codecvt = 0x0, // 0x99-0xa0
    _wide_data = 0x7ffff7fa5a60 <_IO_wide_data_0>, // 0xa1-0xa8
    _freeres_list = 0x0, // 0xa9-0xb0
    _freeres_buf = 0x0, // 0xb1-0xb8
    __pad5 = 0, // 0xb9-0xc0
    _mode = -1, // 0xc1-0xc4
    _unused2 = '\000' <repeats 19 times> // 0xc5-0xd8 (20)
  },
  vtable = 0x7ffff7fa74a0 <_IO_file_jumps> // 0xd8-0xe0
}
```

##### fread

```c
// /libio/iofread.c

_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t bytes_requested = size * count;
  _IO_size_t bytes_read;
  CHECK_FILE (fp, 0); /* nothing */
  if (bytes_requested == 0)
    return 0;
  _IO_acquire_lock (fp); /* file._lock ^= 1 */
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size;
}
```

```c
// /libio/genops.c

_IO_size_t
_IO_sgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  /* FIXME handle putback buffer here! */
  return _IO_XSGETN (fp, data, n); // _IO_file_xsgetn
}
```

```c
// /libio/libioP.h

/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  // __stop___libc_IO_vtables: __elf_set___libc_atexit_element__IO_cleanup__
  // __start___libc_IO_vtables: _IO_helper_jumps
  // section_length: 0x000d68
  const char *ptr = (const char *) vtable;
  uintptr_t offset = ptr - __start___libc_IO_vtables;
  // 會檢查 file.vtable 是否在正常範圍內
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check (); // 繞不掉
  return vtable;
}
```

```c
// /libio/fileops.c

_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  _IO_size_t want, have;
  _IO_ssize_t count;
  char *s = data;

  want = n;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp); // 如果還沒有 allocate buffer，嘗試 allocate 一塊 memory 給 file
    }

  while (want > 0) // 想要讀取的資料量 (size * nmemb)
    {
      have = fp->_IO_read_end - fp->_IO_read_ptr;
      // end == buffer 的結尾
      // ptr == buffer 目前存放到的地方
      
      if (want <= have) // 內容存放的數量 > 想要的
	{
	  memcpy (s, fp->_IO_read_ptr, want); // copy want 過去
	  fp->_IO_read_ptr += want; // 給 want 數量的值
	  want = 0;
	}
      else
	{
	  if (have > 0)
	    {
	      s = __mempcpy (s, fp->_IO_read_ptr, have);
	      want -= have;
	      fp->_IO_read_ptr += have; // 此時 fp->_IO_read_ptr == fp->_IO_read_end
	    }

	  /* Check for backup and repeat */
	  if (_IO_in_backup (fp))
	    {
	      _IO_switch_to_main_get_area (fp);
	      continue;
	    }

	  /* If we now want less than a buffer, underflow and repeat
	     the copy.  Otherwise, _IO_SYSREAD directly to
	     the user buffer. */
	  if (fp->_IO_buf_base
	      && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
          // 想要的比 buffer 的空間還要少，做 underflow() 將 input 存入 buffer 中，並在 copy 一次
	    {
	      if (__underflow (fp) == EOF)
		break;

	      continue;
	    }

	  /* These must be set before the sysread as we might longjmp out
	     waiting for input. */
	  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
	  _IO_setp (fp, fp->_IO_buf_base, fp->_IO_buf_base);

	  /* Try to maintain alignment: read a whole number of blocks.  */
	  count = want;
	  if (fp->_IO_buf_base)
	    {
	      _IO_size_t block_size = fp->_IO_buf_end - fp->_IO_buf_base;
	      if (block_size >= 128)
		count -= want % block_size;
	    }

	  count = _IO_SYSREAD (fp, s, count);
	  if (count <= 0)
	    {
	      if (count == 0)
		fp->_flags |= _IO_EOF_SEEN;
	      else
		fp->_flags |= _IO_ERR_SEEN;

	      break;
	    }

	  s += count;
	  want -= count;
	  if (fp->_offset != _IO_pos_BAD)
	    _IO_pos_adjust (fp->_offset, count);
	}
    }

  return n - want; // return 回 _IO_sgetn
}
libc_hidden_def (_IO_file_xsgetn)
```

```c
// /libio/genops.c

void
_IO_doallocbuf (_IO_FILE *fp)
{
  if (fp->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED) || fp->_mode > 0)
    if (_IO_DOALLOCATE (fp) != EOF) // _IO_file_doallocate
      return;
  _IO_setb (fp, fp->_shortbuf, fp->_shortbuf+1, 0);
}
```

```c
// /libio/filedoalloc.c

/* Allocate a file buffer, or switch to unbuffered I/O.  Streams for
   TTY devices default to line buffered.  */
// 預設為 line buffered
int
_IO_file_doallocate (_IO_FILE *fp)
{
  _IO_size_t size;
  char *p;
  struct stat64 st;

  size = _IO_BUFSIZ;
  if (fp->_fileno >= 0 && __builtin_expect (_IO_SYSSTAT (fp, &st), 0) >= 0)
    {
      if (S_ISCHR (st.st_mode))
	{
	  /* Possibly a tty.  */
	  if (
#ifdef DEV_TTY_P
	      DEV_TTY_P (&st) ||
#endif
	      local_isatty (fp->_fileno))
	    fp->_flags |= _IO_LINE_BUF; // 調整為 line buffered
	}
#if _IO_HAVE_ST_BLKSIZE
      if (st.st_blksize > 0 && st.st_blksize < _IO_BUFSIZ)
	size = st.st_blksize;
#endif
    }
  // create buffer
  p = malloc (size); // size: 0x400 (1024)
  if (__glibc_unlikely (p == NULL))
    return EOF;
  _IO_setb (fp, p, p + size, 1); // setb == set buffer
  return 1;
}
libc_hidden_def (_IO_file_doallocate)
```

```c
// /libio/fileops.c

// 取得 file stat
int
_IO_file_stat (_IO_FILE *fp, void *st)
{
  return __fxstat64 (_STAT_VER, fp->_fileno, (struct stat64 *) st);
}
libc_hidden_def (_IO_file_stat)
```

```c
// /libio/genops.c

void
_IO_setb (_IO_FILE *f, char *b, char *eb, int a)
{
  // b 為剛剛 malloc 的 buffer
  // eb 為 b + size (+ 0x400)
  if (f->_IO_buf_base && !(f->_flags & _IO_USER_BUF))
    free (f->_IO_buf_base);
  f->_IO_buf_base = b;
  f->_IO_buf_end = eb;
  if (a) // 從 _IO_file_doallocate 來的 a == 1
    f->_flags &= ~_IO_USER_BUF;
  else
    f->_flags |= _IO_USER_BUF;
}
libc_hidden_def (_IO_setb)
```

```c
// /libio/genops.c

int
__underflow (_IO_FILE *fp)
{
  if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
    return EOF;

  if (fp->_mode == 0) // stdin mode == -1
    _IO_fwide (fp, -1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_get_mode (fp) == EOF)
      return EOF;
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
  if (_IO_in_backup (fp))
    {
      _IO_switch_to_main_get_area (fp);
      if (fp->_IO_read_ptr < fp->_IO_read_end) // ptr < end 代表還可以 read (?)
	return *(unsigned char *) fp->_IO_read_ptr;
    }
  if (_IO_have_markers (fp))
    {
      if (save_for_backup (fp, fp->_IO_read_end))
	return EOF;
    }
  else if (_IO_have_backup (fp))
    _IO_free_backup_area (fp);
  return _IO_UNDERFLOW (fp);
}
libc_hidden_def (__underflow)
```

```c
// /libio/fileops.c

int
_IO_new_file_underflow (_IO_FILE *fp)
{
  _IO_ssize_t count;
#if 0
  /* SysV does not make this test; take it out for compatibility */
  if (fp->_flags & _IO_EOF_SEEN)
    return (EOF);
#endif

  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;

  // 這裡做的行為跟 _IO_file_xsgetn() 的一開始一樣
  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }

  /* Flush all line buffered files before reading. */
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
#if 0
      _IO_flush_all_linebuffered ();
#else
      /* We used to flush all line-buffered stream.  This really isn't
	 required by any standard.  My recollection is that
	 traditional Unix systems did this for stdout.  stderr better
	 not be line buffered.  So we do just that here
	 explicitly.  --drepper */
      _IO_acquire_lock (_IO_stdout);

      if ((_IO_stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
	  == (_IO_LINKED | _IO_LINE_BUF))
	_IO_OVERFLOW (_IO_stdout, EOF);

      _IO_release_lock (_IO_stdout); // _IO_acquire_lock_fct
#endif
    }

  // 切換到 get mode
  _IO_switch_to_get_mode (fp);

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;
  
  // 到這邊，如果是第一次 call fread，所有 read_ptr ~ buf_base 都會變成 memory chunk 開頭
  // buf_end 為 chunk + 0x400
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base); // syscall_read
  if (count <= 0) // syscall read 回傳
    {
      if (count == 0)
	fp->_flags |= _IO_EOF_SEEN;
      else
	fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count; // 代表 data 的結尾在 read_end + count
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
	 handles.  As a result, our offset cache would no longer be valid, so
	 unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
libc_hidden_ver (_IO_new_file_underflow, _IO_file_underflow)
```

```c
// /libio/libioP.h

static inline void
__attribute__ ((__always_inline__))
_IO_acquire_lock_fct (_IO_FILE **p)
{
  _IO_FILE *fp = *p;
  if ((fp->_flags & _IO_USER_LOCK) == 0)
    _IO_funlockfile (fp);
}
```

```c
// /libio/genops.c

int
_IO_switch_to_get_mode (_IO_FILE *fp)
{
  if (fp->_IO_write_ptr > fp->_IO_write_base) // ptr > base，代表還有東西沒印
    if (_IO_OVERFLOW (fp, EOF) == EOF) // 印出來 ?
      return EOF;
  if (_IO_in_backup (fp))
    fp->_IO_read_base = fp->_IO_backup_base;
  else
    {
      fp->_IO_read_base = fp->_IO_buf_base; // read_base -> buf_base
      if (fp->_IO_write_ptr > fp->_IO_read_end)
		fp->_IO_read_end = fp->_IO_write_ptr; // 如果 write ptr > read end，把 read end 設為 write ptr
    }
  fp->_IO_read_ptr = fp->_IO_write_ptr; // read ptr 設為 write ptr

  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end = fp->_IO_read_ptr;
  // write base = write end = read ptr = write ptr

  fp->_flags &= ~_IO_CURRENTLY_PUTTING;
  // 到這邊，如果是第一次 call fread()
  // read_base == buf_base == chunk
  // buf_end == chunk + size (chunk end)
  return 0;
}
libc_hidden_def (_IO_switch_to_get_mode)
```

##### fwrite

```c
// /libio/iofwrite.c

_IO_size_t
_IO_fwrite (const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t request = size * count;
  _IO_size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request); // read 叫做 _IO_sgetn
  _IO_release_lock (fp);
  /* We have written all of the input in case the return value indicates
     this or EOF is returned.  The latter is a special case where we
     simply did not manage to flush the buffer.  But the data is in the
     buffer and therefore written as far as fwrite is concerned.  */
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
libc_hidden_def (_IO_fwrite)
```

```c
// /libio/fileops.c

_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n; // todo == 要寫的數量
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  // unbuffered 就直接 write
  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
	{
	  const char *p;
	  for (p = s + n; p > s; )
	    {
	      if (*--p == '\n')
		{
		  count = p - s + 1;
		  must_flush = 1;
		  break;
		}
	    }
	}
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
		count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF) // _IO_new_file_overflow，並且傳 EOF 是要 flush buffer
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	return to_do == 0 ? EOF : n - to_do;

      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

      if (do_write)
	{
	  count = new_do_write (f, s, do_write);
	  to_do -= count;
	  if (count < do_write)
	    return n - to_do;
	}

      /* Now write out the remainder.  Normally, this will fit in the
	 buffer, but it's somewhat messier for line-buffered files,
	 so we let _IO_default_xsputn handle the general case. */
      if (to_do)
	to_do -= _IO_default_xsputn (f, s+do_write, to_do); // s 為傳入的 data ptr，to_do 為要 write 的大小
    }
  return n - to_do;
}
libc_hidden_ver (_IO_new_file_xsputn, _IO_file_xsputn)
```

```c
// /libio/fileops.c

int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  // 當前沒有 buffer
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL) // _IO_CURRENTLY_PUTTING 0x800
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
      // set f.read (base, ptr, end)
	}
      /* Otherwise must be currently reading.
	 If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
	 logically slide the buffer forwards one block (by setting the
	 read pointers to all point at the beginning of the block).  This
	 makes room for subsequent output.
	 Otherwise, set the read pointers to _IO_read_end (leaving that
	 alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
	{
	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
	  _IO_free_backup_area (f);
	  f->_IO_read_base -= MIN (nbackup,
				   f->_IO_read_base - f->_IO_buf_base);
	  f->_IO_read_ptr = f->_IO_read_base;
	}

      if (f->_IO_read_ptr == f->_IO_buf_end) // 讀到 buffer 結尾了
 		f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;
      // 第一次 fwrite() 跑到這，除了 write_end / buf_end (為 chunk end)，其他都是 memory chunk beginning

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF) // -1
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```

```c
#define _IO_setg(fp, eb, g, eg)  ((fp)->_IO_read_base = (eb),\
	(fp)->_IO_read_ptr = (g), (fp)->_IO_read_end = (eg))
```

```c
// /libio/genops.c

_IO_size_t
_IO_default_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (char *) data;
  _IO_size_t more = n;
  if (more <= 0)
    return 0;
  for (;;)
    {
      /* Space available. */
      // write buffer 仍有空間可以儲存
      if (f->_IO_write_ptr < f->_IO_write_end)
	{
	  _IO_size_t count = f->_IO_write_end - f->_IO_write_ptr;
	  if (count > more)
	    count = more;
	  if (count > 20)
	    {
	      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
	      s += count;
	    }
	  else if (count)
	    {
	      char *p = f->_IO_write_ptr;
	      _IO_ssize_t i;
	      for (i = count; --i >= 0; )
		*p++ = *s++;
	      f->_IO_write_ptr = p;
	    }
	  more -= count;
	}
      if (more == 0 || _IO_OVERFLOW (f, (unsigned char) *s++) == EOF) // 這邊傳入 _IO_new_file_overflow 的 ch 就不是 EOF，而是當前的 data ptr 的 dereference
      // 不斷使用 _IO_OVERFLOW 將資料寫入 buffer 之中，直到 return EOF
	break;
      more--;
    }
  return n - more;
}
libc_hidden_def (_IO_default_xsputn)
```

```c
// /libio/fileops.c

static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

##### clean

`exit` -> `_IO_cleanup` -> `_IO_flush_all_lockp` 時會清空 buffer

```c
// /libio/genops.c

int
_IO_cleanup (void)
{
  /* We do *not* want locking.  Some threads might use streams but
     that is their problem, we flush them underneath them.  */
  int result = _IO_flush_all_lockp (0);

  /* We currently don't have a reliable mechanism for making sure that
     C++ static destructors are executed in the correct order.
     So it is possible that other static destructors might want to
     write to cout - and they're supposed to be able to do so.

     The following will make the standard streambufs be unbuffered,
     which forces any output from late destructors to be written out. */
  _IO_unbuffer_all ();

  return result;
}
```

```c
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (_IO_FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}
```

```c
// /libio/genops.c

static void
_IO_unbuffer_all (void)
{
  struct _IO_FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif
  // _IO_list_all: stderr -> stdout -> stdin
  for (fp = (_IO_FILE *) _IO_list_all; fp; fp = fp->_chain)
    {
      if (! (fp->_flags & _IO_UNBUFFERED)
	  /* Iff stream is un-orientated, it wasn't used. */
	  && fp->_mode != 0)
	{
#ifdef _IO_MTSAFE_IO
	  int cnt;
#define MAXTRIES 2
	  for (cnt = 0; cnt < MAXTRIES; ++cnt)
	    if (fp->_lock == NULL || _IO_lock_trylock (*fp->_lock) == 0)
	      break;
	    else
	      /* Give the other thread time to finish up its use of the
		 stream.  */
	      __sched_yield ();
#endif

	  if (! dealloc_buffers && !(fp->_flags & _IO_USER_BUF))
	    {
	      fp->_flags |= _IO_USER_BUF;

	      fp->_freeres_list = freeres_list;
	      freeres_list = fp;
	      fp->_freeres_buf = fp->_IO_buf_base;
	    }

	  _IO_SETBUF (fp, NULL, 0);

	  if (fp->_mode > 0)
	    _IO_wsetb (fp, NULL, NULL, 0);

#ifdef _IO_MTSAFE_IO
	  if (cnt < MAXTRIES && fp->_lock != NULL)
	    _IO_lock_unlock (*fp->_lock);
#endif
	}

      /* Make sure that never again the wide char functions can be
	 used.  */
      fp->_mode = -1;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif
}
```

- The problem is we do not know whether **the freeres code** is called first or `_IO_cleanup`
  - If the former is the case, we set the `DEALLOC_BUFFER` variable to true and `_IO_unbuffer_all` will take care of the rest.
  - If `_IO_unbuffer_all` is called first we add the streams to a list which the freeres function later can walk through



---



FILE 相關的 function:

-  write function: `_IO_new_file_xsputn`、`_IO_new_file_overflow` (flush all)
- read function : `_IO_new_file_xsgetn`、`_IO_new_file_underflow`



example `gets()`:

```c
int
__uflow (_IO_FILE *fp)
{
  if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
    return EOF;

  if (fp->_mode == 0)
    _IO_fwide (fp, -1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_get_mode (fp) == EOF)
      return EOF;
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr++;
  if (_IO_in_backup (fp))
    {
      _IO_switch_to_main_get_area (fp);
      if (fp->_IO_read_ptr < fp->_IO_read_end)
	return *(unsigned char *) fp->_IO_read_ptr++;
    }
  if (_IO_have_markers (fp))
    {
      if (save_for_backup (fp, fp->_IO_read_end))
	return EOF;
    }
  else if (_IO_have_backup (fp))
    _IO_free_backup_area (fp);
  return _IO_UFLOW (fp);
}
libc_hidden_def (__uflow)
```

