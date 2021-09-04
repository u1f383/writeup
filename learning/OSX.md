## OSX memory allocator - Magazine allocator

Resources:

- [angelboy slide](https://www.slideshare.net/AngelBoy1/macos-memory-allocator-libmalloc-exploitation)
- [source code](https://opensource.apple.com/source/libmalloc/)
- [presentation slide](https://papers.put.as/papers/macosx/2016/Summercon-2016.pdf)
- 



Divided by size:

- tiny - `<= 1008`
- small - `<= 128K`
- large



### tiny

**block**

- 最小分配的單位 0x10
- 也被稱作 **Quantum**



**chunk (inused)**

- `malloc()` 取得的基本 data structure
- 由許多 blocks 組成
- 沒有像是 Linux `malloc()` 的 metadata (size, inuse bit...)



**chunk (freed)**

- 0x0 ~ 0x7 - `previous ptr`
- 0x8 ~ 0xf - `next ptr`
  - 但是 prev 跟 next 都不是 raw pointer，而是前面 4 bit 為 `checksum`、被 RSH 4 bit 的 ptr
    - `checksum` = SumOfEveryBytes(ptr ^ cookie) & 0xf
- 0x15 ~ 0x17 以及 `[-0xf:0xf-2]`  - `msize` - freed chunk 的大小 (以 quantum 為單位)，至少會佔據 2 bytes
  - 如果 chunk size 為 0x40，則 msize 為 `0x4`
    - 1 quantum 為 0x10，所以 msize = 0x40 >> 4



**tiny_region**

- memory pool of libmalloc
- 由許多 block 組成，被切成多個 chunk 給 user
- default
  - size of region: 0x100000
  - block 的數量: 64520
- 在 region 的結尾有許多 metadata



**tiny_header_inuse_pair_t** (在 region 的結尾)

- header (4 bytes) + inuse (4 bytes)
- 可以當作 bitmap，當 block 被拿去用的時候會 set bit
- region 中用來代表 chunk state
  - **header** - 是否對應的 block 為 chunk 的開頭 (head)
  - **inuse** - 是否 chunk 正在被使用



**magazine**

- 管理在 small 以及 tiny 的 chunk
- `mag_last`
  - libcmalloc 實際上並沒有 `free` size `<= 0x100` 的 chunk，而是記錄在 magazine
  - 當下次使用 `free()` 時才確實 free chunk
  - 如果 `malloc()` 相同大小，就會優先使用放在 magazine 的
    - 類似 cache 的機制
- `mag_last_free`
  - 最後一個 freed chunk
- ` mag_last_free_msize`
  - 最後一個 freed chunk 的大小
- `mag_last_free_rgn`
  - 最後一個 freed chunk 所在的 region
- `free_list`
  - 將 freed chunk 所串起的 linked list
    - 在 tiny 當中共有 64 個 free_lists
  - 每 0x10 為一個 unit
  - Double linked list
    - first node 不會指回 magazine
- `mag_bitmap`
  - 代表 free_list 的 bitmap
- `mag_bytes_free_at_end`
  - region 剩下的大小
- `mag_num_bytes_in_objects`
  - region 中 chunk 的數量
- `mag_bytes_in_magazine`
  - region 所分配的大小



**tiny rack**

- 用來管理 magazine (mag 上面一層)
- types - tiny rack / small rack
- `num_regions`
  - rack 當中 region 的數量
- `num_magazines`
  - rack 當中 magazine 的數量
- `magazines`
  - rack 的 magazine pointer
- `cookie`
  - checksum cookie for tiny rack



**szone**

- libmalloc 的核心
  - 會記錄 system 當中不同 heap 的資訊，像是 threshold
- malloc_zone_t
  - virtual function table
- cookie
  - 與 tiny rack 有著相同的 value



**機制**

- 當 call `malloc()` 時，會根據 size 走不同的 path
  - `< 1008` - `tiny_malloc(tiny_malloc_should_clear)`
    - 會先檢查 `tiny_mag_ptr->mag_last_free_msize == msize`
      1. 然後從對應的 cache 找，而 cache 的 chunk 其實沒有 free，所以沒有 unlink
      2. 不過如果在 cache 中找不到，就會從 `free_list` 當中找 chunk (`tiny_malloc_from_free_list`)，並回傳**第一個** freed chunk，同時 unchecksum next ptr
      3. 最後沒有在 `free_list` 找到的話 + `free_list` 還有 chunk 的話，就直接拿 `free_list` 中最小的，不過會經過 split，把多的部分 insert 回 `free_list` (跟 unsorted bin 一樣)
      4. 什麼都沒有，直接從 `tiny_region_end` 切一塊
    - 拿到 chunk 後會更新 metadata (`tiny_header_inuse_pair`) 然後回傳給 user
  - 實際上 chunk 會在 cache 或是 free_list 當中，而這邊 cache 可以看成 tcache、free_list 可以看成 unsorted bin 之類的
- 當 call `free()` 時，會根據 size 走不同的 path
  - `< 1008` - `free_tiny()`
  - 遍歷所有 size 的方法 `szone_size()`
    - tiny_size
      - 先驗證 header 以及 inuse state
      - 用 header 的 bitmap 計算大小
  - 當 `msize < 0x10`，會將當前的 chunk 跟 cache 內的 freed chunk 交換 (?)
  - `tiny_free_no_lock()`
    - merge 前後 freed chunk 且 clear inuse bit
    - 找出前一個 chunk 的方法為利用 prev chunk 結尾的 `msize` 去推算
    - 找出 next chunk 也是
    - 先 unlink ---> merge
- `unlink ( tiny_free_list_remove_ptr() )`
  - unchecksum
    - next & prev
    - prev_next & next_prev (next 或是 prev 非 NULL 的情況)
  - 檢查 `prev_next == next_prev == ptr`



### small

**block**

- size 為 0x200，為分配的最小單位
- 也被稱作 **Quantum**



**chunk (inuse)**

- 最基本的 data structure
- 由多個 block 組成
- 沒有 metadata



**chunk (freed)**

- prev, next chunk 的 pointer
- 與 tiny 不同的是，這邊**直接用 raw pointer**
- chunksum
  - 也跟 tiny 不一樣，加上其他的 8 bytes，並且 padding to 8 bytes (?)
  - `SumOfEveryBytes(ptr ^ rack->cookie ^ rack)`



**chunk (out-of-band freed)**

- 用來做 page alignment 的 chunk，也稱作 oob free chunk
- 沒有 metadata



**oob_free_entry_S**

- 用來管理 oob chunk
- (0x0 ~ 0x7) prev / (0x8 ~ 0xf) next pointer (raw pointer)
- (0x10 ~ 0x17) ptr
  - oob chunk 在 region 的 index
  - 最高位 1 bit (MSB) 指出是否為 oob free chunk



**small_region**

- libmalloc 的 memory pool
- 與 tiny 相同，不過 block 變成 0x200
- default
  - region size 為 0x800000
  - 有 16319 個 block
- 在 region 後有一些 metadata
  - `small_meta_words[]`
    - msize_t array
    - 每個 element 對應到每個 block (bitmap 的概念 ?)
    - 包含 chunk size 以及 inuse bit
    - 對應到 chunk (inuse) 起頭的 block 會存 **chunk size**
    - 對應到 chunk (freed) 起頭與結尾的 block 會存 **chunk size 以及 flag**
    - MSB 表示是否 freed
  - `small_oob_free_entries[32]`
    - `oob_free_entry` array
    - OOB chunk 會被放在這



**magazine**

- 再做一次複習的概念
- 用來管理 tiny / small 的 region
- `mag_last`

- ibmalloc 執行 `free()` 時並不會在一開始就真的 free chunk ，而是放入 cache (`mag_last_free`) 來 maintain



**機制**

- 當 call `malloc()` 時，會根據 size 走不同的 path
  - `> 1008 && size < 128K` - `small_malloc ( small_malloc_should_clear() )`
    - 會先檢查 `tiny_mag_ptr->mag_last_free_msize == msize`
      1. 然後從對應的 cache 找，而 cache 的 chunk 其實沒有 free，所以沒有 unlink
      2. 不過如果在 cache 中找不到，就會從 `free_list` 當中找 chunk (`small_malloc_from_free_list()`)，並回傳**第一個** freed chunk
         - normal chunk - 先 unkchecksum
         - oob chunk - 直接拿下一個
         - do unlink 時會檢查 `next_prev == ptr` (double linked list)
      3. 剩下跟 tiny 一樣 (可能要注意 data structure name，`tiny` --> `small`)
- 當 call `free()` 時，會根據 size 走不同的 path
  - `> 1008 && < 128K` - `free_small()`
    - 會將當前的 chunk 跟 cache 內的 freed chunk 交換 (?)
  - `small_free_no_lock()`
    - 與 tiny 相似，有 merge --> insert `free_list` 的流程
    - 找 prev chunk 的方法為用 `small_meta_word` 對到的 prev chunk，從 chunk end 來看 prev chunk 是否 freed，以及拿到 prev size 而推得 position
      - next chunk 亦然
    - merge prev / next freed chunk
      - 不過 unlink ---> merge
- `unlink ( small_free_list_remove_ptr() )`
  - 如果不是 oob chunk，就可以 unchecksum；如果是，直接拿 `ptr`
    - next & prev
    - prev_next & next_prev (next 或是 prev 非 NULL 的情況)
  - 檢查 `prev_next == next_prev == ptr`



### Exploit

- tiny
  - overlap chunk attack
  - free_list overwrite attack
- small
  - meta word overwrite



#### tiny - overlap chunk attack

當漏洞可以 **overwrite size**，增加原本的 free chunk 再用 merge 的機制製造出 overlap chunk

- 目標是要 overlap chunk 並且更改 chunk 的內容，像是 chunk size
- 當 call `free()`，會檢查 cache 的 ptr 是否等於要 free 的 ptr，如果是的話就會 abort (double free)



#### tiny - free_list overwrite attack

在可以 overwrite free chunk 的 prev / next  時使用

- 基本上就是 unlink attack，不過是在 `malloc()` 時被 trigger
- `tiny_malloc()` 從 double linked list 拿 free chunk 時並沒有檢查 
- 注意事項
  - prev / next ptr 已經被 RSH 4 bits
  - hit 4 bit checksum
  - prev 會被寫成 `*next`



除了上述的兩種方法，unlink attack 也能在這個情況中被使用，不過因為要 bypass checksum 的檢查，因此要 brute force 1/256。而另一種可能的攻擊層面為 overwrite metadata 來建立 overlap chunk。



### small - Meta word overwrite

很少可以利用的地方，如果要做到 unlink attack，必須要 brute-force 2 bytes of checksum

- 如果要 arbitrary memory reading，必須要計算 checksum
- 最好可以 overwrite end of region (?)，以至於能夠建立 fake msize 並且造成 overlap chunk



---



[look-at-how-malloc-works-on-mac](https://www.cocoawithlove.com/2010/05/look-at-how-malloc-works-on-mac.html)



為了省去存 metadata 的空間，有許多 allocator 會使用 free list 的方式，像是 Mac 使用的 Magazine allocator 就是這樣：

- [malloc.c](http://www.opensource.apple.com/source/Libc/Libc-594.1.4/gen/malloc.c)
  - wrapper of **magazine_malloc.c**: `malloc()` ---> `malloc_zone_malloc()`
  - [magazine_malloc.c](http://www.opensource.apple.com/source/Libc/Libc-594.1.4/gen/magazine_malloc.c)
- Snow Leopard 前，內部的機制為 [scalable_malloc.c](http://www.opensource.apple.com/source/Libc/Libc-594.1.4/gen/scalable_malloc.c)
  - 被稱作 scalable 的原因在於 allocation 會根據不同的 size 有不同的 code path
  - 而 Magazine 繼承許多 scalable_malloc.c 的機制，但是額外加上 multithread 的功能

不同大小有不同的 code path:

| Allocation Size                                              | Code path name | Quantum size (Allocation resolution) | Region size                   |
| ------------------------------------------------------------ | -------------- | ------------------------------------ | ----------------------------- |
| 32-bit: 1 byte to 496 bytes<br />64-bit: 1 byte to 992 bytes | Tiny           | 16 bytes (0x10)                      | 32-bit: 1MB<br />64-bit: 2MB  |
| 32-bit: 497 bytes to "Large" threshold<br />64-bit: 993 bytes to "Large" threshold | Small          | 512 bytes (0x200)                    | 32-bit: 8MB<br />64-bit: 16MB |
| < 1GB RAM: 15kB or greater >= 1GB RAM: 127kB or greater      | Large          | 4kB (0x1000)                         | N/A                           |

- Malloc zones allocate **"tiny"** and **"small"** **regions** or **"large"** **blocks** directly
- Regions return **blocks** from their contents as results for **"tiny" and "small"** malloc operations

分成 tiny 以及 small 的原因在於 region 可以更有效的用 metadata 存取對應 size 的 object

- tiny 提供了較小單位的記憶體分配，減少 fragmentation

而原本一開始並沒有 zone 的概念，而後被其他 Allocator 所 **inspired**：

- Most of the allocation metadata that was previously kept in the "zone" structures moves into the **new "magazine" level of the hierarchy** so that it can be kept **thread-specific**
- zone 包含了每次 allocation 都要更新的資料，像是 allocated region 的數量、 `free_list` 以及可使用的 memory 數量
- 而 "tiny" region 屬於 specific thread，因此不需要 lock

**the levels of hierarchy** for "tiny" allocations:

- **Malloc** zones allocate magazines for **"tiny" regions (1 per thread)** and allocated the regions themselves when requested by the magazines.
- **Magazines** manage the regions for **a thread**
- Regions return **blocks** from their contents

在 allocate / free region 時還是要用 lock (global)，不過這樣能增加效率 / 減少 contention 的發生。



執行 `free` 時, your application footprint will not immediately go down. Freeing region allocated memory adds the space to **the free list** for the region but will not cause the region to be released unless it was **the last block in the region**

- region maintain 一個 `free_list`，而在最後一個 block 被 `free()` 時才會 release (free -> 放到 `free_list`；release -> 真正 release)

Your application's footprint will only go down if an **entire region is freed** and the zone can **unmap** the virtual memory pages.

- `calloc` takes two parameters: a **size** and a **number of elements**
  - calloc just multiplies its two parameters together — other than some overflow checking on the multiplication, the size of the returned block from `calloc(a, b)` is identical to the block returned by `malloc(a * b)`
- `malloc` only takes a size but is often calculated by multiplying a `sizeof(SomeType)` by a number of elements



Debug inforamtion：

```
MallocLogFile <f> to create/append messages to file <f> instead of stderr
MallocGuardEdges to add 2 guard pages for each large block
MallocDoNotProtectPrelude to disable protection (when previous flag set)
MallocDoNotProtectPostlude to disable protection (when previous flag set)
MallocStackLogging to record all stacks. Tools like leaks can then be applied
MallocStackLoggingNoCompact to record all stacks. Needed for malloc_history
MallocStackLoggingDirectory to set location of stack logs, which can grow large; default is /tmp
MallocScribble to detect writing on free blocks and missing initializers: 0x55 is written upon free and 0xaa is written on allocation
MallocCheckHeapStart <n> to start checking the heap after <n> operations
MallocCheckHeapEach <s> to repeat the checking of the heap after <s> operations
MallocCheckHeapSleep <t> to sleep <t> seconds on heap corruption
MallocCheckHeapAbort <b> to abort on heap corruption if <b> is non-zero
MallocCorruptionAbort to abort on malloc errors, but not on out of memory for 32-bit processes MallocCorruptionAbort is always set on 64-bit processes
MallocErrorAbort to abort on any malloc error, including out of memory
MallocHelp - this help!
```



---



lldb debug script apple 似乎有提供 (?)，像是 [heap.py](https://opensource.apple.com/source/lldb/lldb-159/examples/darwin/heap_find/heap.py.auto.html)

- `malloc_info -s <addr>`

https://gloxec.github.io/2019/04/08/MacOS%20Heap%20Exploit/

- **tiny** (Q = 16) ( **tiny** < 1009B )
- **small** (Q = 512) ( 1008B < **small** < 127KB )
- **large** ( 127KB < **large** )



一些 lldb helper

- `process status` - 取得 pid
- `platform shell vmmap <pid>` - 取得 vmmap
  - 或者 `image list` (比較精簡)