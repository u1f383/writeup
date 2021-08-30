## Pwn

### abw

`abw` 本身為一個 python script:

```python
#!/usr/bin/env python3

print( "Write File")
filename = input("File Name :")
with open(filename,"wb") as file:
        seek = int(input("Seek :"))
        file.seek(seek)
        file.write(bytes.fromhex(input("Data (hex):")[:20]))
```

可以開啟檔案並任意寫入 20 bytes 的字串，而 python3 本身的 checksec 為:

```
[*] '/usr/bin/python3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

因為 No PIE，因此第一個想法為是否找出改 memory 內容的方式，再透過 hijack GOT 等等方式做 exploit，而搜了一下發現 `/proc` 的 manual 出現這段:

```
/proc/[pid]/mem
              This file can be used to access the pages of a process's
              memory through open(2), read(2), and lseek(2).

              Permission to access this file is governed by a ptrace
              access mode PTRACE_MODE_ATTACH_FSCREDS check; see
              ptrace(2).
```

雖然是寫 open / read / lseek，但是 LWN.net 中[有封信](https://lwn.net/Articles/433326/)描述有人將 `/proc/self/mem` 改成可以 writable。

因此先找出 `python3` main function 的程式邏輯，並且更改 main function 要 return 前的 epilogue，也就是下方 `add rsp, 0x28` 的部分:

```c
   0x6b71d2 <Py_BytesMain+18>    mov    dword ptr [rsp + 8], 1
 ► 0x6b71da <Py_BytesMain+26>    mov    qword ptr [rsp + 0x10], rsi
   0x6b71df <Py_BytesMain+31>    mov    qword ptr [rsp + 0x18], 0
   0x6b71e8 <Py_BytesMain+40>    call   0x6b7170                      <0x6b7170>
   0x6b71ed <Py_BytesMain+45>    add    rsp, 0x28
   0x6b71f1 <Py_BytesMain+49>    ret
```

先用 int3 (0xcc) 作為斷點，更改完後會長得像:

```c
 ► 0x6b71ee <Py_BytesMain+46>    int3    <SYS_read>
        fd: 0x90b608 ◂— 0x0
        buf: 0x7ffeca5d8528 —▸ 0x67f7bb (Py_FinalizeEx+379) ◂— mov    dword ptr [rip + 0x2df323], 0
        nbytes: 0x5b8670 ◂— endbr64
   0x6b71ef <Py_BytesMain+47>    int3
   0x6b71f0 <Py_BytesMain+48>    int3
   0x6b71f1 <Py_BytesMain+49>    int3
```

不僅僅是 binary code section，基本上任何 address 都可以做更改，而後想出幾種攻擊方式:

- 執行過程中有某個情況能夠讓 20 bytes 的 shellcode 可以做到 `execve()` ，如 rsi, rdx 是 0，使得 shellcode 只需要控 rax, rdi 而能減少長度
- 做出 `read(0, rsp, 0x1000)` 然後堆 ROP，也是最簡單的方式

考點應該是 `/proc/self/mem`，在此就不寫 exploit 了。

不得不說 linux page permission 的機制真的很奇妙，`/dev/mem` 不能寫 read-only，但是 `/proc/self/mem` 就可以任意寫。



### app 1 / 2

環境的部分有點難復現，因此就直接看 writeup 做分析。

第一部分是用 ROP `_dl_make_stack_executable` 讓 stack 可執行，最後就直接 `read("/flag1")`。

- `__stack_prot` 要先設為 7
- 接收 `__libc_stack_end` 做為參數 (rdi)



第二部分是用 `#!/read_flag` 繞掉 apparmor 的執行限制，但首先必須要新增一個可執行的檔案，這邊使用了 `memfd_create` 產生一個匿名記憶體的檔案，並沒有實體路徑:

> memfd_create() creates an anonymous file and returns a file descriptor that refers to it. The file behaves like a regular file, and so can be modified, truncated, memory-mapped, and so on. However, unlike a regular file, it lives in RAM and has a volatile backing storage.

並且用 `execveat()` 執行 `memfd` ，其中 flag 必須要設為 `AT_EMPTY_PATH`:

>  If pathname is an empty string and the AT_EMPTY_PATH flag is specified, then the file descriptor dirfd specifies the file to be executed (i.e., dirfd refers to an executable file, rather than a directory).

範例如下:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
# define AT_EMPTY_PATH 0x1000 /* Allow empty relative pathname */

int main()
{
    int zero = 0;
    int fd = memfd_create("OWO", 0);
    
    write(fd, "#!/bin/ls", 0x30);
    syscall(SYS_execveat, fd, &zero, 0, 0, AT_EMPTY_PATH);
    return 0;
}
```

