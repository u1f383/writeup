## Pwn

### bookface

```
// file
bookface: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6966ac75a75ba7def2eb9bb924f615e6dc6a4964, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/tmp/bookface/bookface'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

覺得題目部份的設計有點硬要，所以直接看 flow 以及 core tech:

- Leak using fmt
- Abusing glibc PRNG by overwrite the random state using *friends* pointer
  - 很有趣的一點，他是去看 PRNG `rand()` 的 source code，看怎麼影響到產生 random number 的過程，讓其產生 `& 0xfffffffffffff000` 後為 0 的 random value
- Writing a forged FILE structure in Zero Page
  - 因為 `vm.mmap_min_addr=0`，所以是有機會在 `0x0` 寫東西的，因此能嘗試用 `fgets(user->name, 0x100, stdin);` 來寫 forged FILE structure
- Trigger FILE structure exploit by a **NULL Pointer Dereference Attack** and exploiting a TOCTOU bug
  - 目標是 `fclose((FILE *)0)`，攻擊方法參考[該文章](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)，而在 uncategorized.md 中也有做練習
  - 而執行 `fopen()` 的 basic block 需要 condition `access(file, F_OK) != -1` 才能進入，但是又需要 `fopen()` 失敗，此時就必須在執行過程中透過另一個 client 把 file 刪除，此方法也稱做 TOCTOU attack



- mmap_min_addr: `mmap()` 得到的最小地址
  - remote server set `vm.mmap_min_addr=0`
  - local 的設定可以從 `/proc/sys/vm/mmap_min_addr` 看 (default 0x10000)
- [writeup 參考](https://philomath213.github.io/post/angstromctf2020-bookface/)
- TOCTOU: Time-of-check to time-of-use
  - a class of software bugs caused by a race condition involving the checking of the state of a part of a system (such as a security credential) and the use of the results of that check
  - common in **Unix** between **operations on the file system**

