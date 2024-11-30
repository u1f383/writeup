## simple_blogger

```
#  checksec ./client_nix
[*] '/docker_vol/linectf_2023/simple_blogger/client/client_nix'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- 題目提供兩個 binary： **client_nix** 與 **server_nix**，其中 client 的行為可以讓我們參考要怎麼與 server 做互動。



Server 為 blogger server，後端使用 sqlite3 紀錄相關資訊，而我們可以透過 client 端與 server 互動，執行下列功能：

- ping - 測試連線
- login - 登入，使用者的帳號密碼需要 match db 的一組
- logout - 登出
- read msg - 讀給定 ID 的 message
- write msg - 寫 message
- get flag - 需要有權限的使用者才能夠讀 flag

此外，server 在收到 data 後會先 decode，並且還會執行一些 sql 命令：

- PING
  - 同時也會 reset 整個 db
  - reset 的方法是取出 `rowid == 1` 的 token (admin token)，而後將除了此 token 外的 sess 給移除
- LOGIN
  - 登入使用者，如果是 "super_admin" priv 就是 0，"admin" 就是 1，其他就是 2
- LOGOUT
  - 刪除 token 對應到的 sess



client 請求格式：

```
0: unknown
1: opcode
2-18: token
19-20: length
21-: data
```

server 格式：

```
0: unknown
1: opcode
2-18: token
24-32: size
32-: data
```



Exploit 思路：

- 在 PING handler 中，由於 response data size 可控，因此可以 leak 在 stack 存放的 admin token
- 使用 admin token 取得 flag





## Hackatris

> writeup: https://chovid99.github.io/posts/line-ctf-2023/

```
[*] '/docker_vol/linectf_2023/hackatris/game'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

下面列出一些 ncurses 常用的 API：

- `init_pair(pair, F, B)` - changes the definition of a color-pair
  - pair - color pair, index
  - F - frontend color
  - B - backend color
- `initscr()`
  - determines the terminal type and initialises all implementation data structure
- `cbreak()`
  - **disables line buffering** and erase/kill character-processing (interrupt and flow control characters are unaffected), making characters typed by the user **immediately available to the program**
- `noecho()`
  - control whether characters typed by the user are echoed by **getch** as they are typed
- `keypad()`
  - enables the keypad of the user's terminal
  - If enabled (*bf* is **TRUE**), the user can press a function key (such as an arrow key) and **wgetch** returns a single value representing the function key, as in **KEY_LEFT**
- `wtimeout()`
  - set blocking or non-blocking read for a given window
  - If delay is zero, then non-blocking read is used
- `curs_set()`
  - set the cursor mode
  - 0 - Invisible
- `start_color()`
  - called if the programmer wants to use colors, and before any other color manipulation routine is called
  - initializes eight basic colors
- `newwin(int nlines, int ncols, int begin_y, int begin_x)`
  - creates and returns a pointer to a new window with the given number of lines and columns
- `wborder()`
  - routines draw a box around the edges of a window
- `waddch()`



---

題目設計為俄羅斯方塊遊戲，並且每個 shape 為 5 * 5 的大小，方塊除了顏色之外還會有值在裡面，可以參考 `get_bleak()` function 實作：

```c
void __fastcall get_bleak()
{
  int stack_offset; // [rsp+Ch] [rbp-14h]
  void *_system_ptr; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 canary; // [rsp+18h] [rbp-8h]

  canary = __readfsqword(0x28u);
  stack_offset = rand() % 6;
  base_counter += 10;
  difficulty = base_counter + stack_offset;
  _system_ptr = system_p;
  *B_leak_value = *(&_system_ptr + stack_offset);
  *&B_leak_value[8] = *(&_system_ptr + stack_offset);
  *&B_leak_value[16] = *(&_system_ptr + stack_offset);
  *&B_leak_value[24] = *(&_system_ptr + stack_offset);
  *B_leak_value ^= 0x4141414141414141uLL;
  *&B_leak_value[8] ^= 0x4141414141414141uLL;
  *&B_leak_value[16] ^= 0x4141414141414141uLL;
  *&B_leak_value[24] ^= 0x4141414141414141uLL;
} 
```

- 在加上對應的 stack_offset 後 `B_leak_value` 的值：
  - 0 - system
  - 1 - canary
  - 2 - old_rbp
  - 3 - return address
- 並且 stack_offset 能從計分板的資訊中取得



在結束遊戲後，如果 score 不為 0 會呼叫 `show_scoreboard()` function，除了印出一些遊戲資訊外，還會要求你輸入 "Reward"，程式邏輯如下：

```c
void __fastcall show_scoreboard()
{
	// ...
    char buf[72]; // [rsp+10h] [rbp-50h]
    unsigned __int64 v6; // [rsp+58h] [rbp-8h]

    v6 = __readfsqword(0x28u);
    // ...
    while ( 1 ) {
        c = wgetch(local_win);
        if ( c > 47 && c <= '9' )                   // is_digit
        {
          digit = c - '0';
          if ( (i & 1) != 0 )
            buf[i / 2] |= digit & 0xF;
          else
            buf[i / 2] = 16 * digit;
          goto LABEL_13;
        }
        
        if ( c <= 96 || c > 122 )
          break;
        
        v2 = c - 'a' + 10;                          // is_alpha
        if ( (i & 1) != 0 )
          buf[i / 2] |= v2 & 0xF;
        else
          buf[i / 2] = 16 * v2;
LABEL_13:
        ++i;
    }
    if ( c != 10 )
        goto LABEL_13;
}
```

1. 每次從 window 讀一個 char
2. 如果為 digit / alpha，直接以 hex value 的方式寫入到 buffer
3. 讀到 `'\n'` 就會離開

蓋寫時沒有判斷邊界，所以有 overflow，因此將 leak 的資料用 `hex()` 轉成 hex value string，就能蓋寫 canary、old rbp、return address 等等，而這些 address 我們都能透過先前的方塊資訊取得。



P.S. 漏洞本身簡單好懂，並且 exploit 也不難，直接 ROP 就能成功，但麻煩的地方就在於圖形化介面的資訊要怎樣分析

- 可以使用 pyte 來模擬輸出
- 還是必須 parse 輸出結果來取得資訊



## Books

```
#  checksec ./booksd
[*] '/docker_vol/linectf_2023/books/booksd'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    UBSAN:    Enabled
```

- 透過 IDA 看起來一大包，透過一些 function name 與字串發現是用 llvm 的 project "compiler-rt" 來編譯
  - 等同於 GCC 中的 libgcc

> 引用：https://www.jianshu.com/p/4f22bfd1a93d
>
> Compiler-RT（RT指运行时）项目用于为硬件不支持的低级功能提供特定于目标的支持。例如，32位目标通常缺少支持64位除法的指令。Compiler-RT通过提供特定于目标并经过优化的功能来解决这个问题，该功能在使用32位指令的同时实现了64位除法。它提供相同的功能，因此是LLVM项目中libgcc的替代品。







