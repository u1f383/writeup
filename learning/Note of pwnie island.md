### Note of pwnie island



- 通常遊戲給的 exe 可能會是一個 launcher，在去執行另一個 exe 或 elf，因此可以在運行後去看 `ps aux` 找到底真正運行起來的遊戲執行檔是哪一個，並且看使用的參數或環境變數來直接運行遊戲本體，通常直接運行會有比較詳細的 log output

- 透過 `/proc/<pid>` 可以查看關於 process 內部開啟的檔案、記憶體結構、用的 library 等等

  ```
  file
  ldd
  wireshark
  ```

- `netstat` 可以看 binary 是否有與 server 做連線，`wireshark` 可以看與 server 溝通時傳送的資料

- 使用 `wireshark` 查看封包時，可以用 filter 來挑出想要的封包來觀察

- 觀察封包形式時，可以先看遊戲角色靜止時候的封包，再看跳躍、移動等等時候使用的封包，比較兩者差異

- 可以用動態追蹤 (`gdb`) 的方式觀察執行的過程，像是 bt，並且也能在 function 下斷點如 `jump()`，透過在遊戲中 jump 來確定對應到的是 `jump()`

  -  `ptype Player` 印出 type
  - `gdb` 對於 C++ class 的 member type 分析可能會有問題 (`std::string` vs. `char *`)

- 可以用 `LD_PRELOAD` hijack shared object，因為 binary 在執行過程中若呼叫 library function，則會優先去 `LD_PRELOAD` 指定的 library 找

  - 在 function 做完 hook 後再執行原本的 function

    ```
    dlsym PTLD_NEXT
    ```

  - 從 `gdb` 找到的 class 當中的 `public` 以及 `protected` member 可以改變，因為 `public` 以及 `protected` 是 C++ 的 compile time mechanism

- 有了 library hijacking，我們可以：

  - 修改 class member 的值
  - 呼叫任何 function
  - e.g. `jump` 可以改 jump 的速度 `jumpSpeed` 以及可不可以 jump 的 function `canJump()`

- `teleport`

  - 在遊戲中難免會需要傳送，而最好的話能有一個介面可以輸入要傳送的位置，送出後就可以到達，不過可以使用遊戲中有的 feature 作為介面，像是 chat channel

- 位移

  - jump 會需要改變 velocity

- 如何在地圖中找到要的物件

  - 如果物件位置是由 server 傳送給 client，有可能沒辦法從一開始就知道物件所位置在哪，需要猜測什麼情況下 server 會傳送物件的位置
  - 或者是物件位置都是固定的，這樣就能直接從 class member 當中去找 (物件已初始化)
    - 也可以看物件在哪裡初始化 (某個 function)，觀察傳入的參數

- network proxy

  - 作為 clinet 與 server 的中繼站
  - 有了 proxy 後，開始分析 client 送出的封包格式
    - Type-Length-Value： https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value
  - 當知道封包格式後，可以紀錄常見操作對應的封包，像是移動、攻擊，然後透過重送達到自動化
    - 或者可以改變封包欄位的內容如武器 id，藉此可能得到未知的武器
  - 而後分析 server 傳回的封包格式
    - 進入遊戲後 server 會傳送哪些資料

proxy.py

```python
#!/usr/bin/python3
import socket
import parser
from threading import Thread
from importlib import reload

# need to connect server
class Proxy2Server(Thread):
    
    def __init__(self, host, port):
        super(Proxy2Server, self).__init__()
        self.game = None
        self.port = port
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, port))
    
    def run(self):
        while True:
            # recv from server
            data = self.server.recv(4096)
            if data:
                try:
                    reload(parser)
                    parser.parse(data, self.port, 'server')
                except Exception as e:
                    print(e)
                # send to game
                self.game.sendall(data)

# game will connect to it
class Game2Proxy(Thread):
    
    def __init__(self, host, port):
        self.server = None
        self.port = port
        self.host = host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        sock.bind((host, port))
        self.game, addr = sock.accept()

    def run(self):
        while True:
            # recv from game
            data = self.game.recv(4096)
            if data:
                try:
                    reload(parser)
                    parser.parse(data, self.port, 'client')
                except Exception as e:
                    print(e)
                # send to server
                self.server.sendall(data)

class Proxy(Thread):
    
    def __init__(self, proxy_host, server_host, port):
        super(Proxy, self).__init__()
        self.proxy_host = proxy_host
        self.server_host = server_host
        self.port = port

    def run(self):
        while True:
            print(f"[proxy({self.port})] setting up")
            self.g2p = Game2Proxy(self.proxy_host, self.port)
            self.p2s = Proxy2Server(self.server_host, self.port)
            print(f"[proxy({self.port})] connection established")
            # exchange socket reference
            self.g2p.server = self.p2s.server
            self.p2s.game = self.g2p.game

            self.g2p.start()
            self.p2s.start()


master_server = Proxy('0.0.0.0', '<real_server>', 3333)

for port in range(3000, 3006):
    _game_server = Proxy('0.0.0.0', '<real_server>', port)
    _game_server.start()

while True:
    try:
        cmd = input('$ ')
        if cmd == 'exit':
            exit(0)
    except Exception as e:
        print(e)
```

parser.py:

```python
def parse(data, port, host):
    print(f"[{host}({port}]) {data.encode('hex')}")
```

