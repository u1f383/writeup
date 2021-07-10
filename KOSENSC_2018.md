## Binary

### まどわされるな！

```
[*] '/tmp/tmp/KOSENSC2018/[01 Binary 100] まどわされるな！/flag.out'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

程式會印出部分 flag: `SCKOSEN{you_are_go`，而另一部分需要你自己去找，不過 main function 以及 init、fini 都沒做什麼，因此猜測藏在 binary 內部，使用 `binwalk` 就能 extract 出一個圖檔，內容是另一部分的 flag `od_eye!}`

### ログインしたい！

```
[*] '/tmp/tmp/KOSENSC2018/[02 Binary 100] ログインしたい！/login'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

`SCKOSEN{P@SSW0RD!}`

###  XOR, XOR

```
[*] '/tmp/tmp/KOSENSC2018/[04 Binary 200] XOR, XOR/asmreading'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

直接用 gdb 在 main function 前下斷點就可以看到 flag `SCKOSEN{you_can_read_assembly!}`

### Simple anti debugger/simple_anti_debugger

```
[*] '/tmp/tmp/KOSENSC2018/[05 Binary 250] Simple anti debugger/simple_anti_debugger'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

anti-debugger 使用的是 `ptrace(PTRACE_TRACEME, 0, 0, 0)`，如果這個 function 回傳 -1，代表已經有 debugger 正在 trace。解決方法為直接

`SCKOSEN{I_like_debugger}`

## Crypto

### exchangeable if

`SCKOSEN{sHDtF1xxxxNLTIWp}` 以及 md5 = `2009d1c114ed83f57cf8adde69fd6ca8`

```python
#!/usr/bin/python3              
                                
import string                   
import random                   
import hashlib                  
                                
wordlist = string.ascii_letters + string.digits                                      
h = '2009d1c114ed83f57cf8adde69fd6ca8'
flag = "SCKOSEN{sHDtF1xxxxNLTIWp}"
                                
def get_ranstr(l=4):            
    s = ""                      
    for _ in range(l):          
        s += random.choice(wordlist)
    return s                    
                                
res = ""                        
while res != h:                 
    s = get_ranstr()            
    res = hashlib.md5(flag.replace('xxxx', s).encode()).hexdigest()
                                
print(s)
```

得到 `xxxx` == `qOLZ`

### シンプルなQRコード

拿到一個只有一半的 QR code，並從長度可以知道為 29x29 (ver. 3) 的 QR code，由於 QR code 有基本的格式，因此可以先將 QR code 恢復到原本的大小，可以使用 [qrazybox](https://github.com/Merricx/qrazybox) 將 QR code 畫回來。

畫回來後，再使用此 [strong-qr-decoder](https://github.com/waidotto/strong-qr-decoder) decode QR code，不過要先將圖檔轉成特定格式: 

```python
#!/usr/bin/python3
        
from PIL import Image
        
UNIT_SIZE = 10
        
BLACK = (0, 0, 0, 255)
WHIEE = (255, 255, 255, 255)
        
img = Image.open('./recover.png')
pixs = img.load()
x, y = img.size                                  
maps = ""
        
for yy in range(0, y, UNIT_SIZE):
    for xx in range(0, x, UNIT_SIZE):
        print(f"({xx}, {yy})", pixs[xx,yy])
        if pixs[xx,yy] == BLACK: # black
            maps += "X" 
        else:
            maps += "0" 
    maps += "\n"
        
open("map.txt", "w").write(maps)
```

`SCKOSEN{remove_rs_qr}`

