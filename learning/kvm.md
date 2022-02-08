參考 jserv repo：

- [kvm-user-x86](https://github.com/jserv/kvm-user-x86)
- [kvm-host](https://github.com/sysprog21/kvm-host)



## kvm-user-x86

`main()` - 大致流程如下：

1. 透過 `kvm_init()` 建立 `kvm` 的結構，過程中會嘗試存取 kvm device `"/dev/kvm"`
2. 檢查是否支援 kvm，並透過 `ioctl()` 與 device 互動，建立一個 vm
   - KVM_CREATE_VM - 建立 VM instance，會回傳 VM instance 的 fd
   - KVM_SET_USER_MEMORY_REGION - 傳入結構 `kvm_userspace_memory_region`，其中設定了 userspace 的 memory region
   - 預設 RAM size 為 `512000000`
3. 透過 `load_binary()` 載入 binary `"vm.bin"`，寫到 VM 的 ram 當中
4. 透過 `kvm_init_vcpu()` 來初始化 VCPU (virtual CPU)
   - KVM_CREATE_VCPU - 傳入 vcpu id 建立對應的 VCPU，回傳 vcpu fd
   - KVM_GET_VCPU_MMAP_SIZE - 取得 VCPU 需要的空間
5. `kvm_run_vm()` 建立執行 `kvm_cpu_thread()` 的 thread，並等待其終止
6. `kvm_clean_vm()` 與 `kvm_clean_vcpu()` 各自釋放 `mmap()` 給 ram 以及 vcpu 的空間，並且都關閉 fd
7. `kvm_clean()` 關閉 device 的 fd 並釋放 `kvm` 的記憶體

```c
struct kvm *kvm = kvm_init();

if ((kvm == NULL) || (kvm_create_vm(kvm, RAM_SIZE) < 0))
{
	fprintf(stderr, "Fail to create vm\n");
	return -1;
}

load_binary(kvm);

kvm->vcpus = kvm_init_vcpu(kvm, 0, kvm_cpu_thread);

kvm_run_vm(kvm);

kvm_clean_vm(kvm);
kvm_clean_vcpu(kvm->vcpus);
kvm_clean(kvm);

return 0;
```

---

大多數的 function 基本上就如同上述介紹，而比較重要的則是透過 thread 執行的 function `kvm_cpu_thread()`：

```c
struct kvm *kvm = (struct kvm *)data;
kvm_reset_vcpu(kvm->vcpus); // 重置 vcpu 內的 register

while (1)
{
	printf("KVM start run\n");
    // 執行 kvm
	if (ioctl(kvm->vcpus->vcpu_fd, KVM_RUN, 0) < 0)
	{
		fprintf(stderr, "KVM_RUN failed\n");
		exit(1);
	}

    // 當 kvm 跳出時，代表 vm 執行中觸發 trap / exception 等，因此需要回到 host 來處理
    // 此時 exit_reason 會紀錄著 exit 的原因
	switch (kvm->vcpus->kvm_run->exit_reason)
	{
	case KVM_EXIT_IO:
		... // ignore output and sleep
		break;
	default:
		printf("KVM unknown\n");
		break;
	}
}

return 0;
```

- KVM_RUN - 通知 vcpu 可以開始執行
- 可以將 VCPU 想像成是一個 thread

---

`kvm_reset_vcpu()` - 初始化整個執行環境，包含 segment selector 以及 base address：

```c
// 首先取得 segment register
if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &(vcpu->sregs)) < 0)
{
	perror("can not get sregs\n");
	exit(1);
}

// 更新 segment register 內的值
// CODE_START == 0x1000
vcpu->sregs.cs.selector = CODE_START;
vcpu->sregs.cs.base = CODE_START * 16;
vcpu->sregs.ss.selector = CODE_START;
vcpu->sregs.ss.base = CODE_START * 16;
vcpu->sregs.ds.selector = CODE_START;
vcpu->sregs.ds.base = CODE_START * 16;
vcpu->sregs.es.selector = CODE_START;
vcpu->sregs.es.base = CODE_START * 16;
vcpu->sregs.fs.selector = CODE_START;
vcpu->sregs.fs.base = CODE_START * 16;
vcpu->sregs.gs.selector = CODE_START;

// 更新 segment register
if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0)
{
	perror("can not set sregs");
	exit(1);
}

// set CF 而已
vcpu->regs.rflags = 0x0000000000000002ULL;
vcpu->regs.rip = 0;
vcpu->regs.rsp = 0xffffffff;
vcpu->regs.rbp = 0;

// 更新 general register
if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &(vcpu->regs)) < 0)
{
	perror("KVM SET REGS\n");
	exit(1);
}
```

- 由於 vm 執行起來為 real mode，因此 selector 經過 `<< 4` 後加上 offset 就會是 target address，其中 `CODE_START` 為 0x1000 是因為編譯 binary 時將 text segment 的 base address 設置在 0x10000

---

這個 example 使用到與 kvm 相關的結構有：

```c
struct kvm_userspace_memory_region {
        __u32 slot;
        __u32 flags;
        __u64 guest_phys_addr; /* mapping 到的 guest physical */
        __u64 memory_size; /* guest memory 的大小 (bytes) */
        __u64 userspace_addr; /* memory 的起始位址 */
};
```

---

kvm segment register 使用結構 `kvm_segment`：

```c
struct kvm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8  type;
	__u8  present, dpl, db, s, l, g, avl;
	__u8  unusable;
	__u8  padding;
};
```

在 real mode，segment register 的值會作為 selector，在被 `<< 4` 後會即是 segment address；而在 protected mode 中，segment register 是用來存放 LDT / GDT 以及對應的 index，透過存取 index 中存放的 segment descriptor 來找到 segment base address 以及相關資訊。

然而觀察此結構欄位，雖然叫做 `kvm_segment`，但是資料欄位同時包含 segment descriptor 的資料以及 real mode 的 selector，猜測 kvm 將這些資料存放在一起是為了減少 overhead。



### kvm-host

>  實作一個 type 2 hypervisor，程式碼比 **kvm-user-x86** 多了一些，程式碼中會刪除一些 error handling 的部分

`main()` - 流程簡潔且直觀，並 support 兩個參數：

- `bzImage` - kernel binary 的檔案位置
- `initrd` (optional) - ram disk 的檔案位置

```c
vm_t vm;
vm_init(&vm); // 初始化
vm_load_image(&vm, kernel_file); // 載入 binary
if (initrd_file) // 若有提供 ram disk 就載入
   	vm_load_initrd(&vm, initrd_file);
vm_run(&vm); // 執行 vm
vm_exit(&vm); // 釋放 vm 的相關資源
```

- `struct vm_t` 存放 kvm, vm, vcpu 的 fd、serial 的資料以及 ram 的記憶體位址

  ```c
  typedef struct {
      int kvm_fd, vm_fd, vcpu_fd;
      void *mem; // ram
      serial_dev_t serial;
  } vm_t;
  ```

---

`vm_init()` 

```c
v->kvm_fd = open("/dev/kvm", O_RDWR); // 存取 kvm device
v->vm_fd = ioctl(v->kvm_fd, KVM_CREATE_VM, 0); // 建立 VM instance
ioctl(v->vm_fd, KVM_SET_TSS_ADDR, 0xffffd000); // 設置 TSS 位址 (Task State Segment)
__u64 map_addr = 0xffffc000;
// 設置 identity map
ioctl(v->vm_fd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr);
// 建立 IRQ chip
ioctl(v->vm_fd, KVM_CREATE_IRQCHIP, 0);
// 建立 PIT
struct kvm_pit_config pit = {.flags = 0};
ioctl(v->vm_fd, KVM_CREATE_PIT2, &pit);

v->mem = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

struct kvm_userspace_memory_region region = {
    .slot = 0,
    .flags = 0,
    .guest_phys_addr = 0,
    .memory_size = RAM_SIZE,
    .userspace_addr = (__u64) v->mem,
};
// 更新 RAM 位址
ioctl(v->vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
v->vcpu_fd = ioctl(v->vm_fd, KVM_CREATE_VCPU, 0);

vm_init_regs(v); // 初始化 register
vm_init_cpu_id(v); // 初始化 CPUID (instruction)
serial_init(&v->serial); // 初始化 serial
```

- `open()` kvm device 時需要使用 `O_RDWR`
- Identity Paging - virtual addresses are mapped to physical addresses that have the same value，代表 virtual address 在經過 mapping 後會與 physical address 相同
- KVM_CREATE_IRQCHIP - KVM 建立 2 個 8259A 的 PIC
- KVM_CREATE_PIT2 - KVM 建立 i8254 PIT
  - PIT - Programmable Interval Timer (又稱作 timer chip)，作為 event counter, elapsed time indicator, rate-controllable periodic event generator

---

`vm_init_regs()`

```c
struct kvm_sregs sregs;
// 取得 segment register
ioctl(v->vcpu_fd, KVM_GET_SREGS, &sregs);

#define X(R) sregs.R.base = 0, sregs.R.limit = ~0, sregs.R.g = 1
X(cs), X(ds), X(fs), X(gs), X(es), X(ss);
#undef X

// default operation size = 1 ==> 32-bit segment
sregs.cs.db = 1;
sregs.ss.db = 1;
// set 'Protected Mode Enable' bit
sregs.cr0 |= 1;

// 更新 segment register
ioctl(v->vcpu_fd, KVM_SET_SREGS, &sregs);

struct kvm_regs regs;
ioctl(v->vcpu_fd, KVM_GET_REGS, &regs);

regs.rflags = 2; // CF: carry flag
regs.rip = 0x100000, regs.rsi = 0x10000;
// set general register
ioctl(v->vcpu_fd, KVM_SET_REGS, &regs);

return 0;
```

---

`vm_init_cpu_id()`

```c
struct {
    uint32_t nent;
    uint32_t padding;
    struct kvm_cpuid_entry2 entries[N_ENTRIES];
} kvm_cpuid = {.nent = N_ENTRIES};
// 取得 host 的 CPUID 資訊
ioctl(v->kvm_fd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid);

// N_ENTRIES 為 100
// 一共有 100 個
for (unsigned int i = 0; i < N_ENTRIES; i++) {
    struct kvm_cpuid_entry2 *entry = &kvm_cpuid.entries[i];
    if (entry->function == KVM_CPUID_SIGNATURE) {
        // 如果執行對應的 CPUID，就會設定 ebx, ecx, edx 如下
        entry->eax = KVM_CPUID_FEATURES;
        entry->ebx = 0x4b4d564b; /* KVMK */
        entry->ecx = 0x564b4d56; /* VMKV */
        entry->edx = 0x4d;       /* M */
    }
}
// 設置 cpuid2
ioctl(v->vcpu_fd, KVM_SET_CPUID2, &kvm_cpuid);
```

- KVM_GET_SUPPORTED_CPUID - 可以取得 host 支援的 CPUID 列表

- KVM_SET_CPUID2 - 讓 host 可以模擬 guest 在執行 CPUID 的行為

- KVM_CPUID_SIGNATURE - 用來判斷是否存在於 VM 當中

  ```c
  /* This CPUID returns the signature 'KVMKVMKVM' in ebx, ecx, and edx.  It
   * should be used to determine that a VM is running under KVM.
   */
  #define KVM_CPUID_SIGNATURE	0x40000000
  #define KVM_SIGNATURE "KVMKVMKVM\0\0\0"
  ```

---

`serial_init()` - 用來 guest handle 與 serial 相關的操作

```c
*s = (serial_dev_t){
    .priv = (void *) &serial_dev_priv,
};

pthread_mutex_init(&s->lock, NULL);
s->infd = STDIN_FILENO;
// 建立 thread 執行 serial_console()，處理 serial input/ouput
pthread_create(&s->worker_tid, NULL, (void *) serial_console, (void *) s);
```

---

`vm_load_image()`

```c
// 開啟 target kernel binary
int fd = open(image_path, O_RDONLY);
struct stat st;
fstat(fd, &st);
size_t datasz = st.st_size; // 取得檔案大小
// mmap with fd
void *data = mmap(0, datasz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
close(fd);

struct boot_params *boot =
    (struct boot_params *) ((uint8_t *) v->mem + 0x10000);
void *cmdline = ((uint8_t *) v->mem) + 0x20000;
void *kernel = ((uint8_t *) v->mem) + 0x100000;

// ram 的 0x10000 放 boot_params 結構
memset(boot, 0, sizeof(struct boot_params));
memmove(boot, data, sizeof(struct boot_params));

size_t setup_sectors = boot->hdr.setup_sects;
size_t setupsz = (setup_sectors + 1) * 512;
boot->hdr.vid_mode = 0xFFFF;  // VGA
boot->hdr.type_of_loader = 0xFF;
boot->hdr.loadflags |= CAN_USE_HEAP | 0x01 | KEEP_SEGMENTS;
boot->hdr.heap_end_ptr = 0xFE00;
boot->hdr.ext_loader_ver = 0x0;
boot->hdr.cmd_line_ptr = 0x20000;

// cmdline 位於 0x20000，將參數 console=ttyS0 複製到那
memset(cmdline, 0, boot->hdr.cmdline_size);
memcpy(cmdline, KERNEL_OPTS, sizeof(KERNEL_OPTS));

// 將 kernel 本體放到 0x100000
memmove(kernel, (char *) data + setupsz, datasz - setupsz);

// 新增兩個 e820 memory mapping entry
unsigned int idx = 0;
boot->e820_table[idx++] = (struct boot_e820_entry){
    .addr = 0x0,
    .size = ISA_START_ADDRESS - 1,
    .type = E820_RAM,
};
boot->e820_table[idx++] = (struct boot_e820_entry){
    .addr = ISA_END_ADDRESS,
    .size = RAM_SIZE - ISA_END_ADDRESS,
    .type = E820_RAM,
};
boot->e820_entries = idx;

return 0;
```

- BIOS E820 Table 是在 BIOS 時期使用的 memory 管理機制，可以得到 physical address 的相關資訊，而更多資訊可以參考 [MMU-E820](https://biscuitos.github.io/blog/MMU-E820/)
- `CMDLINE` 與 boot_params 都會在 BIOS E820 管理機制中被使用到

---

`vm_load_initrd()` - 載入傳進來的 ram disk 檔

```c
int fd = open(initrd_path, O_RDONLY);
struct stat st;
fstat(fd, &st);
size_t datasz = st.st_size; // 取得檔案大小
// 一樣做 mmap with fd
void *data = mmap(0, datasz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
close(fd);

// boot_params 落於 offset 0x10000
struct boot_params *boot =
    (struct boot_params *) ((uint8_t *) v->mem + 0x10000);
// 從 boot_params 取得 initrd 的 offset
unsigned long addr = boot->hdr.initrd_addr_max & ~0xfffff;

// 從 max 開始扣，找到滿足放入整個 ramdisk 的位址就 brak
for (;;) {
	if (addr < (RAM_SIZE - datasz))
        break;
    addr -= 0x100000;
}

// 取得 initrd 的絕對位址
void *initrd = ((uint8_t *) v->mem) + addr;

// 複製到裡面
memset(initrd, 0, datasz);
memmove(initrd, data, datasz);

// 更新 ram disk 位置以及大小
boot->hdr.ramdisk_image = addr;
boot->hdr.ramdisk_size = datasz;
return 0;
```

---

`vm_run()`

```c
// 取得 vcpu 需要的 mmap 大小
int run_size = ioctl(v->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
struct kvm_run *run =
    mmap(0, run_size, PROT_READ | PROT_WRITE, MAP_SHARED, v->vcpu_fd, 0);

while (1) {
    ioctl(v->vcpu_fd, KVM_RUN, 0); // 通知 kvm 執行

    switch (run->exit_reason) {
	// 如果 exit reason 是與 IO 相關，並且 io 的 port 落於 COM1
    // 則呼叫 serial_handle() 來處理
    case KVM_EXIT_IO:
        if (run->io.port >= COM1_PORT_BASE && run->io.port < COM1_PORT_END)
            serial_handle(&v->serial, run);
        break;
    case KVM_EXIT_SHUTDOWN:
        printf("shutdown\n");
        return 0;
    default:
        printf("reason: %d\n", run->exit_reason);
        return -1;
    }
}
```

- 當 IO port 落於 COM1 的範圍，就可以用 `serial_handle()` 來處理

---

`vm_exit()` - 單純釋放資源

```c
serial_exit(&v->serial); // 設置 thread_stop 來終止 thread，並且釋放 mutex 的資源
close(v->kvm_fd);
close(v->vm_fd);
close(v->vcpu_fd);
munmap(v->mem, RAM_SIZE);
```

---

下列大多都與 serial 的 in / out 相關，以 `serial_handle()` 作為處理的進入點，而同時 `serial_console()` ，而在做 io 時經常使用到的結構 `struct serial_dev_priv` 如下：

```c
struct serial_dev_priv {
    uint8_t dll; // out: Divisor Latch Low
    uint8_t dlm; // out: Divisor Latch High
    uint8_t iir; // in: Interrupt ID Register
    uint8_t ier; // out: Interrupt Enable Register
    uint8_t fcr; // out: FIFO Control Register
    uint8_t lcr; // out: Line Control Register
    uint8_t mcr; // out: Modem Control Register
    uint8_t lsr; // out: Line Status Register
    uint8_t msr; // in: Modem Status Register
    uint8_t scr; // io: Scratch Register

    struct fifo rx_buf; // receive buffer
};
```



`serial_handle()` - 根據 io 方向呼叫對應的 function 來處理

```c
void *data = (uint8_t *) r + r->io.data_offset;
// 如果 io direction 為 out，則執行 serial_out()，反之 serial_in()
void (*serial_op)(serial_dev_t *, uint16_t, void *) =
    (r->io.direction == KVM_EXIT_IO_OUT) ? serial_out : serial_in;

uint32_t c = r->io.count; // 取得 io operaiont 的次數
for (uint16_t off = r->io.port - COM1_PORT_BASE; c--; data += r->io.size)
    // s: serial 資訊 (fixed)
    // off: port 與 COM1 base 的 offset (fixed)
    // data: VCPU 的 base address 加上 io 資料的 offset，每次都會取出一個 slot
    serial_op(s, off, data);
```

---

`serial_out()` - 處理 serial 的 input

```c
struct serial_dev_priv *priv = (struct serial_dev_priv *) s->priv;
// 嘗試取得 lock
pthread_mutex_lock(&s->lock);

switch (offset) { // 根據 COM1 的 offset 會對應到不同的 serial port
case UART_TX: // out: Transmit buffer
	// UART_LCR_DLAB set 代表要更動 dll
    if (priv->lcr & UART_LCR_DLAB) {
        priv->dll = IO_READ8(data);
    } else {
        // 要 flush TX (Transmit buffer)
        // UART_LSR_TEMT: Transmitter empty
        // UART_LSR_THRE: Transmit-hold-register empty
        priv->lsr |= (UART_LSR_TEMT | UART_LSR_THRE);
        putchar(((char *) data)[0]);
        fflush(stdout);
        serial_update_irq(s);
    }
    break;
case UART_IER:
	// UART_LCR_DLAB unset 的情況下代表要更動 iet
    if (!(priv->lcr & UART_LCR_DLAB)) {
        priv->ier = IO_READ8(data);
        serial_update_irq(s);
    } else {
        priv->dlm = IO_READ8(data);
    }
    break;

// 下方是更新串列埠 (serial) 的 out 相關 regiter
case UART_FCR: ... break;
case UART_LCR: ... break;
case UART_MCR: ... break;
case UART_SCR: ... break;
default: break;
}
pthread_mutex_unlock(&s->lock);
```

- UART - Universal Asynchronous Receiver/Transmitter
- 可參考 [串列埠的原理與運用](https://www.csie.ntu.edu.tw/~d4526011/my_book_copy/CHAP4.3.htm) 以及 [serial_reg.h]()
- transmit 代表讀 VM 寫入的 `data` 到 host

---

`serial_in()`

```c
struct serial_dev_priv *priv = (struct serial_dev_priv *) s->priv;
// 嘗試拿 lock
pthread_mutex_lock(&s->lock);

switch (offset) {
case UART_RX: // Receive buffer
    if (priv->lcr & UART_LCR_DLAB) {
        IO_WRITE8(data, priv->dll);
    } else {
        if (fifo_is_empty(&priv->rx_buf)) // 如果 buffer 沒資料就不處理
            break;

        uint8_t value; // 從 receive buffer 讀一個 byte 傳到 VM serial
        if (fifo_get(&priv->rx_buf, value))
            IO_WRITE8(data, value);

        // 如果讀完空的話，unset DR bit (data ready)
        if (fifo_is_empty(&priv->rx_buf)) {
            priv->lsr &= ~UART_LSR_DR;
            serial_update_irq(s);
        }
    }
    break;
case UART_IER:
    if (priv->lcr & UART_LCR_DLAB)
        IO_WRITE8(data, priv->dlm);
    else
        IO_WRITE8(data, priv->ier);
    break;
case UART_IIR:
    // 0xc0 目的為 FIFO enabled
    IO_WRITE8(data, priv->iir | 0xc0);
    break;
case UART_LCR: ... break;
case UART_MCR: ... break;
case UART_LSR: ... break;
case UART_MSR: ... break;
case UART_SCR: ... break;
default:
    break;
}
pthread_mutex_unlock(&s->lock);
```

- transmit 代表讀 VM 從 host 寫到 `data` 當中，receive 代表將 host 的資料寫入 device
- RX 透過 `IO_WRITE8(dst, src)` 把資料寫入 device 使用的記憶體區塊中

---

`serial_console()`

```c
struct serial_dev_priv *priv = (struct serial_dev_priv *) s->priv;

while (!__atomic_load_n(&thread_stop, __ATOMIC_RELAXED)) {
	// 嘗試取得 lock，但如果
    pthread_mutex_lock(&s->lock);
    // buffer 不為空的話代表還有資料正在傳輸
    if (priv->lsr & UART_LSR_DR || !fifo_is_empty(&priv->rx_buf))
        goto unlock;

    // 還沒有滿之前都嘗試從 stdin 讀取資料
    while (!fifo_is_full(&priv->rx_buf) && serial_readable(s)) {
        char c;
        if (read(s->infd, &c, 1) == -1)
            break;
        // 寫資料到 receive buffer
        if (!fifo_put(&priv->rx_buf, c))
            break;
        priv->lsr |= UART_LSR_DR; // data ready
    }
    serial_update_irq(s);
unlock:
    pthread_mutex_unlock(&s->lock);
}
```

- UART_LSR_DR
  - LSR - Line Status Register
  - DR - Receiver data ready

---

`serial_update_irq()` - 更新 serial 的 register 後，有些 bit 與 interrupt 相關，則需要透過 kvm 的 `KVM_IRQ_LINE` command 來更新

```c
struct serial_dev_priv *priv = (struct serial_dev_priv *) s->priv;
uint8_t iir = UART_IIR_NO_INT;

// 如果允許 receiver data interrupt 以及 data ready，代表可以讀取資料了
if ((priv->ier & UART_IER_RDI) && (priv->lsr & UART_LSR_DR))
    iir = UART_IIR_RDI;
// THRI - Transmitter holding register empty
// TEMT - Transmitter empty
else if ((priv->ier & UART_IER_THRI) && (priv->lsr & UART_LSR_TEMT))
    iir = UART_IIR_THRI;

priv->iir = iir | 0xc0; // 0xc0 for FIFO

// 像 kvm 發送更新狀態
vm_irq_line(container_of(s, vm_t, serial), SERIAL_IRQ,
            iir == UART_IIR_NO_INT ? 0 /* inactive */ : 1 /* active */);
```

- 當 transmitter FIFO 為空時會 trigger **transmitter holding register empty interrupt** (THRI)
