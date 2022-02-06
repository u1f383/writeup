## Virtio

> virtio 為 device 與 paravirtualized hypervisor 之間的 abstraction layer



虛擬化分成全虛擬化以及半虛擬化：

- 全 (Full Virtualization): guest OS 直接跑在 hypervisor 上
  - 虛擬 OS 運行的所有環境
  - 使用 Hosted hypervisor
  - E.g. Virtual PC、VM-Ware，Virtual Box、KVM
- 半: guest OS 與 hypervisor 溝通來做事
  - Focuse 在實現硬體層級的虛擬化層，修改 kernel 使得原本不能被虛擬化的指令，透過 interface 像硬體提出請求
  - 知道自己在 virtual mode 執行
  - 使用 Bare-Metal hypervisor
  - E.g. Xen、Microsoft Hyper-V (Parent Partition)、Citrix XenServer
- 關於 emulator / hypervisor / vm 的關係可以參考 [stack overflow 上的文章](https://stackoverflow.com/a/6234760)
  - VM 強調 CPU self-virtualization，提供與 real hardware 溝通的 virtualized interface
  - Emulators 模擬 hardware，並且不依靠 CPU 跑 code
  - hypervisor 精確來說是 mediates protected access
- more info
  - [Virtualization-method](https://github.com/seekyiyi/Virtualization-method)
  - [Anatomy of a Linux hypervisor](https://developer.ibm.com/tutorials/l-hypervisor/)



在全虛擬化的環境中，hypervisor 遇到 trap 會開始模擬硬體請求，雖有彈性但是比較慢。而半虛擬化則會透過 **virtio** 作為 Guest OS 與 hypervisor 的 interface，其中 Guest OS 為前端、hypervisor 為後端，而後一樣模擬請求並做回覆，實際例子為 **QEMU**。

- QEMU 為 full-system 的 **emulator**，能夠模擬許多 device，像是 PCI host controller, disk, network, video hardware, USB controller 等
- KVM 為 **hypervisor**，可以把 kernel 直接作為 hypervisor，能夠虛擬化 memory 以及 CPU
  - 不過 KVM 是以 kernel module 的方式存在於 linux kernel 當中
- 在 qemu-kvm 中，KVM 負責 kernel mode， qemu 負責 usermode



virtio customed layer

- **Virtual Queue** 能夠將前後端的驅動串在一起，如 network 驅動使用兩個 VQ，一個接收一個發送
- `virtio_driver` 為 Guest OS 的前端驅動
  - 會用 `register_virtio_driver()` 來註冊驅動
  - 發現新 device 時會用 `probe()` 來匹配
- `virtio_device` 為對應的 device
  - `virtio_config_ops` 定義各個 device 的 operation
- `virtqueue`  的 `vdev` 指向 `virtio_device` ，且有個 `virtqueue_ops` member 用來定義與 hypervisor 做溝通時的排序操作
  - 用 `virtio_config_ops.find_vq()` 來找與自己有關的 device
  - `virtqueue_ops` 定義 GuestOS 與 hypervisor 在傳遞資料的規則



### 名詞

- MMIO - memory mapped I/O
  - 直接使用普通的 instruction 就可以存取 device I/O
  - memory 與 device 共享
  - kernel mode
    - map: `ioremap()`
    - 讀: `readb()`, `readw()`, ...
    - 寫: `writeb()`, `writew()`, ...
  - user mode
    - open file: `open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC)`
    - map: `mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0)`
- PMIO - port mapped I/O
  - 需要透過 `IN` 或 `OUT` 來存取 I/O interface，因為有各自的 memory region
  - 使用如 `outb`, `outw`, `outl` 的 instruction 來做操作
  - user mode 在使用 `out` 與 `in` 的 operation 前，需要執行 `iopl(3)` 來更新 IO privilege
    - 較新的 function 使用 `ioperm()`
- `lspci` - 印出 PCI 的相關資訊
  - format: **Bus:Device:功能**
  - PCI 最多能有 256 個 bus、每個 bus 最多能有 32 個 devices、每個 device 最多能有 8 個功能



開發人員能透過 QOM (QEMU Object Module) 來制定 device 的硬體資源與操作:

- 常見的結構: `TypeInfo`, `TypeImpl`, `ObjectClass`, `Object`
- `TypeInfo` 定義 Type 的結構，再透過 `type_register(TypeInfo)` or `type_register_static(TypeInfo)` 來註冊，即可產生對應的 `TypeImpl`
- 當執行完 `type_register_static()` 後，qemu 會在 `type_initialize()` 建構對應的 `ObjectClasses`，也就是說每個 `Type` 都會對到一個 `ObjectClass`
- parent 初始化完後用 `TypeInfo::class_init()` 來產生 `ObjectClass` 的 instance
- `TypeInfo` 內有幾個 function pointer 負責做初始化:
  - `instance_init`: 初始化並建立 `Object` instance
  - `class_init`: 初始化並建立 `ObjectClass` instance



學習資源:

- [Virtio：一种Linux I/O虚拟化框架](https://www.anquanke.com/post/id/224001)
- [VM escape - QEMU Case Study](http://phrack.org/issues/70/5.html)
- [CVE-2015-5165 & CVE-2015-7504](https://github.com/mtalbi/vm_escape)
- [understanding_qemu](https://richardweiyang-2.gitbook.io/understanding_qemu/)
- [qemu 模擬 int](https://www.binss.me/blog/qemu-note-of-interrupt/)
- [QOM 官方文章](https://qemu-project.gitlab.io/qemu/devel/qom.html)



